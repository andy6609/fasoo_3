#!/usr/bin/env python3
"""Offline OCR worker for Local DLP upload records.

The worker never calls a cloud API. It prefers a complete local Tesseract
installation and falls back to Windows.Media.Ocr on Windows. PDF pages are
rendered locally with pdftoppm before OCR.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any


EXIT_OK = 0
EXIT_NO_ENGINE = 2
EXIT_UNSUPPORTED = 3
EXIT_OCR_FAILED = 4


def _run(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _find_executable(env_name: str, executable: str, extra: list[Path] | None = None) -> str | None:
    configured = os.environ.get(env_name)
    if configured and Path(configured).is_file():
        return str(Path(configured).resolve())
    found = shutil.which(executable)
    if found:
        return found
    for candidate in extra or []:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _powershell() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("powershell")


def _windows_probe() -> dict[str, Any]:
    bridge = Path(__file__).with_name("windows_ocr.ps1")
    shell = _powershell()
    if os.name != "nt" or not shell or not bridge.is_file():
        return {"available": False, "engine": "windows-media-ocr", "languages": [], "reason": "Windows OCR bridge unavailable"}
    result = _run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(bridge), "-Probe"], 30)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or not lines:
        return {
            "available": False,
            "engine": "windows-media-ocr",
            "languages": [],
            "reason": (result.stderr or result.stdout or "probe failed").strip(),
        }
    try:
        payload = json.loads(lines[-1])
        if isinstance(payload.get("languages"), str):
            payload["languages"] = [payload["languages"]]
        return payload
    except json.JSONDecodeError:
        return {"available": False, "engine": "windows-media-ocr", "languages": [], "reason": "invalid probe response"}


def _tesseract_probe() -> dict[str, Any]:
    candidates = [
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Tesseract-OCR" / "tesseract.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tesseract-OCR" / "tesseract.exe",
    ]
    executable = _find_executable("LOCAL_DLP_TESSERACT", "tesseract", candidates)
    if not executable:
        return {"available": False, "engine": "tesseract", "languages": [], "reason": "tesseract executable not found"}
    result = _run([executable, "--list-langs"], 30)
    if result.returncode != 0:
        return {"available": False, "engine": "tesseract", "languages": [], "reason": (result.stderr or result.stdout).strip()}
    languages = [line.strip() for line in result.stdout.splitlines()[1:] if line.strip()]
    return {"available": True, "engine": "tesseract", "path": executable, "languages": languages, "offline": True}


def probe() -> dict[str, Any]:
    configured = os.environ.get("LOCAL_DLP_PDFTOPPM")
    pdftoppm_candidates = [
        Path(configured) if configured else None,
        Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "native" / "poppler" / "Library" / "bin" / "pdftoppm.exe",
        Path(shutil.which("pdftoppm")) if shutil.which("pdftoppm") else None,
    ]
    pdftoppm = None
    renderer_reason = "pdftoppm executable not found"
    for candidate in pdftoppm_candidates:
        if not candidate or not candidate.is_file():
            continue
        check = _run([str(candidate), "-v"], 15)
        if check.returncode == 0:
            pdftoppm = str(candidate.resolve())
            renderer_reason = ""
            break
        renderer_reason = (check.stderr or check.stdout or "pdftoppm failed self-test").strip()
    return {
        "offline_only": True,
        "engines": [_tesseract_probe(), _windows_probe()],
        "pdf_renderer": {"available": bool(pdftoppm), "path": pdftoppm, "reason": renderer_reason},
    }


def _choose_engine(report: dict[str, Any], language: str, requested: str) -> dict[str, Any] | None:
    engines = [item for item in report["engines"] if item.get("available")]
    if requested != "auto":
        return next((item for item in engines if item["engine"] == requested), None)

    wanted_korean = any(token in language.lower() for token in ("kor", "ko"))
    tesseract = next((item for item in engines if item["engine"] == "tesseract"), None)
    windows = next((item for item in engines if item["engine"] == "windows-media-ocr"), None)
    if wanted_korean:
        if tesseract and "kor" in tesseract.get("languages", []):
            return tesseract
        if windows and any(str(lang).lower().startswith("ko") for lang in windows.get("languages", [])):
            return windows
    return tesseract or windows


def _magic_kind(path: Path) -> str:
    data = path.read_bytes()[:16]
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image"
    if data.startswith(b"\xff\xd8\xff"):
        return "image"
    if data.startswith((b"GIF87a", b"GIF89a", b"BM", b"II*\x00", b"MM\x00*")):
        return "image"
    return "unsupported"


def _render_pdf(path: Path, renderer: str, target: Path) -> list[Path]:
    prefix = target / "page"
    result = _run([renderer, "-png", "-r", "220", str(path), str(prefix)], 300)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "pdftoppm failed").strip())
    pages = sorted(target.glob("page-*.png"))
    if not pages:
        raise RuntimeError("pdftoppm produced no page images")
    return pages


def _ocr_tesseract(image: Path, engine: dict[str, Any], language: str) -> tuple[str, str]:
    available = set(engine.get("languages", []))
    requested = [part for part in language.split("+") if part]
    usable = [part for part in requested if part in available]
    if not usable:
        if "eng" in available:
            usable = ["eng"]
        elif available:
            usable = [sorted(available)[0]]
        else:
            raise RuntimeError("Tesseract has no installed language data")
    selected = "+".join(usable)
    result = _run([engine["path"], str(image), "stdout", "-l", selected, "--psm", "6"], 180)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "tesseract failed").strip())
    return result.stdout.strip(), selected


def _ocr_windows(image: Path, language: str) -> tuple[str, str]:
    bridge = Path(__file__).with_name("windows_ocr.ps1")
    shell = _powershell()
    requested = "ko" if any(token in language.lower() for token in ("kor", "ko")) else "en"
    result = _run([
        str(shell), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(bridge),
        "-InputPath", str(image.resolve()), "-Language", requested,
    ], 180)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or not lines:
        raise RuntimeError((result.stderr or result.stdout or "Windows OCR failed").strip())
    payload = json.loads(lines[-1])
    if not payload.get("ok"):
        raise RuntimeError(payload.get("error", "Windows OCR failed"))
    return str(payload.get("text", "")).strip(), str(payload.get("language", requested))


def extract(input_path: Path, output_path: Path, report_path: Path | None, language: str, requested_engine: str) -> int:
    environment = probe()
    engine = _choose_engine(environment, language, requested_engine)
    result_report: dict[str, Any] = {
        "ok": False,
        "input": str(input_path.resolve()),
        "output": str(output_path.resolve()),
        "offline": True,
        "requested_language": language,
        "environment": environment,
    }
    if not engine:
        result_report["status"] = "NO_OCR_ENGINE"
        result_report["error"] = "No compatible offline OCR engine is installed"
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(result_report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(result_report, ensure_ascii=False, indent=2))
        return EXIT_NO_ENGINE

    kind = _magic_kind(input_path)
    if kind == "unsupported":
        result_report["status"] = "UNSUPPORTED_INPUT"
        result_report["error"] = "Only PNG/JPEG/GIF/BMP/TIFF and PDF inputs are supported by the OCR worker"
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(result_report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(result_report, ensure_ascii=False, indent=2))
        return EXIT_UNSUPPORTED

    try:
        with tempfile.TemporaryDirectory(prefix="local_dlp_ocr_") as temporary:
            images = [input_path]
            if kind == "pdf":
                renderer = environment["pdf_renderer"].get("path")
                if not renderer:
                    raise RuntimeError("PDF OCR requires local pdftoppm; set LOCAL_DLP_PDFTOPPM")
                images = _render_pdf(input_path, renderer, Path(temporary))

            page_texts: list[str] = []
            selected_language = language
            for index, image in enumerate(images, start=1):
                if engine["engine"] == "tesseract":
                    text, selected_language = _ocr_tesseract(image, engine, language)
                else:
                    text, selected_language = _ocr_windows(image, language)
                if len(images) > 1:
                    page_texts.append(f"[PAGE {index}]\n{text}")
                else:
                    page_texts.append(text)

            full_text = "\n\n".join(page_texts).strip()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(full_text, encoding="utf-8-sig")
            result_report.update({
                "ok": True,
                "status": "OCR_COMPLETE",
                "engine": engine["engine"],
                "selected_language": selected_language,
                "pages": len(images),
                "characters": len(full_text),
            })
    except Exception as exc:
        result_report["status"] = "OCR_FAILED"
        result_report["error"] = str(exc)
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(result_report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(result_report, ensure_ascii=False, indent=2))
        return EXIT_OCR_FAILED

    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(result_report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result_report, ensure_ascii=False, indent=2))
    return EXIT_OK


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Korean/English OCR worker for Local DLP")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("probe", help="Print deterministic local dependency status")

    extract_parser = subparsers.add_parser("extract", help="Extract OCR text from an image or PDF")
    extract_parser.add_argument("--input", required=True, type=Path)
    extract_parser.add_argument("--output", required=True, type=Path)
    extract_parser.add_argument("--report", type=Path)
    extract_parser.add_argument("--language", default="kor+eng")
    extract_parser.add_argument("--engine", choices=("auto", "tesseract", "windows-media-ocr"), default="auto")

    args = parser.parse_args()
    if args.command == "probe":
        print(json.dumps(probe(), ensure_ascii=False, indent=2))
        return EXIT_OK
    if not args.input.is_file():
        parser.error(f"input file not found: {args.input}")
    return extract(args.input, args.output, args.report, args.language, args.engine)


if __name__ == "__main__":
    raise SystemExit(main())
