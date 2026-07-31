#!/usr/bin/env python3
"""Verify phase 1/2 fixtures, magic bytes, document text, and offline OCR."""

from __future__ import annotations

import argparse
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile
from xml.etree import ElementTree

from PIL import Image
from pypdf import PdfReader


DRM_PREFIX = b"\x9b DRMONE"


def normalized(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z가-힣]", "", value).casefold()


def xml_text(data: bytes) -> str:
    try:
        root = ElementTree.fromstring(data)
        return " ".join(text for text in root.itertext() if text and text.strip())
    except ElementTree.ParseError:
        return data.decode("utf-8", errors="ignore")


def zip_text(path: Path, prefixes: tuple[str, ...] = ()) -> str:
    collected: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            lower = name.lower()
            if prefixes and not any(lower.startswith(prefix) for prefix in prefixes):
                continue
            if lower.endswith((".xml", ".rels", ".txt", ".csv", ".json")):
                collected.append(xml_text(archive.read(name)))
    return "\n".join(collected)


def decode_text_fixture(data: bytes) -> str:
    """Decode the deterministic UTF/CP949 text fixtures without replacement."""

    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return data.decode("utf-32")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if len(data) >= 4:
        even_nuls = data[0::2].count(0)
        odd_nuls = data[1::2].count(0)
        pairs = len(data) // 2
        if odd_nuls > pairs // 4 and even_nuls < odd_nuls // 2:
            return data.decode("utf-16le")
        if even_nuls > pairs // 4 and odd_nuls < even_nuls // 2:
            return data.decode("utf-16be")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp949")


def extract_structured(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".csv", ".json", ".xml", ".py"}:
        return decode_text_fixture(path.read_bytes())
    if suffix == ".docx":
        return zip_text(path, ("word/",))
    if suffix == ".xlsx":
        return zip_text(path, ("xl/",))
    if suffix == ".pptx":
        return zip_text(path, ("ppt/slides/", "ppt/notes"))
    if suffix == ".hwpx":
        return zip_text(path, ("contents/",))
    if suffix == ".zip":
        parts: list[str] = []
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                data = archive.read(name)
                if name.lower().endswith((".txt", ".csv", ".json", ".xml")):
                    parts.append(xml_text(data))
                elif name.lower().endswith((".docx", ".xlsx", ".pptx", ".hwpx")):
                    with tempfile.TemporaryDirectory(prefix="local_dlp_zip_") as temporary:
                        nested = Path(temporary) / ("nested" + Path(name).suffix)
                        nested.write_bytes(data)
                        parts.append(extract_structured(nested))
        return "\n".join(parts)
    if suffix == ".pdf":
        return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
    raise ValueError(f"no structural extractor for {suffix}")


def magic_ok(path: Path, mime: str) -> tuple[bool, str]:
    data = path.read_bytes()[:16]
    if data.startswith(DRM_PREFIX):
        return False, "Fasoo DRMONE header detected; generate the pack in the DRM-exempt C:\\Exception path"
    expected = {
        "application/pdf": (b"%PDF-",),
        "image/png": (b"\x89PNG\r\n\x1a\n",),
        "image/jpeg": (b"\xff\xd8\xff",),
        "image/gif": (b"GIF87a", b"GIF89a"),
        "image/bmp": (b"BM",),
        "image/tiff": (b"II*\x00", b"MM\x00*"),
        "application/zip": (b"PK\x03\x04",),
        "application/hwp+zip": (b"PK\x03\x04",),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": (b"PK\x03\x04",),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": (b"PK\x03\x04",),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": (b"PK\x03\x04",),
    }.get(mime)
    if not expected:
        return True, "no universal magic byte is defined for this text type"
    return any(data.startswith(prefix) for prefix in expected), data.hex(" ")


def add(results: list[dict], name: str, status: str, detail: str) -> None:
    results.append({"name": name, "status": status, "detail": detail})
    print(f"[{status:<4}] {name}: {detail}")


def verify_native_only_fixture(path: Path, item: dict, expected: dict[str, str]) -> tuple[bool, str]:
    """Verify structure of fixtures whose policy result is checked by the C binary."""

    if not path.is_file():
        return False, "fixture missing"
    name = path.name
    if name == "minimal_hwp5_confidential.hwp":
        data = path.read_bytes()
        ok = (
            data.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))
            and b"HWP Document File" in data
            and expected["marker"].encode("utf-16le") in data
        )
        return ok, "CFB, HWP FileHeader, and UTF-16LE paragraph marker present"
    if name.startswith("synthetic_legacy_confidential."):
        data = path.read_bytes()
        stream_name = {
            ".doc": "WordDocument",
            ".xls": "Workbook",
            ".ppt": "PowerPoint Document",
        }[path.suffix.casefold()]
        ok = (
            data.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))
            and stream_name.encode("utf-16le") in data
            and expected["marker"].encode("utf-16le") in data
        )
        return ok, f"CFB, {stream_name} directory entry, and UTF-16LE marker present"
    if name == "encrypted_confidential.zip":
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) != 1 or not (archive.infolist()[0].flag_bits & 1):
                return False, "ZIP entry is not marked encrypted"
            entry = archive.infolist()[0]
            try:
                archive.read(entry)
                return False, "encrypted entry unexpectedly opened without a password"
            except RuntimeError:
                pass
            recovered = archive.read(entry, pwd=item["password"].encode("utf-8"))
        ok = expected["marker"].encode("utf-8") in recovered
        return ok, "encrypted flag, no-password rejection, and password round-trip verified"
    if name == "encrypted_confidential.pdf":
        reader = PdfReader(str(path))
        if not reader.is_encrypted:
            return False, "PDF is not encrypted"
        if reader.decrypt(item["password"]) == 0:
            return False, "PDF password round-trip failed"
        recovered = "\n".join(page.extract_text() or "" for page in reader.pages)
        ok = normalized(expected["marker"]) in normalized(recovered)
        return ok, "encrypted flag, password round-trip, and plaintext marker verified"
    if item.get("marker_frame"):
        with Image.open(path) as image:
            frame_count = getattr(image, "n_frames", 1)
            if frame_count < int(item["marker_frame"]):
                return False, f"expected at least {item['marker_frame']} frames/pages; got {frame_count}"
            image.seek(0)
            first = image.convert("RGB").tobytes()
            image.seek(int(item["marker_frame"]) - 1)
            marker_frame = image.convert("RGB").tobytes()
        if first == marker_frame:
            return False, "frame/page 1 and marker frame are identical"
        return True, f"{frame_count} frames/pages present and marker frame differs from frame 1"
    if name == "embedded_opaque_payload.docx":
        with zipfile.ZipFile(path) as archive:
            names = {entry.casefold() for entry in archive.namelist()}
            content_types = archive.read("[Content_Types].xml")
            relationships = archive.read("word/_rels/document.xml.rels")
            ok = (
                "word/embeddings/opaque.bin" in names
                and b"application/octet-stream" in content_types
                and b"rIdDlpOpaque" in relationships
            )
        return ok, "related word/embeddings/opaque.bin package part and content type present"
    ok, detail = magic_ok(path, item["mime"])
    return ok, detail


def run_ocr(worker: Path, fixture: Path, expected: dict[str, str], result_dir: Path) -> tuple[str, str]:
    output = result_dir / f"{fixture.name}.txt"
    report = result_dir / f"{fixture.name}.json"
    command = [
        sys.executable, str(worker), "extract", "--input", str(fixture),
        "--output", str(output), "--report", str(report), "--language", "kor+eng",
    ]
    process = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=360)
    if process.returncode == 2:
        return "SKIP", "offline OCR engine unavailable (see report)"
    if process.returncode != 0:
        return "FAIL", (process.stderr or process.stdout).strip()[-500:]
    text = output.read_text(encoding="utf-8-sig", errors="replace")
    missing = [key for key in ("english", "marker") if normalized(expected[key]) not in normalized(text)]
    expected_korean = "".join(re.findall(r"[가-힣]", expected["korean"]))
    actual_korean = "".join(re.findall(r"[가-힣]", text))
    korean_similarity = SequenceMatcher(None, expected_korean, actual_korean).ratio()
    if korean_similarity < 0.85:
        missing.append("korean")
    if missing:
        return "FAIL", f"OCR output missing normalized fields: {', '.join(missing)}; korean_similarity={korean_similarity:.3f}; output={text!r}"
    return "PASS", f"Korean similarity={korean_similarity:.3f}; English and marker recovered exactly after normalization"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", type=Path, default=Path(r"C:\Exception\AI_DLP_Phase1_Phase2_Test_Pack"))
    parser.add_argument("--strict-ocr", action="store_true", help="Treat OCR engine SKIP as failure")
    args = parser.parse_args()
    pack = args.pack.resolve()
    fixtures = pack / "fixtures"
    manifest_path = pack / "manifest.json"
    if not manifest_path.is_file():
        print(f"[FAIL] manifest missing: {manifest_path}")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = manifest["expected"]
    worker = Path(__file__).resolve().parents[2] / "tools" / "offline_ocr.py"
    result_dir = pack / "verification_results"
    result_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    for item in manifest["fixtures"]:
        path = fixtures / item["file"]
        if not path.is_file():
            add(results, item["file"], "FAIL", "fixture missing")
            continue
        ok, detail = magic_ok(path, item["mime"])
        add(results, f"magic/{item['file']}", "PASS" if ok else "FAIL", detail)
        if not ok:
            continue
        if item["analysis"] == "ocr":
            status, detail = run_ocr(worker, path, expected, result_dir)
            if status == "SKIP" and args.strict_ocr:
                status = "FAIL"
            add(results, f"ocr/{item['file']}", status, detail)
        else:
            try:
                extracted = extract_structured(path)
                missing = [token for token in item["must_contain"] if normalized(token) not in normalized(extracted)]
                add(
                    results,
                    f"extract/{item['file']}",
                    "FAIL" if missing else "PASS",
                    f"missing: {missing}" if missing else "expected marker recovered",
                )
            except Exception as exc:
                add(results, f"extract/{item['file']}", "FAIL", str(exc))

    for item in manifest.get("native_only_fixtures", []):
        path = fixtures / item["file"]
        try:
            ok, detail = verify_native_only_fixture(path, item, expected)
            add(results, f"native-fixture/{item['file']}", "PASS" if ok else "FAIL", detail)
        except Exception as exc:
            add(results, f"native-fixture/{item['file']}", "FAIL", str(exc))

    for item in manifest.get("not_generated", []):
        add(results, "optional/" + ",".join(item["formats"]), "SKIP", item["reason"])

    hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(fixtures.iterdir()) if path.is_file()
    }
    summary = {
        "pack": str(pack),
        "results": results,
        "counts": {status: sum(1 for item in results if item["status"] == status) for status in ("PASS", "FAIL", "SKIP")},
        "sha256": hashes,
    }
    (result_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary["counts"], ensure_ascii=False))
    return 1 if summary["counts"]["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
