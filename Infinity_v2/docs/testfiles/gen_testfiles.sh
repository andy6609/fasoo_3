#!/bin/bash
# Infinity_v2 DLP 테스트 파일 A/B/C 생성기
# (원래 proxy_ToInfinity용으로 작성됐다가 Infinity_v2/docs/testfiles/로 이전됨.
#  이 코퍼스는 버전에 종속되지 않고 v1/v2 양쪽 실험에서 재사용된다.
#  D/E(진짜 docx, PNG-as-xlsx 위조)는 이 스크립트로 안 만든다 — 아래 안내 참고.)
set -e
OUT="$(dirname "$0")"
mkdir -p "$OUT"

# ---------- 공통: 최소 유효 PDF 빌더 ----------
# $1=출력경로  $2=본문 스트림 텍스트가 담긴 파일
build_pdf() {
  local out="$1" streamfile="$2" tmp
  tmp=$(mktemp)
  local slen
  slen=$(wc -c < "$streamfile")

  {
    printf '%%PDF-1.4\n'
    printf '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
    printf '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
    printf '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n'
    printf '4 0 obj\n<< /Length %s >>\nstream\n' "$slen"
    cat "$streamfile"
    printf 'endstream\nendobj\n'
    printf '5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n'
  } > "$tmp"

  # 각 객체의 바이트 오프셋을 실제로 측정해서 xref 를 정확히 만든다
  local o1 o2 o3 o4 o5 xrefpos
  o1=$(grep -abo '^1 0 obj' "$tmp" | head -1 | cut -d: -f1)
  o2=$(grep -abo '^2 0 obj' "$tmp" | head -1 | cut -d: -f1)
  o3=$(grep -abo '^3 0 obj' "$tmp" | head -1 | cut -d: -f1)
  o4=$(grep -abo '^4 0 obj' "$tmp" | head -1 | cut -d: -f1)
  o5=$(grep -abo '^5 0 obj' "$tmp" | head -1 | cut -d: -f1)
  xrefpos=$(wc -c < "$tmp")

  cp "$tmp" "$out"
  {
    printf 'xref\n0 6\n'
    printf '0000000000 65535 f \n'
    printf '%010d 00000 n \n' "$o1" "$o2" "$o3" "$o4" "$o5"
    printf 'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%s\n%%%%EOF\n' "$xrefpos"
  } >> "$out"
  rm -f "$tmp"
}

# ---------- A: 진짜 PDF (정상 풀패스 검증용) ----------
SA=$(mktemp)
{
  printf 'BT /F1 14 Tf 72 740 Td (PROXY-INFINITY DLP TEST FILE A) Tj ET\n'
  printf 'BT /F1 10 Tf 72 715 Td (SENTINEL-A-CONFIDENTIAL-7F3A9C2E4B1D) Tj ET\n'
  printf 'BT /F1 10 Tf 72 695 Td (Purpose: happy-path extraction / magic-number match / hash) Tj ET\n'
  printf 'BT /F1 10 Tf 72 675 Td (This is synthetic test content. No real data.) Tj ET\n'
  for i in $(seq 1 20); do
    printf 'BT /F1 9 Tf 72 %d Td (LINE-%03d PAYLOAD-MARKER-A OK) Tj ET\n' $((650 - i * 14)) "$i"
  done
  printf 'BT /F1 10 Tf 72 340 Td (SENTINEL-A-END-7F3A9C2E4B1D) Tj ET\n'
} > "$SA"
build_pdf "$OUT/A_기밀_설계문서.pdf" "$SA"
rm -f "$SA"

# ---------- B: 확장자 위조 (내용=PNG, 이름=.pdf) ----------
B="$OUT/B_2026_급여명세서.pdf"
# 표준 1x1 RGBA PNG (시그니처 + IHDR + IDAT + IEND)
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a' > "$B"
printf '\x00\x00\x00\x0d\x49\x48\x44\x52' >> "$B"
printf '\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00' >> "$B"
printf '\x1f\x15\xc4\x89' >> "$B"
printf '\x00\x00\x00\x0a\x49\x44\x41\x54' >> "$B"
printf '\x78\x9c\x63\x00\x01\x00\x00\x05\x00\x01' >> "$B"
printf '\x0d\x0a\x2d\xb4' >> "$B"
printf '\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82' >> "$B"
# IEND 뒤 트레일링 데이터(PNG 디코더는 무시) — 실제 파일다운 크기 + grep 가능한 센티넬
{
  printf 'SENTINEL-B-FORGED-EXTENSION-C41E8A0D\n'
  printf 'This file is a PNG image deliberately named with a .pdf extension.\n'
  printf 'Expected proxy behavior: MIME=application/pdf but magic bytes are PNG -> mismatch warning.\n'
  for i in $(seq 1 400); do
    printf 'PADDING-B-%04d-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' "$i"
  done
  printf 'SENTINEL-B-END-C41E8A0D\n'
} >> "$B"

# ---------- C: 대용량 PDF (h2 DATA 프레임 다중 분할 재조립 검증) ----------
SC=$(mktemp)
{
  printf 'BT /F1 14 Tf 72 740 Td (PROXY-INFINITY DLP TEST FILE C - LARGE) Tj ET\n'
  printf 'BT /F1 10 Tf 72 715 Td (SENTINEL-C-HEAD-5D2B7E93F016) Tj ET\n'
  for i in $(seq 1 6000); do
    printf '%% REC-%05d CUSTOMER-ID=SYNTH-%05d FIELD=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' "$i" "$i"
  done
  printf 'BT /F1 10 Tf 72 690 Td (SENTINEL-C-TAIL-5D2B7E93F016) Tj ET\n'
} > "$SC"
build_pdf "$OUT/C_대용량_고객리스트.pdf" "$SC"
rm -f "$SC"

echo "=== A/B/C 생성 완료 ==="
cd "$OUT"
for f in A_*.pdf B_*.pdf C_*.pdf; do
  printf '%-28s %8s bytes  magic=' "$f" "$(wc -c < "$f")"
  head -c 8 "$f" | od -An -tx1 | tr -d '\n'
  echo
done

cat <<'EOF'

=== D/E는 이 스크립트로 안 만든다 ===
D(진짜 .docx)는 유효한 OOXML(ZIP 컨테이너: [Content_Types].xml, _rels/.rels,
word/document.xml)이 필요해 순수 bash로는 안정적으로 못 만든다. PowerShell의
System.IO.Compression.ZipFile로 만들었다 — 절차는
../v1-to-v2-detection-gap-closure.md 및 ../../../proxy_ToInfinity/docs/noDRM/
test-file-design-rationale.md §10.3 참고. E는 B와 동일한 PNG 바이트를 재사용하고
확장자만 .xlsx로 바꾼 것이라 위 B 생성 로직을 그대로 복사해 확장자만 바꾸면 재현된다.
EOF
