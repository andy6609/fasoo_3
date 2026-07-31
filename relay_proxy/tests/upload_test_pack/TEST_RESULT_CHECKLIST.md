# AI 업로드 테스트 결과 기록표

테스트 일시: ____________________
테스터: ____________________
프록시 PID: ____________________
브라우저 버전: ____________________

| 서비스 | 테스트 파일 | 기대 결과 | 실제 UI 결과 | AI ACCESS | UPLOAD PREPARED | UPLOAD INSPECTED | FORWARDED/BLOCKED | 판정 |
|---|---|---|---|---|---|---|---|---|
| ChatGPT | 01_GPT_SAFE.txt | ALLOW |  |  |  |  |  |  |
| ChatGPT | 04_COMMON_SAFE.docx | ALLOW |  |  |  |  |  |  |
| ChatGPT | 91_BLOCK_nested_script.zip | BLOCK |  |  |  |  |  |  |
| Gemini | 02_GEMINI_SAFE.txt | ALLOW |  |  |  |  |  |  |
| Gemini | 05_COMMON_SAFE.pdf | ALLOW |  |  |  |  |  |  |
| Gemini | 91_BLOCK_nested_script.zip | BLOCK |  |  |  |  |  |  |
| Claude | 03_CLAUDE_SAFE.txt | ALLOW |  |  |  |  |  |  |
| Claude | 04_COMMON_SAFE.docx | ALLOW |  |  |  |  |  |  |
| Claude | 91_BLOCK_nested_script.zip | BLOCK |  |  |  |  |  |  |

## 장애 기록

- 인증서 오류: 없음 / 있음
- 사이트 접속 실패: 없음 / 있음
- Outlook 영향: 없음 / 있음
- `relay_runtime.log` 신규 WARN/ERROR: 없음 / 있음
- Gemini/Claude가 AI ACCESS만 기록됨: 없음 / 있음

메모:

____________________________________________________________________

____________________________________________________________________
