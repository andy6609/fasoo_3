# AI 파일 업로드 DLP 테스트 팩

이 폴더는 ChatGPT, Gemini, Claude 파일 업로드 식별 및 차단 테스트 전용입니다.
실제 회사 문서, 개인정보, 계정정보는 테스트에 사용하지 마세요.

## 폴더 구성

- `01_GPT_SAFE.txt`: ChatGPT 허용 테스트
- `02_GEMINI_SAFE.txt`: Gemini 허용 테스트
- `03_CLAUDE_SAFE.txt`: Claude 허용 테스트
- `04_COMMON_SAFE.docx`: 공통 DOCX 허용 테스트
- `05_COMMON_SAFE.pdf`: 공통 PDF 허용 테스트
- `90_BLOCK_script.bat`: 위험 확장자 차단 테스트. 실행하지 말고 업로드에만 사용
- `91_BLOCK_nested_script.zip`: ZIP 내부 위험 스크립트 차단 테스트
- `92_BLOCK_fake_pdf.pdf`: 확장자와 실제 형식 불일치 차단 테스트
- `TEST_RESULT_CHECKLIST.md`: 서비스별 결과 기록표
- `START_HERE.bat`: 프록시 실행, PAC 적용, 환경 점검, 로컬 분석, 로그 창 실행을 한 번에 수행
- `STOP_TEST.bat`: 테스트 전 Windows 프록시 설정 복원
- `tools`: 환경 점검, 로컬 분석, 로그 모니터링 도구. 이 폴더의 파일은 업로드하지 않음

처음 테스트할 때는 `START_HERE.bat`을 실행한 뒤 이 문서의 6번부터 진행해도 됩니다.

## 1. 프록시 실행 확인

최종 테스트 팩 위치는 `C:\Exception\AI_Upload_Test_Pack`입니다. 프로젝트 루트에서 PowerShell을 열고 실행합니다.

```powershell
cd C:\path\to\tcp_proxy_lab
Get-NetTCPConnection -LocalPort 8000 -State Listen
```

결과가 없으면 별도 터미널에서 프록시를 시작합니다.

```powershell
.\relay_proxy\start_ai_dlp_info.bat
```

## 2. AI 전용 Windows PAC 적용

```powershell
.\relay_proxy\set_windows_proxy_127_0_0_1_8000.bat
```

이 설정은 ChatGPT, Gemini, Claude만 로컬 프록시로 보냅니다. Outlook, Microsoft 365 및 일반 사이트는 `DIRECT`로 연결됩니다.

## 3. 환경 자동 점검

```powershell
C:\Exception\AI_Upload_Test_Pack\tools\check_environment.ps1
```

모든 항목이 `PASS`인지 확인합니다.

## 4. 브라우저 테스트 전 로컬 파일 분석

```powershell
C:\Exception\AI_Upload_Test_Pack\tools\run_local_analyzer_tests.ps1
```

예상 결과는 안전한 TXT, DOCX, PDF가 `ALLOW`, BAT, 위험 ZIP, 위장 PDF가 `BLOCK`입니다.

## 5. 로그 창 열기

```powershell
C:\Exception\AI_Upload_Test_Pack\tools\start_log_monitors.bat
```

- `relay_events.log`: AI 접속과 업로드 보안 이벤트
- `relay_runtime.log`: 통신 오류와 진단 정보

## 6. Chrome 재시작

모든 Chrome 창을 완전히 종료한 뒤 다시 실행합니다. 기존 탭은 사용하지 말고 새 탭에서 각 서비스에 로그인합니다.

## 7. 서비스별 허용 테스트

다음 순서로 한 번에 하나씩 업로드하고 각 테스트 사이에 5초 이상 기다립니다.

1. ChatGPT: `01_GPT_SAFE.txt`, 이후 `04_COMMON_SAFE.docx`
2. Gemini: `02_GEMINI_SAFE.txt`, 이후 `05_COMMON_SAFE.pdf`
3. Claude: `03_CLAUDE_SAFE.txt`, 이후 `04_COMMON_SAFE.docx`

사이트가 파일을 선택한 직후 전송을 시작하지 않는 경우 메시지 전송 버튼까지 눌러 실제 업로드를 완료합니다.

## 8. 차단 테스트

먼저 `91_BLOCK_nested_script.zip`을 사용합니다. 사이트가 ZIP을 받지 않으면 `90_BLOCK_script.bat`을 사용합니다. BAT 파일은 절대 실행하지 마세요.

프록시 차단이 정상이라면 업로드 또는 메시지 전송이 실패하고 이벤트 로그에 `BLOCK` 또는 `UPLOAD BLOCKED`가 나타납니다. 사이트 자체가 파일 선택 단계에서 거절하면 프록시까지 요청이 도달하지 않으므로 DLP 로그가 없는 것이 정상입니다.

## 9. 기대 로그

접속 시:

```text
AI ACCESS ...
```

허용 업로드 시:

```text
UPLOAD PREPARED ...
UPLOAD INSPECTED ... action=ALLOW ...
UPLOAD FORWARDED ...
```

차단 업로드 시:

```text
UPLOAD INSPECTED ... action=BLOCK ...
UPLOAD BLOCKED ...
```

현재 ChatGPT는 metadata POST와 signed raw PUT 상관분석이 구현되어 전체 업로드 로그가 가장 잘 보입니다. Gemini 또는 Claude에서 `AI ACCESS`만 보이고 `UPLOAD`가 없다면 서비스별 실제 upload host/path 확정이 필요한 결과로 기록합니다.

## 10. 결과 수집

```powershell
C:\Exception\AI_Upload_Test_Pack\tools\collect_latest_results.ps1
```

결과는 이 폴더의 `latest_test_results.txt`에 저장됩니다. 테스트가 끝나면 `TEST_RESULT_CHECKLIST.md`에도 성공 여부와 시간을 기록하세요.

## 테스트 종료

프록시 라우팅을 해제하고 기존 Windows 설정으로 복원하려면 다음을 실행합니다.

```powershell
.\relay_proxy\unset_windows_proxy.bat
```
