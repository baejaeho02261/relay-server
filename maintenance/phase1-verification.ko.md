# Windows 실행 시험과 서버 권한 검증

> 이전 단계의 기록입니다. 현재 구현·게시 제한과 남은 작업은 `phase2-verification.ko.md`를 확인하세요. 아래 VM v1 경로와 명령의 당시 상태를 현재 운영 승인으로 사용하지 않습니다.

이번 변경은 서버 권한 우회 회귀 시험, 최종 Windows 파일 시험 도구, 클라이언트 내장 키 검사를 추가합니다. 새 Windows 실행 환경은 아직 연결되지 않았습니다. Linux에서 통과한 준비·프로토콜 검사를 실제 Windows EXE 실행 성공으로 취급하지 않습니다.

## 배포 때 자동 실행하는 서버 시험

Docker 빌드는 소스 일관성·실제 서버 시작/종료 검사 뒤 `node --test tests/security/peace.test-server-authority-bypass.js`를 실행합니다. 실패하면 이미지 빌드가 실패합니다. 임시 DATA_DIR, 루프백 TLS, 실제 암호화 요청·검증 워커·SQLite를 사용하며 운영 등록 데이터나 실제 고객 PC에 요청하지 않습니다. 사용한 소켓·워커·시험용 키와 데이터를 정리합니다.

시험 범위는 잘못된 파일 해시·기기·역할·서명, 권한 확인 생략, 재전송, 라이선스·세션 폐기와 인증 만료입니다. 클라이언트가 보고하는 해시는 하드웨어 증명이 아닙니다. 아직 사용하지 않은 A를 복사한 소지자를 원래 수신자와 구분한다는 보장도 하지 않습니다.

## 최종 EXE의 내장 키 검사

```text
node tools/security/peace.audit-client-secrets.js A.exe B.exe O.exe
```

종료 코드 0은 검사 대상 항목에서 PASS, 1은 BLOCKED, 2는 검사 오류입니다. JSON에는 규칙 코드·역할·해시를 기록하며 키 값, 매칭한 비밀 문자열 또는 입력 경로를 출력하지 않습니다. EXE 실행·서버 접속·파일 변경은 없습니다. 공개키·인증서 지문·파일 해시는 비밀로 분류하지 않습니다. 임의 인코딩까지 포함한 모든 비밀의 부재를 증명하지 않습니다.

현재 Cozy VM v1이 생성한 SEALED 파일에는 복호화 키가 들어 있으므로 `COZY_VM_V1_EMBEDDED_KEY`로 차단됩니다. 이 변경은 키 탐지이며 키 제거가 아닙니다. 기존 발급·운영 형식은 자동으로 전환하거나 폐기하지 않습니다.

## 별도 Windows 환경에서 실행할 최종 파일 시험

Windows x64, PowerShell 7, 소스에서 고정한 Node 버전, npm, OpenSSL 및 렌더링 가능한 격리된 테스트 데스크톱 세션이 필요합니다. 서비스의 Session 0에서 Overlay 화면 시험을 통과했다고 처리하지 않습니다. 새로 컴파일할 때는 라이선스가 유효한 Delphi/C++ 도구가 필요합니다.

전체 소스 ZIP을 새 폴더에 풀고, 동일한 패킹 작업에서 받은 최종 A/B/O 템플릿, 웹에서 내보낸 세 패킹 기록의 JSON 배열, 현재 공개 보안 정책 JSON을 준비합니다. 시험 정책은 mode=enforce이고 requireReadonlyApi, requireCompleteCrcLayers, requireReleaseSignature가 모두 true여야 합니다. 개인키나 운영 DATA_DIR는 입력하지 않습니다. 이미 고객용으로 발급한 A는 템플릿으로 사용할 수 없습니다.

```powershell
pwsh -NoProfile -File '.\cozy-peace\Relay Server\tools\windows\Invoke-FinalWindowsTests.ps1' `
  -SourceRoot '.\cozy-peace' `
  -AFile 'C:\CozyTestInputs\A.exe' `
  -BFile 'C:\CozyTestInputs\B.exe' `
  -OFile 'C:\CozyTestInputs\O.exe' `
  -PackingReceiptsFile 'C:\CozyTestInputs\packing-receipts.json' `
  -PolicyFile 'C:\CozyTestInputs\policy.json' `
  -Version '1.0.0' `
  -ResultFile 'C:\CozyTestResults\run-001.json'
```

경로와 Version은 실제 선택한 파일·버전에 맞춰야 합니다. 결과 파일의 부모 폴더는 미리 만들고, 결과 파일은 새 이름을 사용합니다. 원본 EXE를 변경하지 않으며 시험에 복사한 바이트를 전후로 확인합니다. 임시 승인 키는 시험 프로세스에서만 생성하고 운영 승인·서명으로 사용하지 않습니다.

결과는 `FINAL_WINDOWS_EXECUTION_OBSERVATION`입니다. `integrationAttempted`와 `finalExecutionVerified`, `secretBoundary`, 정리 결과를 각각 확인합니다. `buildProvenance=NOT_ATTESTED`, `productionApproved=false`이며, 입력한 패킹 기록의 운영 출처도 독립적으로 증명하지 않습니다. 이 파일은 게시 승인으로 등록할 수 없습니다. 현재 VM v1은 실행 시험을 통과해도 내장 키 검사 때문에 전체 결과가 BLOCKED입니다.

시험 자료 다운로드는 관리자 전용 `GET /api/desktop/bootstrap/security-operations/packed-release-jobs/<jobId>/receipts`를 사용합니다. 이 읽기 작업은 게시·등록·발급을 실행하지 않습니다.

## 남은 작업

새 Windows 환경 연결 후 실제 A/B/O 실행 시험이 필요합니다. 키 없는 발급 형식은 공개 연결 정보, 최초 사용자/기기 인증, 서버에서 처리할 민감 연산을 새 버전으로 설계하고 A/B/O를 함께 전환해야 합니다. 그 검증 뒤 최종 Authenticode 서명·승인·명세·게시 자동화를 연결합니다. 현재 VM 키를 지웠다거나 전체 함수를 암호화했다고 보고하지 않습니다.
