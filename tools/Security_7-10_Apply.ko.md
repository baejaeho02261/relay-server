# GameConnect / GameWeb 보안 개선 7–10 적용 안내

작성일: 2026-10-17. 기준 파일: GameConnect_GameWeb_Security_1-6_Server.zip.
이 전달본은 1–6번을 유지한 누적 **1–10번 소스**입니다. 운영 서버에 배포하거나 실제 Windows 빌드를 수행한 결과물은 아닙니다.

**먼저 확인:** 이번 전달의 8번은 실제 제품 시험을 실행할 도구·시험 전용 코드·결과 검증기를 구현한 것입니다. Linux에서 수행한 계약/서버/암호 시험을 실제 Windows PASS로 바꾸지 않았습니다. 정상 Release와 전용 FaultTest를 Windows에서 빌드·실행해야 합니다. 운영 A/B/O 세 프로그램은 같은 소스로 모두 재빌드하십시오.

## 1. 변경 범위와 유지한 내용

| 항목 | 이번 변경 | 남은 실제 검증 |
|---|---|---|
| 7 | 동일 발급의 만료 변경 거절, 관측된 만료 고정, 원래 승인 시각 보존, 라이선스·상태·서비스 재확인, O 재전송의 기존 응답 유지 | 실제 SQLite, 부하·서버 재시작·운영 환경 |
| 8 | 세 가지 결함 주입과 정상 대조 시험, 실제 서버의 이전 권한 거절 관찰, A 다운로드 시간초과의 구별된 진단 | 실제 Delphi 컴파일, Windows A/B/O, 그래픽·보안 프로그램 환경 |
| 9 | 중요 관리자 변경에 최근 패스키 확인, 세션·challenge 결합, 첫 등록/분실 시 서버 콘솔의 1회 등록 승인 | 물리 패스키·브라우저, 운영 계정·저장소 ACL |
| 10 | 운영 키 없는 CI 빌드/시험 → 별도 배포 승인 → 별도 CI 증명 서명, 시험 결과·정확한 파일·정책 결합 | 실제 Windows CI, 운영 서명 장치/계정, 키 배치 |

Node.js 서버를 C/C++로 재작성하지 않았습니다. 새 프레임워크나 npm 의존성은 추가하지 않았으며, 기존 암호 함수와 직접적인 바이트·범위·상태 검사를 사용합니다. 운영 Win64에는 새 자격 증명 파일이나 측정 성공 캐시를 추가하지 않았습니다. 실행 메모리·측정/보고 코드·패스키 인증기·브라우저 세션 쿠키를 전부 없앴다는 뜻은 아닙니다.

기존 데이터·배포 승인키·CI 개인키는 자동 삭제/생성/교체하지 않습니다. 서버 감사 기록을 지우지 않습니다. 시험 전용 환경에는 제한된 임시 입력·토큰·측정 사건 파일이 생기며, 시험 후 그 시험이 소유한 자원만 정리합니다. 비밀이 없는 시험 결과는 승인 근거로 남깁니다. 관리자 등록 승인용 파일도 서버/관리자 환경에서만 사용하고 사용 후 직접 정리합니다.

1–3번의 관리자 HTTPS 설정은 그대로 필요합니다. 이전 HTTP 관리자 접속을 다시 허용하지 않습니다. 4–6번 푸시 목적지/서버 권한/미완료 측정 검사도 유지합니다. 전체적으로 검증된 A+ 등급이나 임의 로컬 패치 탐지 성공을 의미하지 않습니다.

## 2. 7번: 만료·취소·재사용

변경 파일은 `services/desktopDeadline.js`, `desktopLicenses.js`, `desktopBootstrap.js`, `desktopOverlay.js`입니다.

동일한 발급 시각과 식별자에서 만료 시각만 바꾸는 입력을 거절합니다. 한 프로세스에서 이미 관측한 만료는 벽시계가 돌아가도 되살리지 않습니다. 정상적인 새 갱신은 이전 권한이 아직 살아 있고 서버의 다른 승인 조건도 충족할 때만 반영합니다. 서버 운영체제나 데이터베이스 자체를 장악한 공격자까지 이 메모리 기반 시계 보완이 방어하는 것은 아닙니다. 재시작 후에는 저장된 상태와 신뢰하는 서버 시각이 여전히 필요합니다.

라이선스의 저장이 지연되어도 저장 완료 시점에서 새 수명을 만들지 않습니다. 원래 요청에서 승인한 `originalAt`/`originalExpiresAt`을 유지하고 세션과 실제 라이선스의 현재 상태를 다시 확인합니다. 닫힘·취소·만료되었거나 더 새로운 검증이 이미 반영된 상태를 늦게 끝난 요청이 덮지 못하도록 했습니다. 결과적으로 B의 권한은 원래 라이선스 승인 기한으로 제한될 수 있으며, 이전처럼 저장 지연 뒤 별도의 300초가 생긴다고 기대하면 안 됩니다. 서버/클라이언트의 주기 타이머를 무작정 단축한 변경은 아닙니다.

O 갱신은 같은 관측/요청이면 원래 응답과 만료를 유지합니다. commit 내부와 응답 전의 실제 상태를 확인합니다. 정리·취소 경로를 새 승인을 발급하는 경로로 사용하지 않습니다.

## 3. 8번: 실제 Windows 시험 실행

### 필요한 빌드

정상 Release: `GameLauncher.dproj`, `GameConnect.dproj`, `GameOverlay.dproj`.

시험 전용 Release: `GameConnect_Win64/tests/product-faults/` 아래 `GameLauncherFaultTest.dproj`, `GameConnectFaultTest.dproj`, `GameOverlayFaultTest.dproj`.

시험 전용 O는 기존 `tests/manual-ide/gpu-fault/game_imgui_fault_test.o`가 필요합니다. IDE 사용 시 해당 폴더의 기존 프로젝트/안내와 `GameWeb/tools/Product_Fault_Tests.html`을 따르십시오. 새 CI 경로는 먼저 수행한 overlay-contract 빌드의 전용 object를 이 시험 경로로 복사합니다. **정상 프로젝트의 DEFINE을 바꿔 시험 모드로 만들지 마십시오.** 운영 빌드에서 `GAME_PRODUCT_FAULT_TESTS`를 금지하는 방어와 시험 EXE의 비운영 표식을 유지했습니다.

### 실행

Windows x64의 대화형 데스크톱, PowerShell 7 x64, 프로젝트 지원 Node.js, 설치된 프로젝트 의존성이 필요합니다. 사용자 서비스가 실제 SQLite를 필요로 하므로 그 모듈도 정상 설치되어야 합니다.

```bat
GameWeb\tools\Run_Security_Authority_Windows_Tests.bat
```

정상 A/B/O와 시험 A/B/O의 전체 경로, 실제 숫자 버전, 시험할 서버 정책 JSON을 입력합니다. 기본 경로는 `GameConnect_Win64/bin/` 및 `tests/product-faults/bin/`입니다. 정책을 생략하면 명시된 기본 enforce 정책을 시험한 것으로 기록합니다. 운영 정책과 다르면 운영 정책에 대한 시험으로 재사용하면 안 됩니다.

입력 파일을 미리 제공하려면 다음 형식입니다. `policyFile`은 선택적이지만 새 분리 서명 절차에서는 승인할 정책과 시험 설정이 일치해야 합니다.

```json
{
  "version": 1,
  "releaseVersion": "1.0.0",
  "artifacts": {"A":"C:\\Build\\A.exe","B":"C:\\Build\\B.exe","O":"C:\\Build\\O.exe"},
  "faultArtifacts": {"A":"C:\\Tests\\GameLauncherFaultTest.exe","B":"C:\\Tests\\GameConnectFaultTest.exe","O":"C:\\Tests\\GameOverlayFaultTest.exe"},
  "policyFile": "C:\\Reviewed\\deployment-policy.json"
}
```

```powershell
& .\GameWeb\tools\security-authority-windows-tests.ps1 `
  -InputFile 'C:\Reviewed\authority-input.json' `
  -ResultFile 'C:\Evidence\authority-new-result.json'
```

출력은 존재하지 않는 새 파일을 선택하십시오. 시험은 기존 운영 서버가 아니라 새 격리 서버에서 실행됩니다. 부모·자식 프로세스 핸들을 추적하고 해당 시험이 소유한 자원만 정리합니다.

### 네 가지 시나리오와 합격 조건

| 시나리오 | 입력/관찰 | 합격에 필요한 사실 |
|---|---|---|
| lifecycle-cleanup-success | 실제 정상 Release A/B/O | 승인·인계·종료·정리가 실제로 관찰됨 |
| authority-measurement-skipped | 실제 첫 O 승인 후 다음 측정을 생략하는 전용 빌드 | 생략 사건, 미완료의 거절, 새 승인 없음, 이전 권한 재사용 거절 |
| authority-report-stopped | 실제 첫 승인 후 다음 서명 보고 제출을 중단 | 중단 사건, 새 갱신 없음, 서버의 종료/만료와 이전 권한 거절 |
| authority-local-stop-held | 실제 만료 뒤 전용 자기 O만 최대 30초 종료를 지연 | 동일 O가 살아 있는 중 서버가 기존 권한을 거절한 사실, 그 뒤 소유 프로세스 정리 |

시험은 서버 시각이나 권한 행을 직접 고쳐 만료시켰다고 표시하지 않습니다. 시험 격리 환경에서 정확한 자기 O의 정리 요청을 보류해, 정상 서버의 만료 처리 자체를 관찰하는 경우가 있습니다. 실제 이전 요청과 자격 증명을 재사용해 거절을 확인하며 비밀은 공개 결과에 넣지 않습니다. 시험자가 만든 PASS JSON만으로 실제 실행이 되었다고 간주하지 않습니다.

제보한 임의의 EXE 패치를 자동으로 재현하거나 임의 분석 도구를 조작하는 도구는 아닙니다. 정상 실행과 전용 오류 주입 실행은 결과에서 구별됩니다. 신뢰를 잃은 Windows 실행기가 거짓 결과를 만들 수 있다는 한계는 별도이며, 파일 해시와 서명만으로 하드웨어 원격 증명이 되지는 않습니다.

### 4분 50초 진단

`Game.Bootstrap.pas`의 다운로드 단계 제한 290000ms는 그대로입니다. 이 분기의 오류 코드를 `BOOTSTRAP_DOWNLOAD_DEADLINE`으로 분리했고, A의 서명된 수명주기 보고에 `DOWNLOAD_DEADLINE` 관찰을 실을 수 있게 했습니다. 서버 `desktopTimingDiagnosis.js`는 서버가 확정한 권한 종료와 클라이언트가 보고한 다운로드 제한을 구별합니다.

290초라는 관찰만으로 하트비트라고 추정하지 않습니다. 보고가 도착하지 않으면 원인을 모를 수 있으며, 서버 수신 순서도 실제 인과 순서와 같다고 단정하지 않습니다. 사용자가 수정한 이전 EXE의 실제 종료 원인은 이번 작업에서 검증하지 못했습니다.

## 4. 9번: 중요 관리자 작업과 첫 패스키 등록

신뢰 키·보안 정책·기준 측정값·중요 증거·배포 활성화·기기 복구 등에는 **최근 5분 안의 서버 검증 패스키 인증**을 요구합니다. 단독 관리자 방식은 그대로이며, 두 사람의 계정을 만들도록 강제하지 않습니다. 최근 비밀번호 재입력은 이 조건을 충족하지 않습니다. 패스키 challenge는 해당 세션과 인증 목적에 결합되어 다른 세션의 응답을 가져다 쓸 수 없습니다.

클라이언트 세션 객체의 `verified`류 플래그로 최근 인증을 만들 수 없고, 서버의 비공개 세션 메타데이터와 단조 시간을 확인합니다. 패스키를 폐기하면 그 패스키에 결합된 세션도 사용 불가합니다. 일반 조회·후보 업로드·계획 생성은 기본적으로 이 중요 변경 단계와 구분됩니다. `DESKTOP_ADMIN_REAUTH_REQUIRED=1`은 범위를 확장할 뿐, 0으로 중요 작업의 필수 조건을 끄지 못합니다.

### 기존 패스키가 있을 때

현재 HTTPS 관리자 화면에서 중요 작업을 실행하면 패스키 확인창이 열립니다. 올바른 패스키로 인증하면 원래 요청을 한 번 재시도합니다. 패스키 취소·실패 때 자동으로 비밀번호로 낮추지 않습니다.

### 처음 등록하거나 모든 패스키를 잃었을 때

최근 패스키가 없어서 영구 잠기는 문제를 피하기 위해 **서버 콘솔에서 1회 등록만 승인**할 수 있습니다.

관리자 HTTPS 비밀번호 로그인 후 패스키 등록 또는 “분실 복구 등록”을 선택하면 현재 공개 세션 ID가 표시됩니다. 이 ID는 세션 토큰이 아닙니다. 서버에 직접 접속하여, 실제 서버와 같은 서비스 계정 및 `DATA_DIR`로 아래 명령을 실행하십시오. 예시 ID와 경로는 실제 값으로 바꾸십시오.

```powershell
$env:DATA_DIR = 'D:\GameWebData'
node .\GameWeb\tools\admin-enrollment-approve.js issue `
  0123456789ABCDEF 'D:\AdminOnly\new-enrollment-approval.json'
```

이미 `GameWeb` 폴더에 있다면 스크립트 경로는 `tools/admin-enrollment-approve.js`입니다. 출력 폴더는 먼저 관리자만 읽게 만들고, 새 파일명을 사용합니다. JSON의 `token`을 관리자 화면의 승인 입력란에 넣으십시오. 토큰은 출력 로그에 직접 표시하지 않으며 명령줄 인수로 전달하지 않습니다. 사용하거나 만료된 출력 파일은 관리자 영역에서 정리하십시오.

승인은 그 **세션의 패스키 등록 한 건에만** 사용되며 5분 기한입니다. 등록 시작 시 원자적으로 소비되고 실제 등록 challenge 한 건의 완료에만 연결됩니다. 중간 취소·네트워크 실패·서버 재시작 등으로 완료하지 못하면 새 승인을 발급합니다. 기존 패스키·서명키·계정을 삭제하지 않으며, 이 토큰으로 정책 변경이나 배포 활성화를 직접 수행할 수는 없습니다. 새 패스키 등록 후 패스키 로그인/재인증을 완료해야 중요 변경이 허용됩니다.

서버에는 토큰 해시만 제한된 `.admin-enrollment` 하위에 보관합니다. Unix 권한 모드 요청만으로 Windows ACL을 보장하지는 않습니다. 실제 서비스 계정·데이터 폴더·승인 출력 파일의 Windows ACL은 운영자가 확인해야 합니다. 서버 콘솔이 장악된 상황을 이 복구 절차가 막는다는 의미는 아닙니다.

## 5. 10번: 빌드와 서명은 다른 단계

이제 **CI 성공 = 곧바로 운영 배포 승인 완료**가 아닙니다. 기존 수동 IDE 빌드 기능은 유지하지만, 새 분리 서명 경로는 실제 Windows CI와 시험 결과가 담긴 묶음을 요구합니다. IDE에서 만든 EXE 세 개나 개별 4사례 시험 결과만 넣어 CI 전체가 수행됐다고 표시하지 않습니다.

### 단계 A: 운영 개인키 없는 Windows 빌드·시험

기존 `Run_Windows_CI.bat`/CI 실행 도구를 사용합니다. Windows x64 Native Tools 환경, RAD Studio, OpenSSL, Node.js, Python 및 실제 의존성이 필요합니다. 기존 검토된 build-input lock과 공개 운영 정책은 필요하지만 **배포 승인키와 CI 증명 개인키는 빌드 실행기에 주지 않습니다.**

`GAME_RELEASE_APPROVAL_KEY_B64`, `GAME_CI_ATTESTATION_KEY_B64`, 기존 `-ReleaseKeyFile`/`-CiKeyFile`을 빌드 실행에 전달하면 거절합니다. Workflow의 두 secret 주입을 제거했습니다. 실제 GitHub 설정이나 기존 실행기의 파일/계정은 이 소스 수정으로 제거되지 않습니다. 빌드 계정·장치가 운영 키 저장소에 접근하지 못하게 실제 배치도 변경해야 합니다. 서로 다른 경로만으로 동일 계정에 두 키를 보관하는 것은 별도 신뢰 영역이 아닙니다.

빌드는 임시 시험용 Ed25519 키만 생성해 서명 필수 경로를 시험합니다. 임시 키 파일은 정리하며 **운영 서버가 이 시험 키를 신뢰하도록 등록하면 안 됩니다.** 정책의 다른 설정은 시험 대상 정책과 일치시킵니다. 테스트는 정상 A/B/O와 전용 fault 세트를 구별해 기록합니다.

성공 결과: `UNSIGNED_WINDOWS_TEST_BUNDLE`, `runner-results.json`의 `productionKeysPresent=false`, `signed=false`. 파일·소스·입력 잠금·로그·무결성 정책·실제 Windows 시험 결과를 담고 `bundle-index.json`/`bundle-review-sha512.txt`로 검토 대상을 고정합니다.

### 단계 B: 별도 배포 승인 환경

신뢰하는 오프라인 도구 사본과 배포 승인 전용 개인키를 사용합니다. **전달받은 묶음 안의 스크립트나 EXE를 이 환경에서 실행하지 마십시오.** 승인자는 출처·작업 로그·기대 버전·정책·시험 결과를 검토하고 인덱스의 SHA-512를 별도 신뢰 경로로 확정해야 합니다. 묶음에 쓰인 해시를 확인 없이 그대로 읽어서 인수로 넘기는 것만으로 출처 검토가 되지는 않습니다.

```powershell
node 'D:\TrustedTools\GameWeb\ci\separated-signing.js' release `
  'E:\Reviewed\unsigned-bundle' `
  '<독립적으로 검토한 bundle-index.json의 128자리 소문자 SHA-512>' `
  'E:\Approved\new-release-bundle' `
  'D:\ReleaseKeys\release-private.pem' `
  'D:\ReviewedPolicy\deployment-policy.json'
```

출력 디렉터리는 존재하지 않는 새 경로여야 합니다. 도구는 최종 EXE 바이트와 각 결과의 해시, 필수 실제 Windows 단계, 정확한 네 권한 시험, 설정을 검사합니다. 복사 중 바뀐 바이트도 서명 전 거절합니다. 개인키는 입력/출력 묶음 밖에 있어야 합니다. 시험 정책과 운영 정책의 **허용된 차이는 임시 시험용 신뢰 공개키를 운영 신뢰 공개키로 바꾸는 것뿐**입니다. 다른 보안 설정이 다르면 새로 시험하십시오.

같은 최종 EXE를 재빌드/변경하지 않고 운영 배포 승인을 생성합니다. 원래 시험 매니페스트와 운영 매니페스트, 이전 묶음 해시, 정책 차이를 `release-test-binding.json`으로 서명합니다. 버전 2 호환성 증거도 사실 값은 유지하고 매니페스트 결합만 정확하게 새로 연결합니다. 이 증거의 의미는 운영자가 검토한 실행 결과이지 하드웨어 증명은 아닙니다.

### 단계 C: 별도 CI 증명 서명 환경

배포 승인 환경과 다른 계정/장치에 CI 증명 전용 개인키를 두고 수행합니다. **기대하는 배포 공개키도 입력 묶음에서 자동으로 믿지 말고 별도 검증된 사본을 사용합니다.**

```powershell
node 'D:\TrustedTools\GameWeb\ci\separated-signing.js' attest `
  'E:\Reviewed\release-bundle' `
  '<검토한 배포 승인 묶음 인덱스의 128자리 소문자 SHA-512>' `
  'E:\Approved\new-final-ci-bundle' `
  'D:\CiKeys\ci-attestation-private.pem' `
  'D:\TrustedPublicKeys\expected-release-public.pem'
```

배포 승인과 CI 서명에 같은 키를 사용하면 거절합니다. 기존 배포 승인 서명, 원래 Windows 시험, 정확한 파일과 정책 결합을 재검증한 뒤 최종 `ci-evidence.json`과 호환성 서명을 만듭니다. 두 오프라인 단계는 EXE·전달된 테스트 스크립트를 실행하지 않습니다. 키 파일을 온라인 서버/빌드로 자동 복사하지 않습니다.

### 마지막 확인 및 기존 수동 경로의 범위

기존 `Check_CI_Output`/Tools의 CI 결과 검증은 최종 CI 서명 묶음을 대상으로 실행하십시오. 새 무서명 빌드 중간 산출물은 아직 최종 승인 결과가 아닙니다. 최종 검증에는 사전에 신뢰한 CI 공개키가 필요합니다.

기존 수동 배포 기능과 선택적 CI 정책을 이 작업에서 전부 삭제하거나 강제 변경하지 않았습니다. 수동으로도 키 소유자가 다른 파일에 서명할 수 있으므로 “모든 가능한 서명 방법을 코드로 금지했다”고 해석하면 안 됩니다. 이번 새 경로의 엄격한 승인을 사용하고 운영 개인키 접근을 분리해야 10번의 의도에 맞습니다. 운영을 새 경로로 제한하는 조직적/서버 정책은 실제 운영 설정과 함께 검토하십시오.

## 6. 시험 명령과 이번 결과의 한계

`GameWeb`에서 다음을 실행합니다.

```text
npm run test:security:all
npm run test:security:456:tls
npm run check:native
npm run check:ui
python scripts/verify-source.py
```

`test:security:78910`은 만료/재사용 25, 관리자 인증/등록 승인 14, Windows 결과 계약 21, 분리 서명 27의 **87개**입니다. 실제 서버 함수·암호·파일 검증과 합성 입력/격리 저장소를 사용하며 일부 정적 소스 검사도 포함합니다. Windows 21개는 Windows 실행 증거가 아닙니다. 분리 서명 시험의 가짜 EXE/합성 실행 보고는 검증기 테스트용이며 실행하지 않았고, 실제 Windows 결과물로 배포하지 않습니다.

기존 1–6 회귀, HTTPS/푸시 실제 루프백 TLS, 추가 수명주기·빌드 도구 계약도 실행했습니다. 자세한 명령·결과·로그는 전달된 시험 보고서에 있습니다. 네 통합 실행(`test-product-fault-wire`, `test-lifecycle-trace`, `test-desktop-deadlines`, `test-security-authority`)은 `better-sqlite3` 미설치로 중단됐습니다. 실패를 PASS나 취약점 없음으로 표시하지 않았습니다.

시험 환경은 Linux / Node.js 22.16.0입니다. `package.json`이 선언한 지원 범위 `^22.22.2 || ^24.15.0 || >=26.0.0` 밖입니다. 지원 런타임·실제 SQLite에서 재시험해야 합니다. 실제 Delphi/C++ 컴파일, Windows/PowerShell 실행, 물리 패스키, 운영 방화벽·호스트 ACL·서명 장치 분리는 여기서 검증하지 못했습니다. PowerShell은 정적 검토만 했으며 실제 파서/실행 통과라고 주장하지 않습니다.

## 7. 배포 전 순서

새 폴더에 누적 전체본을 풀고 데이터·인증서·기존 키는 별도로 보존합니다. 소스 일치 검사, 지원 Node.js/실제 의존성 시험, HTTPS 관리자와 패스키 등록/복구 점검을 먼저 수행합니다. 같은 소스로 정상 A/B/O 및 전용 시험 세트를 빌드합니다. 실제 Windows 권한 시험의 원본 결과를 확인하고, 새 CI·분리 서명 경로를 사용한 경우 최종 승인까지 완료한 동일 파일만 운영에 적용하십시오. 시험용 키·EXE를 운영 등록하지 마십시오.

운영 적용 전에 정상 로그인/권한 갱신/종료도 확인해야 합니다. 지연된 저장 뒤 기한을 새로 주지 않거나 새 측정이 이전 성공을 무효화하는 변경은 의도적인 fail-closed 동작이며, 과부하·잘못된 정책에서도 정상 사용자의 체감 영향이 있을 수 있습니다. 그때 검사를 해제하거나 임의 시간을 늘려 숨기지 말고 최초 오류와 서버 결과를 확인하십시오.

## 검토에 사용한 공개 기준

- OWASP Authentication Cheat Sheet, 민감 작업의 재인증: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- GitHub Actions Secure use reference, 비밀과 자체 실행기 신뢰: https://docs.github.com/en/actions/reference/security/secure-use

이 문서와 소스 매니페스트는 전달 파일의 내용과 절차를 설명합니다. 자체 해시 목록이 독립된 배포자 인증이나 보안 등급 인증을 대신하지는 않습니다.
