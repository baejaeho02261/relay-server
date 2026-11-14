# 최종 파일의 오프라인 릴리스 승인

이 도구는 운영자가 검토한 최종 Windows 시험 기록과 A/B/O 파일을 묶어 릴리스 승인 서명을 만듭니다. 실행 파일이나 제출된 스크립트를 실행하지 않고, 시험 결과를 PASS로 바꾸지 않습니다. 실제 Windows 시험은 `tools/windows/Invoke-FinalWindowsTests.ps1`에서 별도로 수행하며, 이 소스 패키지만으로 실행 완료를 주장하지 않습니다.

이미 완료한 시험 기록은 파일·소스·정책이 동일할 때 사용할 수 있습니다. 빌드 이력의 독립 검증 여부는 계속 `NOT_ATTESTED`로 남습니다.

## 입력 폴더

소스 폴더 밖에 검토용 폴더를 새로 만들고 다음 **8개 파일만** 넣습니다. 아래 예시는 `C:\CozyRelease\reviewed-input`을 사용합니다.

| 파일명 | 넣을 내용 |
| --- | --- |
| `A.exe` | 실제 시험한 최종 A 파일 |
| `B.exe` | 실제 시험한 최종 B 파일 |
| `O.exe` | 실제 시험한 최종 O 파일 |
| `source-manifest.json` | 시험에 사용한 전체 소스의 `Relay Server/maintenance/source-manifest.json` 원본 |
| `policy.json` | 시험 명령의 `-PolicyFile`로 사용한 정책 JSON 원본 |
| `spec.json` | 위 세 파일에 사용한 규격. `tools/artifacts/Create_Spec.bat`의 출력 |
| `manifest.json` | 위 세 파일·소스·정책·규격에 대응하는 배포 명세. `Create_Release_Manifest.bat` 출력의 파일명만 바꾸어 복사 |
| `final-windows-result.json` | `Invoke-FinalWindowsTests.ps1`의 `-ResultFile` 출력 원본 |

보고서의 형식은 `FINAL_WINDOWS_EXECUTION_OBSERVATION`이어야 합니다. 실행·무결성 검사·정리 결과가 성공해야 하며 파일 해시와 크기, 소스 해시, 검토 정책 해시가 일치해야 합니다. 새 형식의 서버 정책 파일을 시험했다면 해당 실행의 등록 승인 완료도 확인합니다. 내용이 다르면 보고서를 수정하지 말고 다른 버전의 파일을 섞었는지 확인하세요.

`spec.json`과 `manifest.json`의 규격은 같아야 합니다. 정책은 `enforce` 및 읽기 전용 API·전체 CRC·릴리스 서명 검사를 유지해야 합니다. 서명 단계에서 변경할 수 있는 정책 항목은 `trustedReleaseKeys`뿐입니다.

## 실행 순서

다음 명령은 풀 소스 압축을 푼 최상위 폴더에서 실행합니다. 예시 절대 경로를 실제 경로로 바꾸세요. 서명은 운영 데이터나 서버 비밀 변수가 전달되지 않은 별도 환경에서 수행합니다.

1. 입력 묶음을 고정합니다.

   ```bat
   node "cozy-peace\Relay Server\tools\artifacts\peace.separated-signing.js" seal "C:\CozyRelease\reviewed-input"
   ```

   입력 폴더에 `bundle-index.json`과 `bundle-review-sha512.txt`가 생성됩니다. 고정 이후에는 내용을 바꾸지 않습니다. 다음 명령의 `검토한_SHA512`에는 검토한 `bundle-review-sha512.txt`의 128자리 값을 넣습니다.

2. 기존 릴리스 승인 개인키로 승인합니다.

   ```bat
   node "cozy-peace\Relay Server\tools\artifacts\peace.separated-signing.js" release "C:\CozyRelease\reviewed-input" "검토한_SHA512" "C:\CozyRelease\approved-output" "C:\PrivateKeys\release-private.pem" "C:\CozyRelease\deployment-policy.json"
   ```

   `approved-output`은 아직 존재하지 않는 새 경로여야 합니다. `deployment-policy.json`은 해당 개인키의 공개키를 `trustedReleaseKeys`로 신뢰하는 배포 정책입니다. 다른 정책 항목은 시험한 정책과 같아야 합니다. 개인키는 소스·입력·출력 폴더 밖에 보관하고 웹에 업로드하거나 실행 파일에 포함하지 않습니다.

3. 신뢰하는 릴리스 공개키로 결과를 검증합니다.

   ```bat
   node "cozy-peace\Relay Server\tools\artifacts\peace.separated-signing.js" verify "C:\CozyRelease\approved-output" "C:\CozyRelease\release-public-key.pem"
   ```

   공개키 PEM 또는 `publicKey` 필드를 가진 공개 JSON을 사용할 수 있습니다. 검증에는 서명할 때 선택한 키와 대응하는 공개키를 사용합니다.

## 결과의 의미

출력의 A/B/O는 입력과 같은 바이트입니다. `A.approval.json`, `B.approval.json`, `O.approval.json`은 각 파일의 역할·버전·해시에 대한 기존 릴리스 승인 형식의 서명입니다. `manifest.json`과 `policy.json`은 선택한 릴리스 신뢰 키를 반영합니다.

`final-windows-result.json`은 수정하지 않고 보존합니다. `release-test-binding.json`은 검토한 입력 묶음·시험 기록·소스·새 배포 명세를 연결하는 V2 서명입니다. 이전 정책과 명세, 입력 인덱스는 `reviewed` 폴더에 남습니다. 전체 출력의 `bundle-index.json`과 `bundle-review-sha512.txt`도 생성됩니다.

이 서명은 **운영자가 검토한 기록의 연결**을 확인합니다. Windows Authenticode 서명, 빌드 도구의 진위, 하드웨어 기반 검증이나 독립적인 실행 관측을 의미하지 않습니다. 자동 게시나 최종 발급 설정을 붙인 A의 개별 서명도 수행하지 않습니다. 서버의 나머지 승인·정책·게시 조건은 그대로 적용됩니다.
