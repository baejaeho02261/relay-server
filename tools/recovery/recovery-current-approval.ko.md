# 현재 발급 형식의 격리 Windows 복구 시험

`Run_Recovery_Windows.bat`은 복사한 서버 저장소와 원래 PC의 기기 키를 사용하는 실행 시험 도구입니다. 현재 A 형식은 실행 요청마다 명시적인 승인과 기기 키 소유 증명을 요구합니다. 예전 bearer-ticket 방식으로 새 A 흐름을 만들지 않습니다.

`recovery-windows-input.example.json`을 별도 운영자 설정 파일로 복사하여 실제 경로와 기기 식별자를 입력합니다. 새 필드는 다음과 같습니다.

- `issuedASigningKeyFile`: 선택한 A에 내장된 공개 검증 키와 일치하는 **발급 서버의 RSA 개인키 PEM** 절대 경로. EXE 승인 키와 다른 용도입니다. 소스, 백업, witness 스냅샷, 시험 작업 폴더 밖에 두고 운영자 계정만 읽도록 제한합니다. 도구는 키를 새로 만들거나 다른 키로 대체하지 않습니다.
- `allowIsolatedRequestApproval: true`: 이 격리 시험에서 생성한 각 기기 증명 요청과 최종 시험용 A 요청에 대한 승인입니다. 최종 A 요청은 새로 발급한 launcher ID, 원래 PC, 실제 증명한 교체 키가 모두 일치할 때 한 요청만 승인합니다. 운영 서버의 요청이나 다른 발급 파일에 적용하지 않습니다.

발급 키는 격리된 복구 서버 프로세스에서만 읽습니다. 복구 계획·시험 결과·A/B/O·네이티브 기기 키 probe에 개인키를 넣지 않습니다. 네이티브 probe는 서버 발급 키 환경 변수를 상속하지 않습니다. 최초 기기 키와 교체 기기 키의 요청 서명은 원래 Windows probe를 통해 수행하며, 서버에서 임의 기기 키를 만들어 대신 승인하지 않습니다.

필수 조건이 없으면 다음 오류로 중단합니다.

| 코드 | 조치 |
| --- | --- |
| `RECOVERY_REQUEST_APPROVAL_CONSENT_REQUIRED` | 격리 시험용 요청 승인 범위를 확인하고 설정에 명시합니다. |
| `RECOVERY_ISSUED_A_SIGNER_PATH_REQUIRED` | 일치하는 발급 서버 개인키 파일의 절대 경로를 지정합니다. |
| `RECOVERY_ISSUED_A_SIGNER_MUST_BE_OUTSIDE_SOURCE_AND_BACKUP` | 개인키를 소스·백업·witness·시험 작업 폴더 밖의 제한된 위치로 옮깁니다. |
| `RECOVERY_ISSUED_A_SIGNER_PATH_INVALID` | 실제 존재하는 디렉터리의 일반 파일 경로를 사용하고 링크 경로를 제거합니다. |
| `RECOVERY_ISSUED_A_SIGNER_INVALID` | 읽기 권한과 지원되는 RSA-2048 개인키 PEM 형식을 확인합니다. |
| `RECOVERY_ISSUED_A_SIGNER_MISMATCH` | 선택한 A의 공개 검증 키와 일치하는 발급 서버 키를 사용합니다. |
| `RECOVERY_NATIVE_BOOTSTRAP_SIGNER_REQUIRED` | 원래 Windows 기기 키 probe의 실제 서명 연결이 필요합니다. |
| `RECOVERY_TPM_REENROLLMENT_CHANNEL_REQUIRED` | 현재 `PLATFORM` 교체 키 복구는 차단됩니다. 인증된 A 없이 새 TPM 키를 사전 증명하는 별도 등록 경로가 아직 필요합니다. `SOFTWARE`로 낮추거나 TPM 증명 결과를 만들어 대신 진행하지 않습니다. |

`SOFTWARE` 경로의 프로토콜·서명·격리 저장소 동작은 자동 회귀시험으로 검사합니다. 이는 실제 Windows/CNG 또는 A→B→O 실행 성공을 뜻하지 않습니다. 실제 Windows 실행과 정리 결과가 없으면 실행 성공 자료로 사용할 수 없습니다.

`Run_Recovery_Drill.bat`의 합성 서비스 시험은 별도입니다. 합성 발급 키는 소스와 복사한 백업 데이터 밖의 소유 표시가 있는 임시 폴더에서만 생성·공유하고 시험 종료 시 폴더와 함께 제거합니다. 운영 백업에 대해 합성 키를 사용하지 않으며, 원래 기기나 실제 TPM을 검증했다고 표시하지 않습니다.
