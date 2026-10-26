# Windows 최종 서명 준비

`ci/pipeline/Invoke-AuthenticodePreparation.ps1`는 A/B/O 복사본에 Windows Authenticode 서명과 RFC 3161 타임스탬프를 적용하고 검증하는 준비 도구입니다. 원본 파일을 바꾸지 않고 새 출력 폴더만 만듭니다. 라이선스 발급, 게시, 서버 승인 또는 실제 제품 실행 시험을 수행하지 않습니다.

## 준비 조건

- 별도의 Windows x64 서명 호스트와 PowerShell 7, 프로젝트에서 고정한 Node 버전이 필요합니다.
- Windows SDK의 `signtool.exe`와 Node 실행 파일을 준비하고 신뢰한 배포 경로에서 검토한 각각의 SHA-512 값을 전달합니다. 실행할 파일의 해시를 방금 계산해 그대로 신뢰하는 것은 검토를 대체하지 못합니다. 도구 사용 중 읽기 전용 핸들로 파일 쓰기·교체를 막고, Node 버전 검사도 비밀 변수를 제외한 제한된 자식 작업에서 실행합니다.
- 코드 서명 인증서를 Windows의 CurrentUser 또는 LocalMachine `My` 저장소에 연결합니다. 개인키는 서명 공급자/HSM에서 관리하고, 인증서 DER의 공개 SHA-256 지문으로 선택합니다. 이 도구는 PFX, 비밀번호 또는 개인키 파일을 받지 않습니다. HSM인지 소프트웨어 키인지까지 도구가 증명하지 않으므로 공급자 정책으로 보장해야 합니다.
- 운영자가 검토한 HTTPS 타임스탬프 주소를 인자로 전달합니다. 서명 호스트에는 공급자·인증서 폐기 상태·타임스탬프 검증에 필요한 네트워크 연결이 필요합니다.
- 모든 패킹·보호 처리와 O 정규화는 서명 전에 끝내야 합니다. 현재 알려진 내장 VM 키가 있는 입력은 거부합니다. 제한된 비밀 검사 PASS는 모든 숨겨진 비밀의 부재를 증명하지 않습니다.

```powershell
pwsh -NoProfile -File '.\cozy-peace\Relay Server\ci\pipeline\Invoke-AuthenticodePreparation.ps1' `
  -AFile 'C:\ReleaseInputs\A.exe' -BFile 'C:\ReleaseInputs\B.exe' -OFile 'C:\ReleaseInputs\O.exe' `
  -SignTool $ReviewedSignToolPath -SignToolSha512 $ReviewedSignToolSha512 -NodeSha512 $ReviewedNodeSha512 `
  -CertificateSha256 $CodeSigningCertificateSha256 -CertificateStore CurrentUser `
  -TimestampUri $ReviewedTimestampUri -OutputDirectory 'C:\ReleaseOutputs\signed-new'
```

입력은 아직 Authenticode가 서명되지 않은 서로 다른 파일이어야 합니다. 이미 고객별 발급 정보가 붙은 A는 템플릿으로 사용할 수 없습니다. 출력의 부모 폴더는 미리 만들고 출력 폴더 자체는 새 이름을 사용합니다. 같은 부모 폴더에 무작위 이름의 전용 임시 폴더를 생성하고 권한을 제한하므로 별도 드라이브의 출력도 지원합니다. 기존 폴더를 자신의 작업 폴더로 취급하지 않으며 생성 직후 실패도 정리 대상으로 기록합니다. 인증서·도구 정보는 공개 검증값이며 프로젝트 소스에 개인키를 넣지 않습니다.

## 검증과 결과

서명 명령에 `/fd SHA256`, `/tr`, `/td SHA256`를 명시합니다. 이후 `verify /pa /all /tw`와 `Get-AuthenticodeSignature`를 모두 검사하고, 선택한 인증서 및 타임스탬프를 확인합니다. 검증하는 동안 결과 파일에 읽기 핸들을 유지해 변경을 막고, 검증 전 해시와 변환 비교 해시·최종 해시가 모두 같아야 합니다. 각 자식 프로세스에 시간·로그 제한을 두고 작업 종료 시 해당 작업의 프로세스와 임시 입력 복사본·로그만 정리합니다. 인증서 공급자가 별도로 관리하는 서비스는 종료하지 않습니다.

`peace.authenticode-plan.js`는 서명 전후 PE의 체크섬·인증서 디렉터리·정렬된 인증서 테이블 외의 바이트가 바뀌지 않았는지 검사합니다. 코드·데이터 변조와 설명되지 않은 뒤쪽 데이터 추가를 거부합니다. 이 검사는 서명 구조만 비교합니다. 가짜 인증서 바이트도 구조는 맞을 수 있으므로 이 도구 단독의 `signatureCryptographicallyVerified`는 항상 false입니다. Windows 검증을 실제 통과한 서명 래퍼만 별도 결과에 true를 기록합니다.

새 출력에는 A.exe, B.exe, O.exe와 `authenticode-preparation.json`이 들어갑니다. 출력 JSON은 독립적으로 서명된 증명이나 운영 승인 자료가 아닙니다. `productionApproved=false`, `publicationPerformed=false`, `windowsProductExecuted=false`를 유지합니다. 최종 stdout에 정리 결과와 종료 코드를 확인하세요. 파일에 보관한 준비 기록은 최종 임시 폴더 정리 전에 작성되므로 정리 완료를 보증하지 않습니다.

## 아직 자동 게시하지 않는 이유

서명하면 최종 파일 SHA-512가 달라집니다. 기존 패킹 기록을 서명된 파일의 기록인 것처럼 재사용할 수 없습니다. 최종 서명 바이트의 실제 Windows 실행·종료·잔여물 시험, 그 바이트에 대한 새 분리 승인, 새 배포 명세, 서버에서 검증하는 서명 변환 이력이 차례로 필요합니다. 현재의 일반 JSON 준비 기록만으로 서버 승인이나 패킹 기록을 우회하지 않습니다.

고객별 A 발급 때 EXE 뒤에 설정을 붙이는 형식에서는 서명 뒤 파일이 다시 달라집니다. 고정된 서명 A와 별도의 인증된 발급 자료로 나누거나 최종 고객별 A를 안전한 서명 서비스에서 서명하는 경로를 먼저 완성해야 합니다. 이 연결이 없으면 자동 게시를 완료했다고 보고할 수 없습니다.

이번 환경은 Linux이며 Windows 실행기·Delphi·서명 인증서가 연결되어 있지 않습니다. 제공한 바이트 비교 회귀 시험은 실제 Windows 서명·실행 시험을 대신하지 않습니다. 유료 Windows 자원이나 라이선스는 자동 생성하지 않았습니다.

## V2 최종 실행 시험의 서버 전용 입력

`Invoke-FinalWindowsTests.ps1`의 V2 입력에는 기존 A/B/O·패킹 기록·정책 외에 `-ServerPoliciesFile`이 필요합니다. 이 파일은 격리 시험 서버용 V2 정책 레코드 3개이며, 실제 파일 슬롯의 역할·정책 ID·해시·함수 개수와 정확히 같아야 합니다. 고객 PC에 배포하거나 웹 다운로드에 포함하는 파일이 아닙니다. 공개 해시만으로 이 서버 프로그램을 복원하거나 임의로 대체하지 않습니다.

서버 정책은 래퍼가 만든 전용 작업 폴더에만 복사합니다. V2 준비 도구를 직접 호출해도 부모 폴더의 소유 표식과 실제 권한을 검사합니다. Windows에서는 상속이 차단되고 현재 사용자·SYSTEM만 허용된 DACL을, POSIX에서는 현재 사용자 소유와 0700 권한을 요구합니다. 결과 JSON에는 프로그램 내용이나 개인키를 넣지 않습니다. 이식 가능한 시험용 임시 서명은 실제 게시 승인과 분리됩니다.

격리된 시험 서버는 자신이 방금 발급한 A 하나의 정확한 ID·해시와 이미 완료된 이중 키 소유 증명을 확인한 뒤 시험용 등록 승인을 한 번 처리합니다. 운영 서버에 자동 승인 옵션을 추가하지 않습니다. 공개 결과는 `fixtureEnrollmentApprovalUsed`로 이 시험 설정을 표시하며 사용자 신원·TPM 증명·운영 승인으로 취급하지 않습니다.

B가 자동 인증 뒤 매우 빨리 O로 전환하더라도 제어기가 실제 B 프로세스를 놓치지 않도록, 시험 서버는 성공한 claim 응답을 최대 3초 동안만 유지합니다. 제어기는 실제 JobObject 소유 프로세스 핸들과 이미지 경로를 확보한 뒤 새 확인 신호를 기록합니다. 이후에도 실제 종료 코드와 파일 정리·세션 종료를 각각 관찰해야 합니다. 이 동기화는 시험 서버에만 있고 `fixtureClaimObservationBarrierUsed`로 결과에 기록됩니다. 이 실행 결과를 자연 실행 속도나 지연 시간의 증명으로 사용하지 않습니다.

아직 Authenticode 뒤의 최종 바이트를 서버 패킹 기록·A 발급과 연결한 자동 게시 경로는 완성되지 않았습니다. 현재 시험 준비 도구는 원래 패킹 기록과 해시가 달라진 파일을 거부합니다. 서명 준비 기록만 넣어 이 검사를 우회하지 않습니다. 실제 Windows 실행·정리·서명 시험 결과 역시 아직 없습니다.

공식 참고: [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool), [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature).
