# O 실행의 선택형 제한 권한 프로필

`Cozy.Handoff.pas`의 인계 경합 검사와 선택형 O 제한 토큰 실행 경로를 구현했습니다.

## 적용

기존 `TGameApi` 인스턴스에서 다음과 같이 선택합니다.

```pascal
Api.StartOverlay;       // 기본 호환성 경로
Api.StartOverlay(True); // 선택형 제한 권한 프로필
```

두 호출을 연달아 실행하는 예제가 아닙니다. 실제 B 프로그램의 기존 O 시작 호출 한 곳에서 하나를 선택합니다. 제한 프로필은 기본으로 꺼져 있습니다. 최종 O와 사용하는 GPU·Windows 버전·실제 기기 키 방식·TLS 접속·서버 인증·화면 표시·부모 인계·종료를 해당 환경에서 시험한 뒤에만 `True`를 선택하세요. 이미 선택한 실행 프로필을 같은 인스턴스에서 바꿀 수 없습니다.

`True`는 `LaunchOverlay` → `LaunchWithHandoff(..., hlpOverlayRestricted)` → 제한 토큰 생성 경로로 전달됩니다. A→B에서는 해당 프로필을 거부합니다. 환경 변수나 파일에 비밀 키를 추가할 필요가 없습니다.

## 적용되는 경계

- 현재 대화형 사용자의 원래 토큰만 사용합니다. 서비스 계정과 세션 0은 거부합니다.
- `CreateRestrictedToken`의 최대 권한 제거와 LUA 옵션을 사용하고, 관리자·운영자 그룹을 deny-only로 만듭니다. 디렉터리 통과 권한 외의 토큰 권한이 남아 있으면 거부합니다.
- 무결성 수준을 medium으로 제한하고 비상승 상태를 확인합니다.
- 자식은 일시 정지 상태로 생성합니다. 실제 자식 토큰을 확인한 다음 시작하고, 공개 hello 이후 및 완료 승인 직전에도 다시 확인합니다.
- 기존 제한 핸들 목록, 개인 환경 블록, 암호화된 일회용 인계, 서버 인증, 준비 완료와 부모 생존 검사는 유지합니다.
- 준비 이벤트와 자식 종료·취소가 함께 관측되면 성공으로 처리하지 않습니다. 처음 정한 기한이 지난 준비도 거부합니다.
- 요청한 제한 토큰 생성·무결성 조정·실행·검증이 실패하면 일반 토큰으로 재시도하지 않습니다. `CreateProcessAsUserW`가 할당량 권한 등으로 실패하는 Windows 구성도 이 규칙에 포함됩니다. 이 호출이 만든 정확한 자식 핸들만 중지·합류·해제합니다.

이 프로필은 **권한 감소**입니다. AppContainer, 파일·레지스트리·네트워크 허용 목록 또는 완전한 샌드박스가 아닙니다. 같은 사용자의 일반 ACL 접근 권한과 O의 기존 대화형 데스크톱은 유지합니다. 새 상주 프로세스나 브로커를 만들지 않습니다.

## 수동 Windows 확인

RAD Studio IDE에서 다음 프로젝트를 열어 Win64 Release로 빌드합니다.

`cozy-peace\Railway\Cozy.Tests\Cozy.Handoff\Cozy.HandoffProcessProbe.dproj`

이 프로젝트는 `GAME_HANDOFF_CONTRACT_TESTS`를 자체 설정합니다. 기존 실패한 전체 BAT 빌드를 다시 실행할 필요가 없습니다. 빌드된 `Cozy.HandoffProcessProbe.exe`는 이 테스트 프로젝트 폴더에서 직접 실행합니다.

시험에는 총 9개 묶음이 있습니다. 실제 생성한 부모·자식의 종료, 부분 프레임, 준비·취소·종료 경합, 미승인 컨텍스트의 정리 거부, 파일 고정 중 교체 차단, 같은 바이트라도 다른 파일 ID인 대체 파일의 삭제 거부, 제한 자식 토큰·개인 파이프·이벤트·CNG 서명·관리자 전용 쓰기 거부·종료를 검사합니다. 임시 파일의 ACL은 `finally`에서 복원하고 이 시험이 만든 파일만 정리합니다.

이 개발 환경에서 Windows/Delphi 컴파일과 실행은 **NOT_RUN**입니다. 위 probe의 성공도 실제 최종 A/B/O의 GPU·TPM·TLS·서버·첫 프레임 호환성 시험을 대신하지 않습니다. 실제 제품 시험이 끝나기 전에는 기본 경로를 유지합니다.

## 근거

- https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
- https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
