# 요청 모듈 점검 내역

**공부용 프로젝트이며 실제 사용을 목적으로 하지 않습니다.**

다음 표는 전달받은 Game.zip과 실제 파일 바이트를 비교한 결과입니다. 새 동작에 필요한 수정과 확인된 결함을 반영했습니다. 유지된 파일을 수정했다고 표시하지 않습니다. 이 표의 검토는 소스 연결·계약·원문 보존 기준이며 Delphi 컴파일·Windows 런타임 검증을 의미하지 않습니다.

| 파일 | 결과 | 내용 |
|---|---|---|
| `Game.Api.Guid.pas` | 유지 | 기존 API 해석·형식 구현 유지; O가 사용하는 공통 유닛 연결에 포함. 추가 난독화 변경 없음 |
| `Game.Api.pas` | 수정 | B/O stage별 보고·정책 요청, O 준비·측정 바인딩·임대 검증, 메모리 키 인계 추가 |
| `Game.Api.Pointer.pas` | 유지 | 기존 API 해석·형식 구현 유지; O가 사용하는 공통 유닛 연결에 포함. 추가 난독화 변경 없음 |
| `Game.Api.ROR13.pas` | 유지 | 기존 API 해석·형식 구현 유지; O가 사용하는 공통 유닛 연결에 포함. 추가 난독화 변경 없음 |
| `Game.Api.Types.pas` | 유지 | 기존 API 해석·형식 구현 유지; O가 사용하는 공통 유닛 연결에 포함. 추가 난독화 변경 없음 |
| `Game.Bootstrap.pas` | 수정 | O offer/청크/finish/claim/close 프로토콜 및 제한된 동일 증명 재시도 추가 |
| `Game.CodeIntegrity.pas` | 유지 | 기존 무결성/해시/정책 구현 유지; O도 동일 공통 유닛 참조. 기존 계약·해시 벡터 검사 유지 |
| `Game.Console.pas` | 수정 | 성공한 B worker 종료, O 준비 후 A/B API·전송 해제, O 실행 및 취소 경로 소유권 정리 |
| `Game.Handoff.pas` | 수정 | 다음 프로세스로 인계하기 전 기존 파이프·핸들 정리 경로 추가 |
| `Game.Hashes.pas` | 유지 | 기존 무결성/해시/정책 구현 유지; O도 동일 공통 유닛 참조. 기존 계약·해시 벡터 검사 유지 |
| `Game.Integrity.pas` | 수정 | 해시 처리의 선택적 최대 바이트 한도 추가, 기존 호출 기본값 유지 |
| `Game.Launcher.pas` | 수정 | 검증된 기존 다운로드·파일 식별 로직을 O에 재사용 |
| `Game.Metadata.inc` | 유지 | 기존 무결성/해시/정책 구현 유지; O도 동일 공통 유닛 참조. 기존 계약·해시 벡터 검사 유지 |
| `Game.ModuleInventory.pas` | 수정 | 읽는 도중 DLL 파일이 커지거나 작아지면 제한·거절, 무제한 측정 방지 |
| `Game.ProcessMitigations.pas` | 유지 | 기존 무결성/해시/정책 구현 유지; O도 동일 공통 유닛 참조. 기존 계약·해시 벡터 검사 유지 |
| `Game.Security.pas` | 수정 | 메모리 RSA import 후 B→O 재인계에 필요한 export policy 재적용 |
| `Game.SelfImageHeaders.pas` | 유지 | 기존 무결성/해시/정책 구현 유지; O도 동일 공통 유닛 참조. 기존 계약·해시 벡터 검사 유지 |
| `Game.ServerAuthority.pas` | 수정 | O stage를 기존 서버 관측·정책 검증 흐름에 연결 |
| `Game.Tls.pas` | 유지 | 기존 전송·TLS pin·프로필 구현 유지; 새 O 요청이 기존 통신 경로를 재사용. 서버 측 실제 TLS 검사 통과 |
| `Game.WinApi.pas` | 유지 | 기존 API 해석·형식 구현 유지; O가 사용하는 공통 유닛 연결에 포함. 추가 난독화 변경 없음 |
| `GameConnect.dpr` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `GameConnect.dproj` | 수정 | 전체 공통 유닛·메타데이터 참조 명시, 기존 Win64/리소스/출력 설정 유지 |
| `GameConnect.manifest` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `GameConnect.rc` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `GameConnectRelayConfig.pas` | 유지 | 기존 전송·TLS pin·프로필 구현 유지; 새 O 요청이 기존 통신 경로를 재사용. 서버 측 실제 TLS 검사 통과 |
| `GameConnectRelaySocket.pas` | 유지 | 기존 전송·TLS pin·프로필 구현 유지; 새 O 요청이 기존 통신 경로를 재사용. 서버 측 실제 TLS 검사 통과 |
| `GameConnectResources.res` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `GameConnectServerProfile.pas` | 유지 | 기존 전송·TLS pin·프로필 구현 유지; 새 O 요청이 기존 통신 경로를 재사용. 서버 측 실제 TLS 검사 통과 |
| `GameConnectTransport.pas` | 유지 | 기존 전송·TLS pin·프로필 구현 유지; 새 O 요청이 기존 통신 경로를 재사용. 서버 측 실제 TLS 검사 통과 |
| `GameLauncher.dpr` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `GameLauncher.dproj` | 수정 | 전체 공통 유닛·메타데이터 참조 명시, 기존 Win64/리소스/출력 설정 유지 |
| `GameLauncher.manifest` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `GameLauncher.rc` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `GameLauncherResources.res` | 유지 | 기존 구현·리소스 바이트 유지. 공통 의존성/프로젝트 참조 및 해당 기존 소스 계약에 포함 |
| `PEB_Export_x64.pas` | 유지 | 기존 API 해석·형식 구현 유지; O가 사용하는 공통 유닛 연결에 포함. 추가 난독화 변경 없음 |

| 추가 파일 | 목적 |
|---|---|
| `Game.Overlay.pas` | Win32/GDI 자체 화면, 공부용 표시, 무결성 worker·임대·단축키 종료 |
| `GameOverlay.dpr/.dproj/.manifest/.rc`, `GameOverlayResources.res` | O 프로젝트와 전체 공통 참조·Windows 리소스 |
| `Build_All_Win64.bat` | A/B/O Release 빌드와 네이티브 검사 7개 실행 |
| `tests/DeviceSecurityHandoffProbe.dpr` 및 빌드 배치 | A→B→O 메모리 RSA 재인계와 서명 확인 |
| `tests/Build_HashProbe_Win64.bat` | 기존 해시 probe의 일괄 빌드 연결 |

기존 tests의 Delphi probe 소스는 유지했습니다. 서버 측 신규 테스트는 Overlay 승인·웹·실제 TLS·재시작·저장 실패·응답 복구·소스 소유권을 검사하며, `scripts/regression.js`에 연결되어 있습니다. Windows probe는 이 환경에서 실행하지 않았습니다.
