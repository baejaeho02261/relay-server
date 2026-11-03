# Cozy · 제품별 라이선스와 B/O UI 적용 안내

이번 소스는 최신 카드 디자인·등장 효과·부드러운 이동을 유지하면서 B의 라이선스 입력 화면과 O의 제품 선택·START 동작을 갱신합니다. 아래 경로는 전체 소스의 `cozy-peace` 폴더를 기준으로 합니다.

## 화면과 라이선스

- B는 콘솔 대신 ImGui 라이선스 입력 창을 사용합니다. 키 입력·인증·O 인계는 기존 서버 절차를 따릅니다.
- O는 `Cleanner`, `Mobile`, `Spoofer` 세 탭에 각각 6개, 총 18개 카드를 표시합니다. 탭은 로고와 같은 높이에 배치하고, 카드 정보의 흐림 영역은 카드 전체를 덮습니다. 중앙 카드만 정보 화면을 열며, 다른 카드를 누르면 먼저 중앙으로 이동합니다.
- 새 START는 굵은 글자의 버튼입니다. 서버에서 해당 제품의 현재 권한을 확인하면 UI 전체를 흐리게 하고 중앙에 5초 카운터를 표시합니다. 요청·카운트 중 카드·탭·드래그·버튼 입력을 잠그고, 완료 후 원래 화면으로 돌아옵니다. 이전 토스트와 START 자동 종료는 사용하지 않습니다.
- 이 동작은 **서버가 승인한 시각적 카운트다운**입니다. 게임 실행, 청소, 식별자 변경, 안티치트 우회나 실제 Spoofer 작업을 수행하지 않습니다. 창 닫기·실제 권한 만료·철회 시의 기존 종료·정리는 유지합니다.

| 탭 | 카드 6개 |
| --- | --- |
| Cleanner | PUBG: BATTLEGROUNDS, TalesRunner, Lost Saga, Apex Legends, Overwatch, Counter-Strike 2 |
| Mobile | Roblox, Brawl Stars, PUBG MOBILE, Genshin Impact, Pokémon GO, Clash Royale |
| Spoofer | BattlEye, XIGNCODE3, Easy Anti-Cheat, Riot Vanguard, RICOCHET, Anti-Cheat Expert |

웹에서 발급·재발급할 때 **제품 하나**를 선택합니다. 예를 들어 `cleaner.pubg` 라이선스는 PC PUBG 카드에만 적용되며 `mobile.pubg-mobile`이나 다른 제품에는 적용되지 않습니다. 탭 전체·모든 제품을 허용하는 옵션은 없습니다. 웹의 제품 목록은 서버 카탈로그를 사용하므로 ID를 직접 수정할 필요가 없습니다.

기존 제품 미지정 라이선스는 기록을 유지하지만 모든 START가 차단됩니다. 필요한 제품을 선택해 **재발급**하세요. 기존 키에 나중에 제품을 덧붙이거나 사용된 키·세션을 되살리지 않습니다. 서버도 요청의 서명·제품·세션·만료·철회·재전송을 검증하므로 UI만 바꾸어 다른 제품을 활성화할 수 없습니다.

## 라이선스 사용 전 준비

1. 전체 소스를 **새 폴더**에 풉니다. 이전 `.o`, `.dcu`, EXE를 가져오지 않습니다. 서버 등록 데이터·개인키·ACTIVE 상태는 초기화하지 않습니다. 기존 A 공개키 리소스가 운영 ACTIVE 발급키와 일치하는지 확인하되, 이번 UI 적용 때문에 키를 새로 만들거나 철회할 필요는 없습니다.
2. RAD Studio 명령 프롬프트에서 `Relay Server/tools/overlay/Prepare_ImGui.bat`를 먼저 실행해 성공을 확인합니다. 설치된 classic Win64 `bcc64.exe`와 Node.js가 필요합니다. 실패한 오브젝트를 이전 파일로 대체하지 않습니다.
3. RAD Studio 13에서 `Railway/Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dproj`를 엽니다. **Build Configurations → Release**, **Target Platforms → Windows 64-bit(Win64)**를 활성화하고 **Rebuild**합니다. 최신 `.dproj`에는 Release/Win64 선택 메타데이터가 포함돼 있습니다. Base만 보이면 이전 프로젝트를 닫고 새 폴더의 이 `.dproj`를 다시 여세요. 필수 구성 오류를 끄거나 Base/Win32로 진행하지 않습니다.
4. 생성된 `Railway/build/tests/manual-ide/Cozy.OverlayGraphicsProbe.exe`를 실행합니다. 실제 카드 표시가 약 3.5초 이어진 뒤 정상 종료하고 `PASS_REAL_WINDOWS_GRAPHICS`가 나오는지 확인합니다. FAIL이면 단계와 숫자 코드를 확인하고 제품 라이선스를 사용하기 전에 해결합니다.

GraphicsProbe는 서버에 접속하거나 라이선스를 소모하지 않습니다. 진단용 콘솔은 PASS/FAIL 출력용이며 B 제품의 콘솔 UI와 별개입니다. 이 사전 검사는 O 렌더링 경로를 확인하며 B GUI 인증·실제 A/B/O 인계·제품별 권한까지 검증하지 않습니다.

## 재빌드·등록 순서

1. 최신 소스와 ImGui 오브젝트로 다음 세 프로젝트를 각각 **Win64 Release → Rebuild**합니다. 전체 Build-All BAT는 선택 사항입니다.

   | 역할 | 프로젝트 |
   | --- | --- |
   | A | `Railway/Cozy.Projects/Cozy.Launcher/Cozy.Launcher.dproj` |
   | B | `Railway/Cozy.Projects/Cozy.Client/Cozy.Client.dproj` |
   | O | `Railway/Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dproj` |

2. B도 이제 D3D11/DirectComposition·폰트·GPU 모듈을 사용합니다. 이전 콘솔 B에서 만든 모듈 기준·환경 관측·완화 정책 호환성 자료가 새 B의 근거가 되지는 않습니다. 새 최종 B/O와 해당 Windows·GPU 환경의 모듈 스냅샷 및 호환성을 확인하고, 정책이 요구하는 새 증거를 등록합니다. 기존 `Run_Mitigation_Compatibility.bat`의 프로브 결과도 최종 B GUI의 실제 실행 시험을 대신하지 않습니다. 문제를 통과시키려고 무결성·완화 정책을 끄지 않습니다.
3. 서버 정책 연결·패킹·서명 등 파일을 바꾸는 단계를 끝낸 **최종 A/B/O**로 새 승인·검사 규격·배포 명세를 만듭니다. 새 후보 등록 → 조합 검증 → 게시 순서로 진행합니다. 이전 EXE 해시의 승인·명세를 새 파일에 재사용하지 않습니다.
4. API 포인터 수량은 전체 묶음의 `tools/Cozy.Check-ApiSlots.bat`를 해당 Windows에서 실행해 확인합니다. 이 BAT는 최신 소스 계약에서 생성된 값을 사용합니다. 이전에 불렀던 숫자나 과거 문서의 고정 수량을 입력하지 말고 **이번 소스·이번 최종 후보**에 맞는 결과를 등록하세요. 이 검사는 실행 파일 자체의 실행·무결성 증명이 아닙니다.
5. 게시된 새 조합에서 실행용 A를 새로 발급하고 제품을 선택한 새 라이선스로 확인합니다. 기존 1회 사용으로 테스트 PC가 차단돼 있다면 관리자에서 그 PC를 해제한 뒤 새 A·새 라이선스를 사용합니다. 기존 사용 기록과 철회 상태는 유지합니다.

서버 GitHub/Railway 반영만으로 PC의 기존 EXE가 바뀌지 않습니다. 이번 변경에는 서버와 새 B/O를 함께 적용해야 하며, 전체 조합을 같은 소스의 새 A/B/O로 확인하세요. 데이터 초기화나 발급키 교체는 이 적용 절차에 포함되지 않습니다.

## 검증 범위

이 개발 환경에서는 **RAD Studio 13의 실제 dcc64/bcc64 빌드, Windows GPU 실행, 최종 A/B/O 인증·인계 시험을 실행하지 않았습니다(NOT_RUN)**. 소스 검사·서버 테스트·UI 미리보기는 그 실행 결과를 대신하지 않습니다. 이 문서 자체는 GitHub 게시·Railway 배포 완료를 뜻하지 않으며 실제 배포 결과는 별도 최종 보고를 확인하세요.
