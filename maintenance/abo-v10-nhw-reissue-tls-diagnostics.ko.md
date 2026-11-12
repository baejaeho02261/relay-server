# Cozy A 재발급 연결 안정화 V10 — 2026-11-12

## 재현 근거 (운영 서버의 과거 감사 로그)

- 같은 공개 B 릴리스에서 첫 A는 부트스트랩 시작 20:53:17 KST, 서버 청크 COMMITTED 69개, FINISH 20:57:06, B CLAIM 20:57:10 정상.
- 동일 기기에서 B 종료 후 새 A를 승인한 두 번째 실행: 21:04:42 시작, 청크 COMMITTED 69개, FINISH 없음, 21:09:50 ABORT.
- 세 번째 재발급: 22:20:32 시작, 청크 COMMITTED 39개, 22:25:26 ABORT. A가 DOWNLOAD_DEADLINE(285424ms) 보고.
- 세 실행의 DEVICE_IDENTITY_PROOF(PERSISTENT_KEY_POSSESSION)는 모두 COMMITTED, 동일 영속 기기 증명 주체. 기기 인증 거부를 이 사건의 확정 원인으로 삼지 않음.
- B_NOT_STARTED는 B의 서버 CLAIM이 없다는 뜻으로, B가 실제로 PC에 잔류했다는 증거가 아님. A FILE_CLEANUP 실패 역시 A 자기 파일 삭제 실패 관측.

## 수정 내용 (상세 경로)

1. `Railway/Cozy.Source/Cozy.Network/Cozy.Transport.pas`: A의 bootstrap `chunk` 요청에 한해서 TLS 1.2/인증서 핀 검증을 거친 연결을 재사용. 요청마다 새로운 UUID, CNG AES 키, nonce 및 RSA-OAEP 감싸기·AES-GCM AAD 검증을 유지. 전송 취소, 새 흐름, 오류, 긴 유휴 기간(7초), 비청크 요청에서는 소켓 재사용 중단. `PostJSON` 소유권은 I/O 잠금으로 직렬화하고 취소/CloseAndWait admission을 유지.
2. `Railway/Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas`: 이미 고정된 TLS 채널에 후속 독립 요청의 10초 이하 타임아웃을 재장착하는 `BeginNextRequest`; 이전 버퍼나 종료 상태에서는 거절.
3. `Relay Server/services/network/peace.desktop-connect.js`: 구형 1요청/연결 프레임 100% 허용. 추가 `keepAlive:1`은 정확한 외부 프레임 키 집합·암호 인증·`bootstrap/chunk`·동일 flow·성공 응답에만 유효. 응답과 다음 요청 사이 단일 순서 처리. 요청별 10초, 최대 256프레임, 전체 TLS 소켓 수명 360초, 기존 raw-socket admission 및 타임아웃 유지. 인증/복호화/부트스트랩 권한·공개키·키 수명·리플레이 검사 모두 종전 서버 경로로 다시 실행.
4. `Railway/Cozy.Source/Cozy.Application/Cozy.Launcher.pas`: 다운로드 루프 중 NHW의 *미확정 관측*에 의해 반복적으로 유발되는 전체 이미지 검사+서버 무결성 보고를 청크마다 수행하지 않고, 완전 다운로드 및 4종 파일 검증을 끝낸 뒤 B 인수인계 직전에 최대 1회 통합. NHW 감시 자체는 동작하며 `RequireLauncherWatch`의 **확정 공격 즉시 중단**과 무조건 수행되는 최종 이미지 검증/서버 보고는 유지. 204개 NHW 판정·194 출력명 유지.
5. `Railway/Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas`와 `Relay Server/services/bootstrap/peace.desktop-bootstrap.js`: 요청·TLS·전송·복호화·파일 쓰기·무결성 검사·NHW 재검증의 누적 시간을 비밀값 없이 A의 인증된 bootstrap 요청에 선택적으로 실어 서버 이벤트 `DESKTOP_BOOTSTRAP_CLIENT_TIMING`으로 기록. 정확한 10개 비음수 정수만 허용하며 기기 ID, 서명, 키, 티켓, 파일 경로는 금지. 진단 정보로 세션 승인·연장·권한을 생성하지 않음. 기존 `FLOW_MS=900000`, A 내부 290000/300000 제한 모두 그대로.
6. `Relay Server/public/scripts/desktop/peace.admin-desktop-server-state.js`: B_NOT_STARTED UI를 `B 시작 미확인`으로 명시. 파일/프로세스 부재 증명은 여전히 하지 않음.
7. `Relay Server/Dockerfile`: 새로운 소스/보안 회귀 게이트를 빌드 때 실행. 통합 TLS 프레임 테스트에 유지 연결을 요청한 비부트스트랩 요청의 거부 검증 추가.

## 기기 재발급 정책

- `keylessChallenge` → 신규 A 개별 명시 승인 → `beginKeyless` 새 흐름 생성은 그대로. 이전 A에 쓰인 토큰 재사용, 기존 기기/키 승인 자동 승계, B 세션 소유권 강제 변경은 없음.
- 현재 서버 테스트 `tests/bootstrap/peace.test-keyless-bootstrap.js`는 'every new A on the same PC and persistent key requires a separate explicit decision' 사례를 포함하므로 릴리스 빌드에서 재실행.
- A와 B의 실제 Windows 프로세스 종료 여부 및 파일 삭제는 서버 로그만으로 확정 불가능. 잔류 여부 조사도 별도 단계.

## 검증 및 한계

- Node 순수 계약·NHW 판정·Delphi 소스 정적 회귀 검증을 시행. Docker/Railway에서는 `better-sqlite3` 네이티브 모듈을 포함한 실제 테스트를 추가로 실행.
- 이 Linux 작업 환경에는 Delphi RAD Studio 13 Win64 컴파일러와 `better-sqlite3` N-API 네이티브 모듈이 없어 Windows 실물 A/B/O 실행 및 일부 TLS-DB 통합 테스트는 현지 재현 불가. 결과를 임의로 성공 처리하지 않음.
- 운영 서버만 업데이트해도 과거 발급 A EXE에는 TLS 재사용이 나타나지 않음. 변경된 전체 소스로 A/B/O를 RAD Studio 13 Win64 Release에서 다시 빌드하고 검증·게시한 후 새 A를 발급해야 함.
- 안정화 완료 판정: 같은 PC에서 새 A 3회 이상(첫 B 실행→정상 종료→새 A→B→O) 모두 FINISH/CLAIM 및 O visible 확인. A 리포트로 TLS 연결 수립 시간과 NHW 검증 시간을 검토. 현재 사용자 PC에서 실측 전이므로 완전 해결을 보장하지 않음.
