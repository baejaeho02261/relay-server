# Cozy A/B/O 연결·다운로드 중단 분석 및 수정 — 2026-11-12

## 사건 (운영 로그로 확인)

- Flow: `7A7950E40D8E2CF857323AC9`; A issued ID `F2840651208201EC32AAAB1D`.
- 22:20:32 KST `BOOTSTRAP_BEGIN` 수락, A `FLOW_STARTED`.
- 22:20:46~22:25:23 KST에 `BOOTSTRAP_CHUNK` 처리 기록이 이어짐 (조회된 로그에서 COMMITTED 최소 39개; 전체 청크 개수라는 뜻 아님).
- 22:25:26 KST `BOOTSTRAP_ABORT` 수락, B의 `CLAIM` 및 O 시작 기록 없음.
- A 클라이언트 `DOWNLOAD_DEADLINE` 보고: 약 285초, 이어서 `SHUTDOWN_BEGIN`, `FILE_CLEANUP FAILED`.
- 같은 화면에 보안 감지 23건이 있다는 이유만으로 이 단절이 NHW 차단 때문이라고 단정하지 않음. 최초 중단 지점은 A의 다운로드 단계.

## 원인 및 수정 범위

1. 서버 측 flow TTL: `FLOW_MS=900000` (15분)으로 유지. 서명·기기·무결성·B handoff는 그대로.
2. 클라이언트 내부에 290초(`Cozy.Bootstrap.Post`)와 300초(`Cozy.Launcher.DownloadVerifiedBinary`) 제한이 별도로 있어 클라이언트가 서버보다 조기에 중단할 수 있었음.
3. `Cozy.Bootstrap`에 공통 `BootstrapDownloadBudgetMS=780000` 상수를 두고 A download와 bootstrap POST 재시도 종료 시간을 모두 이 상수에 맞춤. 서버의 900초보다 120초 빠르며, 임의의 리셋/갱신 없이 인수인계 시간을 보존.
4. A의 장시간 다운로드 만료 보고는 `DOWNLOAD_DEADLINE` 이벤트에 한해 `elapsedMs<=900000` 허용. 기존 다른 이벤트 제한 600초, 역할 검증 및 서명/후속 승인 금지 유지.
5. `FILE_CLEANUP FAILED` 발생 시 `RemoveOwnImage` 내부 Win32 파일 핸들/삭제 오류를 수집해 함께 보고함. 오류가 났다고 삭제 성공을 주장하거나 파일 경로를 임의 변경해 제거하지 않음. Windows에서 실행 중인 EXE 삭제는 파일 시스템 및 보안 정책상 실패할 수 있으므로, 물리적 제거의 성공을 보장하지 않음.
6. B/O의 세션/핸드오프 및 NHW 감지 판정은 건드리지 않음. 기존 활성 라이선스·발급키·운영 DB 데이터 초기화 없음.

## 정적 회귀와 한계

- Node 회귀: 신규 780초 예산·서버 900초 상한·A 전용 보고·B/O 위임 제한 테스트.
- Delphi RAD Studio 13 Win64에서 A/B/O 직접 빌드, 제한적인 네트워크 속도·재전송·Windows 파일 삭제·정확한 B CLAIM/O DISPLAY까지 물리적 재현 필요.
- 클라이언트 변경은 **A를 재빌드하고 새 A 발급본을 만들어야** 적용됨. Railway 서버 배포만으로 이미 발급된 A EXE의 290/300초 제한은 고쳐지지 않음.
- 구형 5분 제한 A의 중단 사건은 과거 기록 그대로 보존하며 새 V9 정책으로 소급 수정하지 않음.

## 후속 진단 권고

- 같은 PC의 A 재발급 후 `FLOW_STARTED` → 다운로드 완료 → `HANDOFF_COMPLETED` → `B SESSION_CLAIMED` → `O PREPARED`/`VISIBLE` 전 과정을 검증.
- B 시작 전 중단 시 다운로드 속도, B 아티팩트 크기, 실측 청크/시간, 오류 코드를 함께 기록 (개인 데이터나 로컬 파일 경로·키는 전송하지 않음).
- `FILE_CLEANUP`이 실패하면 Win32 오류 코드로 원인 분류. 단독 실패를 공격 감지로 표시하지 않으며, 실제 파일 제거를 확인하지 않은 채 정리 성공으로 기록하지 않음.
