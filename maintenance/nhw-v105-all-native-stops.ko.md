# Cozy-Peace V10.5 — NHW 확인된 출력 종료 판정 복구

- 기준: V10.4 전체 소스; Delphi Win64 자체 소스, TLS, NHW 204개 센서는 원형 유지
- V7 서버 정책의 V5 `DETECTED` + `standaloneOutput` 종료 판정을 V10.4 서버 정책에 복구
- 분류: NHW 전체 204 typed kinds / 197 standalone output kinds / 194 distinct display names;
  실제 보안 DETECTED 출력은 191개, 수집 가용성 경고 6개, 내부 관측 7개
- `OBSERVED` 및 수집 공백 경고는 단독 공격 확정으로 승격하지 않음
- 서버가 검증한 동일 A/B/O 권한 범위의 정상 자기 동작 및 최초 토큰 baseline 유지
- 서명된 보고서, RSA 서명, 채널/nonce/epoch, 중복 요청 및 진위 검사 유지
- 실제 종료: `StopDecision` -> `boot.Revoke` -> `stopped=true` 응답 -> 클라이언트 Confirm latch -> 기존 소유 리소스 정리
- 서버 폐기는 즉시 처리하지만 다른 오프라인 로컬 프로세스 종료 및 파일 삭제까지
  실시간으로 증명하지는 못하므로 Windows RAD Studio 13 실제 실행 회귀 테스트가 필요
- 테스트: 204개 전수 및 A/B/O 역할 별 정적 계약 검증, 실제 서명/세션 폐기 통합 테스트를
  Railway Dockerfile.railway 실행 단계에 추가. 운영 키·발급 이력·라이선스 리셋 없음
- 이 변경은 라이선스 우회, TLS 완화, 감지 삭제, 대량 데이터 초기화가 아님.
