# GameConnect / GameWeb — Railway HTTP 502 호환성 수정

작성: 2026-10-17. 기준: `GameConnect_GameWeb_Security_1-10_Server.zip`.

## 완료 범위

1~10번 누적 소스에 Railway 전용 웹 전송 모드와 포트 검사를 추가했습니다. 실제 Railway 프로젝트의 변수를 변경하거나 배포하지 않았습니다. Railway 플러그인은 설치된 것으로 확인됐지만, 이 대화에서 프로젝트/배포/로그를 읽는 실행 도구는 노출되지 않아 실제 운영 로그를 읽지 못했습니다. 따라서 운영 장애 원인 확정 또는 복구 완료 보고가 아닙니다.

## 1. 확인된 코드 호환성 문제

기존 기본 `proxy` 모드는 `127.0.0.1`에만 HTTP를 바인딩하고 `0.0.0.0`으로 바꾸면 `WEB_ADMIN_HTTP_LOOPBACK_REQUIRED`를 발생시킵니다. 이 방식은 같은 네트워크 네임스페이스의 HTTPS 프록시에 맞춘 것입니다. Railway 외부 HTTP edge가 직접 연결해야 하는 배포에는 그대로 적용할 수 없습니다.

또한 종전 `PORT`는 `CONNECT_TCP_PORT`가 없을 때 네이티브 TCP 포트의 대체값이었습니다. Railway HTTP 포트와 혼동하면 HTTP가 TLS 전용 포트에 연결되거나 포트 충돌이 날 수 있습니다.

Railway 공식 설명에서 `Application failed to respond`는 edge가 애플리케이션과 통신하지 못한 502를 뜻합니다. 바인딩/포트/대상 포트 불일치가 흔한 원인이지만, 앱 시작 실패나 부하도 원인이 될 수 있습니다. 제공된 오류 화면만으로 어느 하나를 단정하지 않습니다. [R1]

## 2. 수정 내용

| 파일 | 변경 |
|---|---|
| `web/webTransport.js` | 기존 loopback proxy/direct TLS 유지. 명시적 `railway` 모드에서만 `0.0.0.0` HTTP 허용. HTTPS/Secure 해제는 계속 거절. |
| `web/railwayIngress.js` | 운영자 명시 동의, Railway 컨텍스트, 포트 충돌, 고정 RP/origin 검사. 단일 전달 헤더와 클라이언트 IP 형식 검사. |
| `config/config.js` | Railway 모드의 `PORT`는 HTTP 용도로 사용. 네이티브 TLS는 별도의 `CONNECT_TCP_PORT`/기존 TCP target으로 유지. |
| `web/webAuth.js` | Railway 모드의 모든 관리자 로그인/세션 검사에 동일 ingress 정책 적용. |
| `services/passkeyContext.js` | 검증된 요청에서 원래 공개 도메인을 고정 RP/origin과 비교. 클라이언트 Host로 신뢰 도메인을 생성하지 않음. |
| `server.js` | 잘못된 웹 전송 설정을 저장소 잠금·키 생성·리스너보다 먼저 진단. |
| `web/webServer.js` | 웹 바인딩 실패를 오류 코드와 함께 기록하고 실패로 종료. 정상 바인딩 모드/주소/포트 로그. 기존 readiness 기준 유지. |
| `tools/check-admin-security.js` | 읽기 전용 Railway 포트/RP 사전 검사. 네트워크 격리를 검증했다고 표시하지 않음. |
| `scripts/test-railway-web-security.js` | 실제 HTTP/합성 edge/격리 저장소 테스트. |
| `package.json` | `npm run test:railway` 추가. 의존성 변경 없음. |

Win64 소스/바이너리 파일은 기준 1~10번과 동일합니다. 이 수정 때문에 추가 Windows 빌드가 필요한 것은 아닙니다. 아직 1~10번 소스로 A/B/O를 빌드하지 않았다면 기존 빌드·시험 계획은 그대로 남아 있습니다.

## 3. 중요한 신뢰 경계 — 설정 이름이 방화벽은 아닙니다

Railway는 외부 TLS를 edge에서 종단하고 내부 네트워크를 통해 요청을 앱으로 보냅니다. 문서화된 `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`, `X-Railway-Request-Id`를 해당 배포 경계 안에서 사용합니다. [R2, R3]

이 헤더나 `RAILWAY_*` 환경 변수는 암호학적 출처 증명이 아닙니다. 앱에 직접 접근 가능한 다른 내부 서비스가 같은 헤더를 만들면 코드만으로 edge와 구별할 수 없습니다. `WEB_ADMIN_RAILWAY_EDGE_ONLY=1`은 이 배포 전제를 운영자가 확인했다는 표시이며, Railway 설정/방화벽을 자동 변경하지 않습니다. [R6, R7]

사용 조건:

- 관리자 HTTP 리스너에는 Railway의 공개 HTTPS edge만 외부 진입점으로 사용합니다.
- 이 웹 포트를 Railway TCP Proxy 또는 다른 raw TCP 경로로 공개하지 않습니다. 기존 네이티브 TLS용 TCP Proxy는 별도 포트에서 유지할 수 있습니다.
- 같은 프로젝트/환경의 내부 접근 가능한 서비스는 신뢰·격리되어 있어야 합니다. 불신 서비스가 있는 환경이면 별도 격리 또는 인증된 내부 프록시 설계를 먼저 준비해야 합니다.

기존처럼 `0.0.0.0/0`이나 `::/0`을 프록시 신뢰 목록에 추가하지 않습니다. 임의 프록시 CIDR을 추정하지 않습니다. 외부 브라우저 HTTPS와 `Secure` 쿠키는 유지하지만, edge부터 앱까지 앱 자체 TLS를 수행하는 `direct` 모드와 같은 보장은 아닙니다.

## 4. 적용 순서

### A. 소스 교체

이번 누적 전체 ZIP을 새 디렉터리에 풉니다. 운영 DATA_DIR/볼륨/기기 등록/인증서/서명키/관리자 비밀값은 덮어쓰거나 초기화하지 마십시오. 기존 GitHub 연동 또는 업로드 배포 방식을 유지하여 **GameWeb 서버 변경분**을 반영합니다. ZIP 자체는 배포 완료를 뜻하지 않습니다.

기존 저장소 레이아웃에서 GameWeb가 하위 폴더라면 Railway의 현재 Root Directory가 올바른 GameWeb 폴더인지 확인합니다. 이 문서를 따라 기존 경로를 무조건 다른 경로로 바꾸지 마십시오.

### B. Railway 서비스 Variables

다음은 **네이티브 TLS 내부 포트가 3000이고 웹 포트 8080이 비어 있는 경우의 예시**입니다. 현재 네이티브 포트가 다르면 그 값을 유지하고, 웹 포트만 겹치지 않게 선택합니다.

```ini
WEB_ADMIN_TRANSPORT=railway
WEB_ADMIN_RAILWAY_EDGE_ONLY=1
WEB_ADMIN_HOST=0.0.0.0
WEB_ADMIN_REQUIRE_HTTPS=1
WEB_ADMIN_SECURE_COOKIE=1
PORT=8080
WEB_ADMIN_PORT=8080
CONNECT_TCP_PORT=3000
```

`WEB_ADMIN_TRUSTED_PROXIES`가 기존 `127.0.0.1/32,::1/128` 값으로 남아 있으면 **삭제하거나 빈 값**으로 둡니다. 이 모드에서는 그 CIDR 설정과 혼합하지 않습니다.

다음은 실제로 사용하는 **기존 관리자 도메인**을 넣습니다. 내부 도메인, URL 경로, 네이티브 TCP 프록시 주소가 아닙니다.

```ini
WEBAUTHN_RP_ID=admin.example.com
WEBAUTHN_ORIGIN=https://admin.example.com
```

기존 패스키를 등록한 도메인을 바꾸지 마십시오. 새 도메인으로 바꾸면 기존 패스키의 범위가 일치하지 않을 수 있습니다. 여러 도메인을 등록했더라도 이 구현은 하나의 고정 관리자 origin만 허용합니다.

`RAILWAY_PROJECT_ID`, `RAILWAY_ENVIRONMENT_ID`, `RAILWAY_SERVICE_ID`는 Railway가 주입합니다. 수동으로 가짜 값을 만들지 않습니다. `RAILWAY_TCP_APPLICATION_PORT`는 네이티브 TCP의 **내부 target**이며 `RAILWAY_TCP_PROXY_PORT`는 외부 포트입니다. 서로 혼동하지 마십시오. [R4]

Railway에서 변수 수정은 staged changes를 배포해야 적용됩니다. 소스와 변수 변경을 함께 검토해 배포합니다. 이 문서의 예시 파일을 로컬에서 편집하는 것만으로 Railway 환경이 변경되지는 않습니다. [R5]

### C. 공개 도메인과 상태 검사

HTTP 공개 도메인의 target port를 **PORT 및 WEB_ADMIN_PORT와 같은 값**으로 지정합니다. 위 예시는 8080입니다. 네이티브 TCP Proxy target을 이 웹 포트로 바꾸지 않습니다. 네이티브 TCP는 기존 CONNECT_TCP_PORT(예: 3000)로 유지합니다. [R1, R4]

Railway Healthcheck Path는 `/readyz`를 사용합니다. 기존 경로는 native listener와 UI 묶음이 준비됐을 때만 200을 반환합니다. 단순 성공 고정 응답으로 바꾸지 않았습니다. 관리자가 서비스 기능을 잠갔다는 이유만으로 배포 자체를 막는 `/health` 대신 readiness 용도를 분리합니다. [R8]

건강 검사 요청은 관리자 로그인이나 인증 성공을 의미하지 않습니다. `healthcheck.railway.app` Host가 관리자 UI의 HTTPS 검사를 우회하지 않습니다.

### D. 사전 점검과 확인

GameWeb에서 **해당 환경 변수를 적용한 상태**로 실행합니다:

```text
npm run check:admin-security
npm run test:railway
python scripts/verify-source.py
```

지원 런타임과 실제 의존성 설치가 필요합니다. SQLite가 없다고 잠금·복구·감사 검사를 비활성화하거나 STORAGE_ENGINE을 임의로 변경하여 우회하지 마십시오.

정상 바인딩 로그 예시(운영 관찰 결과가 아닌 예시):

```text
Web Admin transport: railway bind: 0.0.0.0 port: 8080
Railway HTTP ready path: /readyz; raw TCP exposure of this HTTP port is forbidden.
```

HTTPS 관리자 도메인의 `/readyz`가 200인지, 관리자 화면이 열리는지, 로그인이 정상인지, Secure/HttpOnly/SameSite 쿠키와 실제 패스키 인증이 작동하는지 확인합니다. 지원 물리 패스키·브라우저는 이번 로컬 테스트에서 실행하지 않았습니다.

## 5. 로그별 조치

| 오류/관찰 | 확인 |
|---|---|
| `WEB_ADMIN_HTTP_LOOPBACK_REQUIRED` | 옛 proxy 모드에서 wildcard를 지정한 상태. 새 코드와 `railway` 모드를 같이 반영했는지 확인. |
| `WEB_ADMIN_TRANSPORT_INVALID` | 옛 코드에 `railway` 값만 넣었거나 오타. 소스 교체 확인. |
| `WEB_ADMIN_RAILWAY_CONTEXT_REQUIRED` | 실제 Railway 서비스에 자동 컨텍스트가 전달되는지 확인. 더미 값으로 통과시키지 않음. |
| `WEB_ADMIN_RAILWAY_EDGE_ONLY_REQUIRED` | 내부/외부 진입 경계를 먼저 검토하고 명시 설정. 단순 오류 무시 스위치가 아님. |
| `WEB_ADMIN_RAILWAY_CLEAR_TRUSTED_PROXIES` | 옛 프록시 CIDR 설정 삭제/비움. |
| `WEB_ADMIN_RAILWAY_PORT_MISMATCH` | PORT와 WEB_ADMIN_PORT를 일치시킴. 공개 도메인 target도 일치 필요. |
| `WEB_ADMIN_TCP_PORT_CONFLICT` | HTTP와 네이티브 TLS를 서로 다른 내부 포트로 지정. |
| `WEB_ADMIN_RAILWAY_TCP_EXPOSURE_FORBIDDEN` | raw TCP Proxy가 웹 포트를 직접 노출. 네이티브 전용 target 유지. |
| `PASSKEY_CONFIG_REQUIRED` / `PASSKEY_ORIGIN_CONFIG_INVALID` | 실제 HTTPS 관리자 도메인과 기존 패스키 RP 설정 확인. |
| `ADMIN_HTTPS_REQUIRED` HTTP 403 | 앱에는 도달함. 공개 도메인/고정 origin/전달 헤더/진입 경계를 확인. HTTPS 검사를 끄지 않음. |
| `DESKTOP_WRITER_LOCK_UNAVAILABLE` | SQLite 의존성·저장소 경로·권한/마운트 문제를 별도로 확인. 기존 잠금 삭제로 무조건 우회하지 않음. |
| `EADDRINUSE` | 웹/TCP/추가 health 포트 또는 다른 프로세스 충돌 확인. |
| 계속 Railway 502 | 해당 배포가 실제 적용됐는지, 시작 로그, target port, 앱 종료·부하를 확인. |

사용자가 제공한 요청의 Railway HTTP 로그 필터:

```text
@requestId:65F7wfA0Qz-hL0m99fVATg
```

해당 기록의 `responseDetails`와 같은 배포의 시작 로그를 연결하여 최종 원인을 확인합니다. 요청 ID만으로 그 기록을 이미 읽었다고 주장하지 않습니다. 비밀번호/토큰/키 전체를 복사하거나 공개하지 마십시오. [R9]

## 6. 검증 범위

최종 상세 결과와 원본 로그는 별도의 `GameConnect_Railway_Fix_Evidence.zip`에 있습니다. 새 Railway 테스트는 33개 사례이며, 실제 wildcard HTTP 소켓·실제 웹 처리기·격리 JSON 저장소를 사용합니다. Railway edge 헤더/환경은 합성입니다. 정상 네이티브-ready 상태 일부는 모의 상태이며, 실제 플랫폼 격리나 TLS edge를 검증한 것이 아닙니다. 내부 호출자가 동일 헤더를 만들면 구분 불가능하다는 경계도 명시적으로 검사합니다.

기존 HTTPS/패스키/TCP/재인증/서버 측정·만료·권한/분리 서명 회귀를 실행합니다. 실제 SQLite가 필요한 배포 통합 시험은 로컬 `better-sqlite3` 미설치로 중단됩니다. 그 결과를 PASS로 바꾸지 않습니다. Node 22.16.0은 프로젝트 선언 지원 범위 밖이므로 지원 런타임에서 재시험해야 합니다.

이번 수정은 Railway 배포 호환성 보완이며, 전체 보안 A+ 판정이나 실제 운영 복구 완료 보고가 아닙니다. 매니페스트는 소스 일치 확인용으로 갱신하고, 운영 승인서/최종 EXE 서명/실제 Windows PASS 증거는 발급하지 않습니다.

## 참고 공식 문서 (2026-10-17 확인)

- [R1] https://docs.railway.com/networking/troubleshooting/application-failed-to-respond
- [R2] https://docs.railway.com/networking/public-networking/specs-and-limits
- [R3] https://docs.railway.com/networking/edge-networking
- [R4] https://docs.railway.com/variables/reference
- [R5] https://docs.railway.com/variables
- [R6] https://docs.railway.com/networking/private-networking
- [R7] Railway 지원 답변 — https://station.railway.com/questions/fastapi-uvicorn-trusted-proxy-configura-9c06fa12 (제품 문서와 함께 참고; 내부 진입자 식별의 보안 보증으로 취급하지 않음)
- [R8] https://docs.railway.com/deployments/healthchecks
- [R9] https://docs.railway.com/observability/logs
