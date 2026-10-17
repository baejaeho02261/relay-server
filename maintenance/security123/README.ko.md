# GameConnect / GameWeb — 보안 개선 1~3 수정본

작성일: 2026-10-17  
기준 파일: `GameConnect_GameWeb_Server_Cleanup(1).zip`  
범위: 관리자 HTTPS 강제, 패스키 등록·로그인 검증, TCP 접속 제한의 공유 예산 소모 수정. **운영 서버 배포나 방화벽 변경은 수행하지 않았습니다.**

## 1. 적용된 변경

| 항목 | 변경 내용 | 주요 코드 |
|---|---|---|
| 관리자 HTTPS | 로그인·세션 생성·세션 인증에서 HTTPS를 필수로 검사합니다. 관리자 UI/API/SSE는 평문 요청을 본문 처리 전에 403으로 거절합니다. 세션 및 삭제 쿠키에 항상 Secure를 붙이고 HTTPS 응답에 HSTS를 추가합니다. | `web/webAuth.js`, `web/webAuthPolicy.js`, `web/webServer.js` |
| 원본 HTTP 포트 | 기본 proxy 모드는 루프백 주소에만 바인딩합니다. 0.0.0.0, ::, 사설망·공인 주소의 평문 바인딩 및 광범위 프록시 신뢰를 거절합니다. direct 모드는 Node/OpenSSL HTTPS 서버로 동작하며 인증서·키가 없거나 잘못되면 HTTP로 폴백하지 않습니다. | `web/webTransport.js` |
| 패스키 등록 | 원본 `attestationObject`의 CBOR, authData, AT/UP/UV 플래그, 자격 ID, COSE EC2/P-256/ES256 키를 검사합니다. 저장 키는 authData 내부 키로부터 생성합니다. 별도로 보낸 ID/SPKI/authData가 있으면 일치 여부도 검사합니다. 잘못된 곡선점, 중복 키, 잘린 입력, 초과 크기, 불필요한 후행 바이트를 거절합니다. | `services/passkeyAuthData.js`, `services/passkeyAuth.js` |
| 패스키 로그인 | 서버에 명시한 RP ID·HTTPS origin·Host를 사용합니다. Host에서 신뢰 도메인을 자동 생성하지 않습니다. 등록된 RP, 현재 설정, 시작 시점의 허용 자격 목록, 서명, 사용자 확인, 카운터·만료·철회·일회성 challenge를 검사합니다. | `services/passkeyContext.js`, `services/passkeyAuth.js` |
| 관리자 웹 전달 형식 | 브라우저는 표준 API가 반환한 원본 attestationObject를 전달합니다. 공개키 해석과 등록 승인은 서버가 수행합니다. UI 버전 및 파일 매니페스트를 함께 갱신했습니다. | `public/admin-pages-production.js`, `config/config.js`, `web/ui-bundle.json` |
| TCP 입장 제한 | IP별 제한·활성 연결 수·전체 제한·상태 용량을 모두 통과한 뒤에만 IP 및 전체 예산을 동시에 차감합니다. 거절 요청은 다른 사용자 예산을 소비하거나 제한 시간을 연장하지 않습니다. 연결 종료의 중복 해제도 차단합니다. | `services/desktopConnectionAdmission.js`, `services/desktopConnect.js` |

등록은 기존 정책과 같은 **ES256 + attestation none**으로 제한됩니다. 다른 인증기 attestation 형식을 임의로 통과시키지 않습니다. 이는 하드웨어 인증기 진위 증명이나 WebAuthn 전체 옵션 지원을 의미하지 않습니다.

TCP 기본 제한은 종전 값을 유지했습니다: 60초당 전체 1,800, IP당 1,200, 전체 활성 연결 512, IP당 활성 연결 32. 이미 수락된 접속은 실패하더라도 예산을 사용합니다. 분산 공격, 실제 네트워크 용량 초과 또는 허용 예산 자체의 고갈까지 없앴다는 뜻은 아닙니다.

## 2. 저수준 구현과 서버/로컬 경계

기존 Node.js 서버를 유지했습니다. 서버를 C/C++/어셈블리로 재작성한 것은 아닙니다. 추가 고수준 인증 프레임워크나 npm 의존성을 넣지 않고 Buffer 오프셋·길이·플래그·CBOR/COSE 값과 접속 상태를 직접 검사합니다. 암호 연산은 기존 Node/OpenSSL의 검증된 구현에 맡기며, ECC나 TLS 암호 알고리즘을 새로 작성하지 않았습니다.

Win64 파일 **226개 모두 원본과 바이트 단위로 동일**합니다. `package-lock.json`과 외부 의존성 버전도 동일합니다. 관리자 웹의 등록 응답 전달 코드만 필요한 범위로 변경했습니다.

새로운 localStorage, IndexedDB, 로컬 자격 증명 파일을 추가하지 않았습니다. 그러나 기존 프로그램·브라우저 저장 자료를 삭제한 것은 아닙니다. 브라우저의 세션 쿠키, 실행 중 메모리, 인증기/보안키가 보관하는 패스키 개인키는 필요합니다. **패스키 개인키를 서버로 옮기거나 클라이언트의 모든 흔적을 없앴다고 주장하지 않습니다.** 서버에는 검증용 공개키와 기존 인증 상태만 저장합니다.

## 3. 적용 전 필수 사항 — 기존 HTTP 접속은 더 이상 사용할 수 없습니다

운영 코드와 DATA_DIR를 별도로 백업하고 새 소스를 별도 디렉터리에 풀어 확인하십시오. 운영 데이터·인증서·서명키를 소스 ZIP으로 덮어쓰거나 외부에 공유하지 마십시오. 이 수정본은 운영 데이터, 배포 승인키, 라이선스, 기기 등록 정보를 초기화하지 않습니다.

다음 중 하나를 선택하여 **실제 서비스 프로세스의 환경 변수**를 설정해야 합니다. `setup/windows.env.example`을 편집하는 것만으로 Node가 자동으로 읽지는 않습니다. 기존 관리자 비밀값·DATA_DIR·네이티브 TCP 설정은 유지하십시오.

### 방식 A — 같은 서버/네트워크 네임스페이스의 HTTPS 프록시

```ini
WEB_ADMIN_TRANSPORT=proxy
WEB_ADMIN_HOST=127.0.0.1
WEB_ADMIN_PORT=8080
WEB_ADMIN_TRUSTED_PROXIES=127.0.0.1/32,::1/128
WEB_ADMIN_REQUIRE_HTTPS=1
WEB_ADMIN_SECURE_COOKIE=1
WEBAUTHN_RP_ID=admin.example.com
WEBAUTHN_ORIGIN=https://admin.example.com
```

`admin.example.com`은 실제 관리자 도메인으로 교체하십시오. 프록시는 외부 HTTPS를 종단하고 같은 호스트의 `127.0.0.1:8080`으로 전달해야 합니다. 원래 관리자 Host를 보존하고 `X-Forwarded-Proto`를 자신이 확인한 단일 `https` 값으로 **덮어써야** 합니다. 외부 사용자가 제공한 전달 헤더를 그대로 신뢰하면 안 됩니다. `X-Forwarded-For` 역시 실제 출발지로 구성하십시오.

별도 컨테이너의 127.0.0.1은 다른 네임스페이스입니다. Railway 등 관리형 외부 프록시나 분리된 프록시 컨테이너에 이 설정을 그대로 적용하면 연결되지 않을 수 있습니다. 이 버전은 원본 평문 포트의 외부 바인딩을 의도적으로 허용하지 않습니다. 같은 네트워크 네임스페이스의 HTTPS 종단 또는 검토된 TLS 배포 구성이 먼저 필요합니다. 해결하려고 모든 IP를 신뢰 목록에 넣지 마십시오.

루프백 바인딩은 다른 로컬 프로세스를 격리하는 장치가 아닙니다. 같은 OS를 장악한 공격자까지 방어한다고 해석해서는 안 됩니다. OS 방화벽·클라우드 보안 그룹·포트 게시 설정은 실제 운영 환경에서 별도로 확인해야 합니다.

### 방식 B — 서버가 직접 HTTPS 제공

```ini
WEB_ADMIN_TRANSPORT=direct
WEB_ADMIN_HOST=0.0.0.0
WEB_ADMIN_PORT=8443
WEB_ADMIN_TRUSTED_PROXIES=
WEB_ADMIN_REQUIRE_HTTPS=1
WEB_ADMIN_SECURE_COOKIE=1
WEB_ADMIN_TLS_CERT_FILE=C:/GameWeb/certs/fullchain.pem
WEB_ADMIN_TLS_KEY_FILE=C:/GameWeb/certs/privkey.pem
WEBAUTHN_RP_ID=admin.example.com
WEBAUTHN_ORIGIN=https://admin.example.com:8443
```

실제 도메인·포트·인증서 파일 경로를 사용하십시오. direct 모드에서는 프록시 신뢰 설정을 비워야 합니다. 제공한 인증서와 개인키를 Node/OpenSSL이 읽어 HTTPS 리스너를 만들며, 브라우저가 신뢰하는 유효한 서버 인증서와 운영 방화벽 설정이 필요합니다. TLS 1.2 이상을 사용합니다. 이 작업에서 공인 인증서를 발급하거나 운영 방화벽을 변경하지 않았습니다.

### 공통 확인 순서

GameWeb 디렉터리에서, 실제 서비스 환경 변수를 로드한 상태로 실행합니다.

```text
npm run check:admin-security
npm run test:security:123
python scripts/verify-source.py
```

사전 점검은 데이터베이스·방화벽을 변경하거나 포트를 열지 않습니다. 실제 프록시/WAN 접속 확인을 대신하지 않습니다. 핵심 테스트는 임시 디렉터리·임시 키·루프백 임시 포트를 사용합니다. 실제 TLS 시험에는 실행 경로에서 사용할 수 있는 `openssl`이 필요합니다. 환경에 OpenSSL이 없다고 인증서 검증을 끄지 마십시오.

설정과 시험이 확인된 뒤 운영 서비스를 재시작하고 HTTPS 주소로 접속합니다. 기존 세션은 프로세스 재시작으로 소멸하므로 다시 로그인하십시오. 관리자 웹 파일 전체를 함께 교체하고 새로고침하여 새 UI 버전 `console-v4-109-sec123`을 사용하십시오. 이전 UI는 원본 attestationObject를 보내지 않아 새 패스키 등록이 거절됩니다.

기존 패스키의 RP ID와 운영 도메인이 같은지 확인하십시오. RP가 없거나 다르면 그 키를 다른 도메인의 키로 추정하여 허용하지 않습니다. 기존 등록에 대한 과거 원본 attestationObject가 없으므로 이번 패치로 옛 등록을 소급 검증할 수 없습니다. 등록 목록을 검토하고 필요하면 정상 관리자 비밀번호 인증을 유지한 상태에서 새 패스키를 등록하십시오. 기존 키를 이 패치가 자동 폐기하거나 모두 재검증 완료로 표시하지는 않습니다.

`WEB_ADMIN_REQUIRE_HTTPS=0` 또는 `WEB_ADMIN_SECURE_COOKIE=0`이 기존 운영 환경에 남아 있으면 시작 시 오류로 거절됩니다. HTTP로 돌아가지 말고 환경 변수를 1로 고쳐야 합니다.

공개 `/health`, `/healthz`, `/readyz` 및 기존 서명된 공개 배포 경로·별도 내부 HA 경로의 정책은 이번 세 항목의 범위 밖이므로 유지했습니다. 관리자 로그인·세션/API/UI의 평문 허용 예외는 아닙니다. 상태 응답 최소화 등 나머지 개선 항목은 이번에 적용하지 않았습니다.

## 4. 실제 시험 결과

| 핵심 시험 | 통과 수 | 검증 방식 |
|---|---:|---|
| 관리자 HTTPS | 10 | 실제 루프백 HTTP/TLS, 인증서 검증 켜짐, 실제 웹 디스패처·JSON 저장, 합성 패스키 |
| 패스키 검증 보강 | 30 | 정상 ES256 서명, 잘못된 RP/ID/키/CBOR/플래그/서명, 격리된 저장소 |
| TCP 입장 제한 | 12 | 결정적 제한 상태, 실제 연결 핸들러에 합성 소켓 연결 |
| 기존 패스키 수명·재사용·저장 실패 | 9 | 기존 검사를 유지하고 유효한 등록 데이터로 fixture 수정 |
| 기존 관리자 인증·CSRF·만료·권한 | 24 | HTTPS 프록시를 표현한 로컬 HTTP 경유 시험 및 서비스 함수 시험 |
| **합계** | **85** | **모든 경우가 실제 Windows/물리 패스키/운영 침투 시험이라는 뜻은 아님** |

추가로 프로토콜 15개 그룹, 단독 관리자 17개 검사, 엄격 파서 3개 그룹, 생산 경계 31개 그룹, 네트워크 수명주기 5개 그룹 및 UI 파일 묶음 검사가 통과했습니다. 마지막 변경된 JavaScript 파일 31개의 구문 검사도 통과했습니다. 단위/소스 검사를 별도의 실제 운영 성공으로 합산하지 않습니다.

네이티브 TLS·전체 TCP·전체 HTTP·워크스페이스 통합 시험 4개는 `better-sqlite3` 부재 및 그로 인한 `DESKTOP_WRITER_LOCK_UNAVAILABLE`로 중단됐습니다. 잠금을 비활성화하거나 가짜 데이터베이스를 끼워 통과시키지 않았습니다. 원본 로그와 상세 결과는 같은 디렉터리의 `logs/`, `test-results.json`에 있습니다.

시험 런타임은 Node **22.16.0**으로 프로젝트 선언 지원 범위 `^22.22.2 || ^24.15.0 || >=26.0.0` 밖입니다. 이 환경에서 핵심 시험이 통과했더라도 지원 런타임·실제 SQLite·운영 환경에서 재시험이 필요합니다. 컨테이너 DNS에서 공식 배포/패키지 호스트를 조회할 수 없어 런타임 갱신과 의존성 감사를 완료하지 못했습니다.

실제 Delphi 컴파일, 물리 패스키, 브라우저의 WebAuthn 호환성, 운영 서버 부하·침투·방화벽 검증은 완료하지 않았습니다. Windows 소스는 바꾸지 않았습니다. 본 결과는 세 항목 수정본이지 A+ 인증이나 해킹 불가능 보증이 아닙니다.

## 5. 설계 참고 원문

W3C WebAuthn의 등록/인증, 인증기 데이터와 attested credential data 규칙, Node/OpenSSL 공개키·서명·TLS API, OWASP 세션 보호 원칙을 참고했습니다. 이 구현은 전체 WebAuthn 표준의 모든 옵션을 지원하는 라이브러리가 아닙니다.

```text
https://www.w3.org/TR/webauthn-3/
https://nodejs.org/docs/latest-v22.x/api/crypto.html
https://nodejs.org/api/https.html
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
```

소스 및 UI 매니페스트는 변경 파일 누락 확인용으로 재생성했습니다. 암호학적 배포 승인서·외부 감사 결과·Windows 실행 증거를 새로 발급한 것은 아닙니다.
