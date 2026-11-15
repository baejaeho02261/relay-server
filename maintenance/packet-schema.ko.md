# 공통 요청·응답·관측 규격 v1

`contracts/protocol/peace.packet-schema-v1.json`이 GAME-CONNECT-4의 공개 요청 규격입니다. 7개 operation과 40개 action 조합의 허용·필수 필드, 자료형, 정수 범위, 문자열 길이·바이트 상한, 버전, 동시 존재·상호 배타 필드를 한곳에서 관리합니다. 비밀키나 세션 권한을 담은 파일이 아닙니다.

- `tools/build/peace.generate-packet-schema.js`가 JS 규격 상수와 Delphi `Cozy.ProtocolSchema.inc`를 생성합니다.
- 전체 소스에서 `node tools/build/peace.generate-packet-schema.js --native-root ../Railway`로 재생성합니다.
- 서버 저장소에서는 `node tools/build/peace.generate-packet-schema.js --check`로 생성물 일치를 검사합니다. 전체 소스에서는 여기에 `--native-root ../Railway`를 붙여 네이티브 사본까지 검사합니다.
- `node tests/protocol/peace.test-packet-schema.js`가 모든 명령의 형식, 필수 필드, 추가 필드, 자료형, 상한·하한 및 숫자 표기 호환성을 검사합니다.

네이티브의 `EncodeRequestEnvelope`는 직렬화 전에 `ValidateProtocolRequest`를 호출합니다. 서버의 복호화된 실제 Dispatch 경로도 같은 규격으로 검사한 뒤 원래의 목적 분리·서명·세션·역할·만료·동시성 검증을 계속 수행합니다. 기존 서명 대상 문자열의 바이트를 정규화하거나 다시 쓰지 않습니다.

`ParseProtocolObject`는 일반적인 엄격 JSON 객체 파서로 유지됩니다. 요청 패킷 자체를 읽는 시험·도구에서는 `ParseProtocolRequest`를 사용합니다. `ParseProtocolRequest`는 크기(최대 32,768바이트), UTF-8(호출 전 `DecodeProtocolUTF8`), 중복 필드, Unicode, 깊이·노드 수·숫자·후행 입력을 검사한 뒤 공통 명령 규격을 적용합니다.

안정된 이전 클라이언트를 위해 봉투의 `tlsPinVersion`은 생략할 수 있지만 존재하면 1이어야 합니다. 이전 라이선스 실행 도구가 보낸 `payloadHash`도 execute에서 선택적으로 허용합니다. 해시·서명 검증은 원래의 서버 업무 처리에서 반드시 다시 수행하며, 선택 필드가 권한을 만들지는 않습니다.

TPM 증거, 종료 요약, 완화 환경 및 별도 문자열 안의 서명된 무결성 payload는 각각의 기존 전문 검증기가 계속 검사합니다. 공통 패킷 규격은 그 전문 검증을 대체하지 않습니다. 생성 시험 데이터는 자료형만 맞춘 가짜 키·식별자이므로 실제 실행 권한이나 서명 성공 증거가 아닙니다.

Windows Delphi 실행 결과는 제공된 네이티브 probe를 실제 환경에서 실행한 경우에만 판정할 수 있습니다. Linux의 JS 시험 통과는 Windows 실행·기기 인증 통과를 뜻하지 않습니다.

## O 응답과 서버 관측 자료

동일한 JSON의 `documents`는 O 배포 파일 규격·준비·조각 다운로드·완료·claim·갱신·전달 확정·중단·종료 응답과 서버 관측 challenge·payload·판정 응답, 총 12개 문서를 정의합니다. 필수·선택 필드와 중첩된 CRC 역할별 구조, 자체 측정 묶음, 포인터 그래프 관측 및 완화 진단의 버전을 함께 관리합니다. `anyOf`의 각 분기도 알려진 필드만 허용합니다.

- 실제 `Cozy.Overlay.Client`는 공통 응답 검증 뒤 기존 파일 해시·세션·부모 연결·원래 만료 시각·다운로드 위치 검증을 계속합니다.
- `Cozy.ServerAuthority`는 challenge 수신, payload 직렬화 **이전**, 판정 수신 단계에서 같은 생성 규격을 검사합니다. payload 전체 문자열의 해시·서명과 정확히 같은 제출만 재시도하는 규칙은 유지합니다.
- 서버도 출력 응답 및 엄격 JSON으로 읽은 관측 payload를 같은 규격에 대조합니다. 기존 CRC 비교·포인터 수·관측 완전성·서명·세션·취소·만료 검증이 최종 권한 판정을 계속 담당합니다.
- `node --test tests/protocol/peace.test-document-schema.js`는 필수 필드 누락·추가·잘못된 자료형·범위·버전·잘못된 역할 필드와 중복 필드를 검사합니다.
- `Cozy.JsonEnvelopeProbe`와 차등 검사 도구의 문서 모드는 실제 `ValidateProtocolDocument`를 호출합니다. 시험 EXE를 다시 빌드해야 새 문서 검사 모드를 사용할 수 있습니다. Linux의 하네스 검사는 Windows 실행 증거가 아닙니다.

규격은 권한 토큰이나 서버 키가 아닙니다. 규격만 맞춘 입력은 라이선스·실행 권한을 얻지 못합니다.
