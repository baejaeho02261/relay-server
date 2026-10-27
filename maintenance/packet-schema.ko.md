# 공통 요청 패킷 규격 v1

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
