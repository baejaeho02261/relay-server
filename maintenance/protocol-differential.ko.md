# 실제 Delphi JSON 파서 차등 검사

개발용 합성 입력을 실제 `Cozy.ProtocolJson.pas`와 서버의 `peace.strict-json` 파서에 함께 넣습니다. 명령 봉투 입력은 공통 패킷 규격 검증도 함께 비교합니다. A/B/O 운영 프로그램에 시험 출력·임의 입력 엔진을 넣지 않습니다.

## 1. IDE에서 시험 EXE 빌드

풀 소스의 다음 프로젝트를 RAD Studio에서 열고 **Win64 / Release**로 빌드합니다.

`cozy-peace\Railway\Cozy.Tests\Cozy.Protocol\Cozy.ProtocolJsonDifferentialProbe.dproj`

출력은 같은 프로젝트 폴더의 `Cozy.ProtocolJsonDifferentialProbe.exe`입니다. DCU는 그 폴더 아래 `dcu\Win64\Release`에 들어갑니다. 이 시험에는 `Cozy.Build-All-Win64.bat`이 필요하지 않습니다. RAD Studio 사용권의 명령행 컴파일 제한을 우회하지 않습니다.

## 2. Windows에서 실행

Node.js가 설치된 Windows 명령 프롬프트에서 풀 소스 최상위 폴더로 이동합니다. 실제 EXE 절대 경로와 **아직 없는** 결과 파일 경로를 넣습니다.

```bat
call "cozy-peace\Relay Server\tools\runtime\Run_Native_Json_Differential.bat" "C:\Cozy\cozy-peace\Railway\Cozy.Tests\Cozy.Protocol\Cozy.ProtocolJsonDifferentialProbe.exe" "C:\Cozy\json-differential-result.json"
```

기본 시드 `1129339441`과 256개 변이 입력을 사용합니다. 마지막에 시드와 변이 개수(0~2000)를 지정할 수도 있습니다. EXE는 별도 상주 프로그램 없이 한 번 생성되고, 여러 입력을 처리한 뒤 stdin을 닫고 종료를 기다립니다. 요청당 2초, 전체 기본 60초, 입력당 128 KiB, 출력·오류 출력 상한을 적용합니다. 검사는 서버 연결·라이선스·실제 사용자 데이터를 요구하지 않습니다.

## 3. 결과 읽기

- `PASS`, `execution: REAL_NATIVE`: 지정한 Win64 EXE와 서버 파서가 검사 입력의 수락 여부·JSON 값에 동의했습니다. 실제 EXE SHA-512, 정상 종료 코드 0과 검사 개수가 남습니다. 모든 가능한 입력의 안전성 보장은 아닙니다.
- `FAIL / PARSER_DIFFERENCE`: 원본 바이트와 축소한 재현 바이트를 Base64로 보존합니다. 축소는 같은 수락/거절 방향 또는 값 차이를 유지하며 최대 128회 시도합니다. 실제 원시 바이트를 보존하므로 잘린 UTF-8도 손실되지 않습니다. 비교 결과는 수락 여부와 값 해시로 기록합니다. `shrinkBudgetExhausted`가 참이면 축소 예산을 다 쓴 상태이며, 이 경우 전역 최소 입력을 찾았다는 뜻은 아닙니다.
- `NOT_RUN`: Windows 또는 실제 시험 EXE가 없습니다. 종료 코드 2입니다. Windows 검사 성공으로 처리하지 않습니다.
- 비정상 종료·타임아웃·출력 규격 오류: 검사 자체가 실패합니다(종료 코드 1). 파서의 정상적인 거절로 계산하지 않습니다.
- Node 단위 시험의 `TEST_ADAPTER_PASS`: 하네스 제어 로직만 시험한 결과입니다. 실제 Delphi/Windows 검증을 뜻하지 않습니다.

기본 코퍼스는 정상 한글·이모지·정수 경계·소수와 중복/escaped 중복 키, 예약 키, 잘못된 surrogate, 과대 정수·숫자 문법, 잘린/과잉 UTF-8, 중첩·노드·바이트 상한, 명령·필드·버전 오류를 포함합니다. 핵심 문법 벡터는 두 구현이 같이 잘못 수락하는 경우를 잡기 위해 독립된 기대 수락값도 가집니다.

실패 파일을 같은 EXE로 다시 검사하려면 새 보고서 이름을 사용합니다.

```bat
node "cozy-peace\Relay Server\tools\security\peace.native-json-differential.js" "C:\Cozy\cozy-peace\Railway\Cozy.Tests\Cozy.Protocol\Cozy.ProtocolJsonDifferentialProbe.exe" "C:\Cozy\json-differential-replay.json" 1129339441 0 "C:\Cozy\json-differential-result.json"
```

실제 운영 입력에는 토큰이 포함될 수 있으므로 이 도구에는 제공된 합성 코퍼스와 개발용 재현 입력만 넣으세요. 생성한 보고서는 공개 저장소·배포 파일에 자동 업로드하지 않습니다.
