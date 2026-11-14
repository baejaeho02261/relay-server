# Railway 문자열 관리

문자열 값은 아래 별도 유닛과 헤더에서 직접 수정합니다. 기존 소스는 상수 이름을 참조합니다. JSON 목록은 위치·검증 정보를 기록하며, 유닛 값을 덮어쓰는 원본이 아닙니다.

| 대상 | 편집 위치 | 내용 |
| --- | --- | --- |
| A/B/O Pascal | `Cozy.Source/Cozy.Configuration/Cozy.Strings.<기능>.pas` | Application, Crypto, Handoff, Identity, Integrity, Lifecycle, Network, Overlay, Platform, Projects, Protection, Security |
| Pascal 시험·프로브 | 같은 폴더의 `Cozy.Strings.Tests<기능>.pas` | 시험용 오류·입력·기대값. 제품에서 필요한 경우에만 기존 시험 조건으로 참조 |
| ImGui 브리지 | `Cozy.ImGui/Cozy.Strings/Cozy.Strings.Bridge.h` | 브리지의 메시지·API 이름·고정 데이터 |
| C/C++ 시험 | `Cozy.ImGui/Cozy.Strings/Cozy.Strings.Tests.h` | ABI·플랫폼·오버레이 시험 문자열 |
| ImGui 공급 소스 | `Cozy.ImGui/Cozy.Strings/Cozy.Strings.Vendor.h` | 공급 소스의 문자열. 변경 시 공급 소스 검증·동작 시험 필요 |

각 상수 위 주석에서 최초 원본 파일과 줄을 찾을 수 있습니다. Pascal은 `CozyText_...`, C/C++는 `COZY_TEXT_...` 이름을 검색하면 사용 위치를 찾을 수 있습니다. 식별자를 유지하고 오른쪽 문자열 값을 편집하세요. 같은 문구라도 원본 파일별 의미가 다르면 별도 상수입니다.

## 편집 후 확인

`Railway` 폴더에서 실행합니다. Python 관리 도구이며 A/B/O 실행이나 Windows 빌드 환경 설정을 요구하지 않습니다.

```text
python Cozy.Build/Cozy.Extract-StringUnits.py refresh
python Cozy.Build/Cozy.Extract-StringUnits.py check
python Cozy.Build/Cozy.Extract-NativeStrings.py refresh --root .
python Cozy.Build/Cozy.Extract-NativeStrings.py check --root .
python Cozy.Build/Cozy.Manage-Strings.py refresh
python Cozy.Build/Cozy.Manage-Strings.py check
```

수정한 언어의 `refresh`와 `check`를 실행한 뒤 마지막 검색 목록을 갱신하면 됩니다. `refresh`는 편집한 값을 유지하고 검증 목록을 갱신합니다. `check`는 분산된 새 문자열, 잘못된 참조, 상수 파일의 숨겨진 실행 코드 등을 거부합니다. 최초 마이그레이션용 `extract`를 다시 실행할 필요는 없습니다. `verify-migration`은 최초 변경의 원본 복원을 확인하는 명령이므로, 의도적으로 값을 바꾼 뒤에는 원본과 다르다고 표시할 수 있습니다.

일반 문구와 달리 JSON 필드·프로토콜 오류 코드·Windows API 이름·서명 도메인·해시 시험값은 계약입니다. 이 값의 편집은 서버나 대응 구현, 생성 파일 및 시험을 함께 검토해야 합니다. 이 도구는 문자열 편집만으로 호환성을 보장하지 않습니다. 실제 API 생성기와 글꼴 검사는 상수 유닛의 현재 값을 읽으며, 별도 테스트 해석 때문에 잘못된 제품 값을 정상으로 처리하지 않습니다.

Pascal 새 상수는 해당 기능 유닛에 일반 `const`로 추가하고 사용 소스의 `uses`를 유지하세요. 새 기능 유닛까지 추가할 경우 프로젝트의 명시적 경로와 관리 목록도 함께 등록해야 합니다. 기존 프로젝트의 필요한 유닛 참조는 DPR에 명시되어 있고, DPROJ의 파일 참조도 갱신했습니다. DPROJ 파일 목록이 시험 유닛의 무조건 컴파일을 뜻하지는 않으며, DPR의 조건부 `uses`가 적용됩니다.

## 그대로 남긴 문법과 다른 언어

Pascal은 151개 소스의 6,372개 문자열 식을 26개 유닛의 4,694개 상수로 옮겼습니다. C/C++는 28개 파일을 조사해 20개 소스의 2,293개 문자열 식을 3개 헤더의 1,923개 상수로 옮겼습니다.

Pascal 예외 3,353개는 생성기 소유 계약 1,586개, 단일 문자·범위·구분자 685개, DPR 파일 경로 391개, 빈 문자열 372개, 문자 코드 251개, 링커 선언 61개, GUID 6개, 고정 문자 배열 초기값 1개입니다. C/C++ 예외 271개는 include·pragma·전처리 조건 202개, 언어 연결 선언 68개, 전처리 include 설정 1개입니다. 정확한 파일·위치·이유는 다음 목록에 있습니다.

- `Cozy.Source/Cozy.Configuration/Cozy.StringUnits.map.json`
- `Cozy.ImGui/Cozy.Strings/Cozy.NativeStrings.map.json`

BAT·PowerShell·Python·JavaScript 빌드 도구, 리소스, 프로젝트 XML, 생성 계약은 각 언어의 문법과 생성 흐름을 유지합니다. 검색 목록은 이 파일도 위치별로 보여줍니다. Delphi 유닛으로 불러올 수 없는 파일까지 문자열 유닛으로 옮겼다고 표시하지 않습니다.

이 변경은 소스 정리입니다. 실행 파일의 문자열 암호화나 비밀정보 은닉 기능이 아니며, 비밀키를 상수 유닛에 넣으면 안 됩니다. 기존 Linux 도구로 상수 값·C/C++ 동작·소스 계약을 검증했으며, 실제 Windows Delphi 빌드와 A/B/O 실행은 별도 확인 항목입니다.
