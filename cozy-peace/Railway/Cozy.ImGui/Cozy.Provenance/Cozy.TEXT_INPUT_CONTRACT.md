# 선택적 한글 입력 계약 v1

기존 O 화면은 표시 전용이며 입력 수집을 켜지 않습니다. 편집 기능을 만든
호출자만 `RunOverlayUI`의 마지막 두 인수 `TextInputActive`와 `OnTextInput`을
함께 전달합니다. `TextInputActive`는 현재 사용자에게 보이는 편집 항목이
선택됐을 때만 `True`를 반환해야 합니다. 콜백은 UI 스레드에서 실행되며
네트워크·디스크 작업이나 장시간 대기를 해서는 안 됩니다.

입력은 해당 프로그램 창의 포커스, 유효한 서버 권한, 세션의 사용 가능 상태가
모두 유지되는 동안만 전달됩니다. 다른 프로그램의 키 입력은 읽지 않습니다.
후크, 클립보드, 키 상태 폴링이나 별도 입력 스레드를 추가하지 않았습니다.

## 창 메시지와 조합

- 기본 Windows IME 창이 조합 중인 문자와 후보를 표시합니다.
- `WM_IME_STARTCOMPOSITION`과 `WM_IME_ENDCOMPOSITION`은 시작·종료를 알립니다.
- GCS 플래그가 없는 `WM_IME_COMPOSITION`은 취소로 처리합니다.
- `WM_IME_CHAR`는 `DefWindowProcW`에 전달합니다. 최종 문자는 `WM_CHAR`에서만
  받습니다. `GCS_RESULTSTR`를 별도로 읽어 같은 결과를 중복 입력하지 않습니다.
- 포커스 손실·세션 중단·취소·입력 비활성화는 조합·미완성 UTF-16·미전달 문자를
  지웁니다. 조합 종료나 취소로 미확정 문자열을 확정하지 않습니다.
- Backspace와 Enter는 각각 별도 편집·제출 이벤트이며 제어 문자를 텍스트에
  넣지 않습니다. 조합 중 Escape는 입력 취소를 요청하고, 평상시 Escape의
  기존 O 종료 동작은 유지합니다.

문자 범위는 출력 가능한 ASCII와 한글 음절·자모입니다. 잘못된 UTF-8,
과잉 길이 인코딩, 내장 NUL, 제어 문자와 허용 범위 밖 문자를 거절합니다.
UTF-16의 잘못된 서로게이트를 대체 문자로 바꾸지 않으며, 미완성 상위
서로게이트는 포커스 전환을 넘어 살아남지 않습니다.

## 직접 브리지 API

`Cozy.Overlay.ImGui.pas`의 다음 공개 함수는 직접 편집 UI를 만드는 호출자가
사용할 수 있습니다. 모든 함수는 ImGui 컨텍스트를 소유한 UI 스레드 전용입니다.

| 함수 | 역할 |
| --- | --- |
| `ImGuiTextInputEnable` | 명시적으로 입력 켜기·끄기; 끌 때 할당을 지우고 반환 |
| `ImGuiTextInputEvent` | UTF-8 확정·조합 문자열 및 시작·종료·취소 이벤트 |
| `ImGuiTextInputUtf16` | 이미 전달된 창 문자의 UTF-16 코드 단위 입력 |
| `ImGuiTextInputRead` | 확정 문자열은 한 번 소비; 조합 문자열은 현재 값 조회 |
| `ImGuiTextInputStatus` | 활성화·포커스·조합·미완성 UTF-16 상태 비트 |
| `ImGuiTextInputDisplay` | 현재 캔버스에 검증된 한글 입력 문자열 표시 |

각 조합·확정 버퍼는 UTF-8 512바이트까지입니다. 반환 문자열은 호출자가
소유합니다. 민감한 입력의 복사·저장은 호출자가 최소화해야 하며, 이 기능은
운영 로그나 서버 보고서로 입력을 보내지 않습니다.

표시 함수는 컨텍스트 수명 동안 기존 제품 문구 외 글리프를 최대 128개만
추가합니다. 네 가지 기존 글꼴 크기와 64MiB CPU arena를 유지하며 글리프
추가 전마다 여유 공간을 검사합니다. 없는 글리프·메모리 부족·한도 초과는
실패로 반환합니다. 호출자는 표시 실패를 성공으로 간주해서는 안 됩니다.
기존 표시 전용 `ImGuiText`의 어휘 및 크기 제한은 바뀌지 않습니다.

## 빌드와 검증

새 정적 브리지 객체가 필요합니다. `Cozy.Overlay.dproj`의 기존 준비 단계 또는
`Cozy.ImGui\Cozy.Build\Cozy.Build_ImGui_Win64.bat`을 사용합니다. 기존 객체를 재사용하면 새 C 함수 심볼이
없으므로 링크가 실패합니다. 기존 host ABI는 2, 입력 확장 ABI는 별도로 1을
검사합니다. ELF 감사 도구는 28개 공개 C 심볼을 요구합니다.

- `Cozy.ImGui/Cozy.Tests/Cozy.Rendering/Cozy.test_text_input.cpp`는 실제 운영
  입력 상태 구현의 문자·경계·조합·취소·지우기 동작을 실행 검사합니다.
- `Cozy.test_bridge.cpp`는 실제 ImGui core와 C API 연결, 소유 스레드와
  선택적 입력 할당·해제를 검사합니다. 한국어 폰트 검사에는 명시적
  `COZY_IMGUI_KOREAN_TEST_FONT` TrueType 시험 폰트가 필요합니다.
- `Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dproj`의 `--contract`
  실행은 소유 HWND에 메시지를 보내 중복 확정·조합 취소·포커스 초기화·
  입력 비활성화를 검사합니다. 실제 사람이 입력한 한국어 IME 시험과는 별개입니다.

이 변경을 Linux에서 검사한 결과로 Delphi 빌드, Windows 메시지 처리, 실제
한국어 IME 및 GPU 표시의 성공을 주장하지 않습니다. 이 항목은 Windows에서
추가로 실행해야 합니다.

참고한 기본 메시지 규칙:

- https://learn.microsoft.com/en-us/windows/win32/intl/wm-ime-char
- https://learn.microsoft.com/en-us/windows/win32/intl/wm-ime-composition
- https://learn.microsoft.com/en-us/windows/win32/intl/wm-ime-endcomposition
