# O DirectComposition 호출 ABI 수정

2026-11-03 20:49 실행은 READY·CLAIMED·IMAGE_BOUND를 통과한 뒤 GPU_BEGIN 다음에 실패했습니다. 이전 다운로드 시간 초과와는 다른 단계입니다. 당시 보고의 UNKNOWN·코드 0만으로 Windows 예외 번호를 복원할 수는 없습니다.

## 확인한 결함과 수정

기존 classic bcc64 오브젝트를 역어셈블한 결과, DirectComposition 사각형의 float 설정이 Windows COM ABI의 animation 포인터 슬롯으로 호출됐습니다. 예를 들어 SetLeft(float)는 슬롯 4여야 하지만 슬롯 3으로 호출됐습니다. Visual의 clip 객체 설정도 슬롯 13 대신 사각형 슬롯 14를 사용했습니다. C++ 오버로드의 가상 함수 배치 차이가 원인입니다.

새 내부 어댑터는 Microsoft의 평탄한 COM ABI에 맞춰 float 설정 12개와 clip 객체 설정 1개를 명시합니다. 호출 규약·슬롯·인수·HRESULT 전달을 검사하며, 기존 잘못된 슬롯 배치를 넣으면 실패하는 회귀 검사를 포함합니다. API 포인터 슬롯이나 외부 C 함수는 추가하지 않습니다.

초기 Resize의 실패는 이제 RESIZE와 원래 HRESULT로 보고됩니다. 생성 중 Windows 예외가 발생하면 CREATE 등 진행 단계와 숫자 예외 코드만 보존합니다. 예외 주소·메시지·파일 경로는 서버로 보내지 않습니다. 서명·권한·세션 제한은 유지됩니다.

최신 카드 UI, 픽셀, 애니메이션, DPI, 둥근 모서리 반경은 변경하지 않았습니다. 이전 무손실 QOI 이미지 압축과 다운로드 진단 수정도 포함됩니다.

## 전체 소스 적용

1. 전체 ZIP을 새 폴더에 풉니다. 기존 빌드의 `.o`·`.dcu`·EXE를 복사하지 않습니다.
2. RAD Studio 13 IDE에서 `Railway/Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dproj`를 Win64 Release로 Rebuild하고 실행합니다. 사전 빌드가 수정한 C++ 브리지를 다시 생성합니다. 카드 표시와 PASS를 확인합니다. 이 검사는 라이선스를 사용하지 않습니다.
3. B `Cozy.Client.dproj`, O `Cozy.Overlay.dproj`를 Win64 Release로 Rebuild합니다. 새 파일로 승인·후보 등록·새 명세·조합 검증 후 게시합니다. 이미 같은 전체 소스의 B를 빌드했더라도 이번 배포 조합의 파일 해시를 확인합니다.
4. 기존 A 빌드 후보는 그대로 사용할 수 있습니다. 실행용 A는 새 조합에서 다시 발급합니다. 1회용 라이선스 사용으로 차단된 테스트 PC는 관리자에서 해제한 뒤 새 라이선스를 사용합니다. 기존 키 철회 상태를 바꾸거나 사용된 세션을 되살리지는 않습니다.

GitHub·Railway 서버 반영은 Windows에 배포된 O 실행 파일을 교체하지 않습니다. 이 수정은 O를 다시 빌드하고 등록해야 적용됩니다.

## 검증 범위

평탄 COM 슬롯과 Windows 인수 전달 규약을 사용하는 회귀 검사, C++ 교차 컴파일, 네이티브 ABI·소스 계약, 서명된 서버 진단 검사를 수행합니다. 실제 RAD Studio 13 컴파일과 Windows GPU 실행은 이 개발 환경에서 실행할 수 없어 미실행입니다. 포함된 GraphicsProbe와 GpuFaultProbe는 Windows에서 확인할 수 있는 검사입니다.
