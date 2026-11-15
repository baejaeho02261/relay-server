# 코드 페이지 무결성과 CRC32C 경로

## 적용 범위

`Cozy.CodeIntegrity.pas`의 코드 측정은 기존 전체 정규화 코드의 SHA-512·CRC64·XXH3-128·BLAKE3와 `CRC-LAYERS-V1`을 유지합니다. 여기에 검증된 디스크 이미지에서 만든 페이지별 SHA-512 기준을 추가했습니다. 운영 보고서의 기존 필드나 서버 CRC 비교 형식을 바꾸지 않습니다.

각 페이지의 SHA-512 입력은 `COZY-CODE-PAGE-SHA512-V1`와 NUL, little-endian 32비트 RVA, little-endian 32비트 바이트 수, ASLR 재배치를 검증하고 정규화한 실제 코드 바이트입니다. 페이지 CRC를 해시하는 방식과 독립적입니다. 전체 manifest는 `COZY-CODE-PAGES-SHA512-V1`와 NUL, 페이지 크기 4096, 페이지 수, 각 RVA·길이·64바이트 해시를 포함합니다. 최초 디스크 기준을 현재 메모리 결과로 덮어쓰지 않습니다.

`MeasureNowCore`와 `MeasureBundle`의 두 스냅샷에서 이 기준과 비교합니다. 한 페이지만 다르더라도 `OWN_CODE_PAGE_SHA512_CHANGED`로 실패합니다. 전체 코드 해시와 측정 전후 해시·길이의 동등성 검사도 계속 실행됩니다. 측정 실패·취소·시간 초과는 완료 자료로 사용되지 않습니다. 소프트웨어가 자기 상태를 확인하는 기능이며 하드웨어 원격 증명은 아닙니다.

## 버퍼 상한

운영 `MeasureBundle`에서 CRC의 코드 입력은 원본 스냅샷을 직접 읽고, 세 검사 함수 영역은 범위를 따라 작은 청크로 CRC에 공급합니다. 검사 영역 전체 복사본을 만들지 않습니다. 첫 번째 코드 해시·CRC 계산이 끝나면 첫 스냅샷 배열을 지운 뒤 두 번째 스냅샷을 만듭니다. 두 스냅샷은 SHA-512와 길이로 대조합니다.

A/B/O의 코드 상한 64 MiB, 최대 96개 섹션을 적용한 보수적 배열 payload 상한은 **76,760,712바이트**입니다.

- 코드 스트림: 64 MiB + 최대 4096바이트 프레임 여유.
- 유지하는 페이지 기준: 최대 `(16384 + 96 × 2 + 1) × 72 + 64`바이트.
- 동시에 생성하는 보조 자료: 최대 8 MiB export와 65536바이트 여유. 페이지 비교용 임시 manifest도 이보다 작습니다.

이 값은 운영 측정의 코드 스냅샷·역할 입력·페이지 기준 배열 payload 상한입니다. 초기 생성자에서 읽는 디스크 파일, 유지하는 재배치/범위 계획, 해시 객체 내부 상태, JSON·메모리 할당기 오버헤드, 일반 프로세스 메모리, 시험 전용 복사본을 포함한 RSS 상한이라는 의미는 아닙니다. 생성자 입력·정규화 스트림은 각각 기존 파일·코드 상한에 의해 제한됩니다. 명시적 모듈 목록 측정은 기존 더 큰 별도 상한을 유지합니다.

`Cozy.CrcProbe --maximum-pages`는 최대 64 MiB 코드에 대한 페이지 수·manifest 크기를 실제로 계산하고 Windows에서는 해당 시험 프로세스의 peak working set·peak pagefile 수치를 출력합니다. 이 프로세스 수치는 시험 자료 생성 비용도 포함합니다. Linux에서 숫자를 대신 만들어 Windows 결과로 보고하지 않습니다.

## CRC 충돌 시험

시험 자료의 첫 8바이트는 각각 `487059d7b605e9ff`, `48cc3ce6ab789b5c`입니다. 두 입력은 서로 다르지만 CRC32C가 같습니다. 같은 길이의 0 패딩을 붙인 4096바이트 페이지도 CRC가 같습니다. 시험은 기존 페이지 CRC manifest가 같더라도 실제 페이지 SHA-512 manifest와 전체 코드 SHA-512가 다른지 확인합니다. CRC를 인증·서명 또는 파일 동일성의 단독 근거로 승격하지 않습니다.

## 선택형 CRC32C 소프트웨어 가속

`CrcInit(State, ckCrc32C)`는 8바이트 이상 입력에서 portable slicing-by-8 경로를 사용합니다. 하드웨어 명령 가속이 아닙니다. 비정렬 입력은 `Move`로 경계 내 8바이트만 복사하고 바이트 순서를 명시적으로 조합합니다. 8바이트 미만 꼬리는 기존 1바이트 테이블 경로가 처리합니다.

`CrcInit(State, ckCrc32C, cmReference)`로 기준 경로를 선택할 수 있습니다. 빌드 정의 `COZY_CRC32C_REFERENCE_ONLY`는 모든 요청을 기준 경로로 처리합니다. 이 정의는 운영 보안을 우회하지 않으며 결과와 기존 CRC 테이블/파라미터 형식은 동일합니다. CPU 기능이나 외부 DLL을 요구하지 않습니다. CRC32C 상태를 초기화할 때 가속 테이블 2048개 항목이 기존 측정 대상인 기준 테이블에서 정확히 유도되는지 검사합니다. 불일치 시 기준 경로로 처리합니다. 초기화 후 알고리즘 테이블은 수정하지 않습니다. 전체 코드 SHA-512 검증과 별도로 CRC만으로 변조 방지를 보증하지 않습니다.

## 검증 방법과 현재 확인 범위

RAD Studio IDE에서 `cozy-peace\Railway\Cozy.Tests\Cozy.Integrity\Cozy.CrcProbe.dproj`를 Win64/Release로 빌드합니다. 이때 기존 `Cozy.Build-All-Win64.bat`은 필요하지 않습니다.

```bat
"cozy-peace\Railway\Cozy.Tests\Cozy.Integrity\Cozy.CrcProbe.exe"
"cozy-peace\Railway\Cozy.Tests\Cozy.Integrity\Cozy.CrcProbe.exe" --maximum-pages
```

기본 실행은 16개 주소 정렬·19개 길이·분할/빈 입력에서 기준/가속 결과의 일치를 확인하고 CRC 충돌 경계와 페이지 SHA-512 결합을 검사합니다. reference-only 빌드로 같은 시험을 반복할 수 있습니다.

Relay Server에서:

```text
node --test tests/cryptography/peace.test-code-page-sha512.js
node tests/cryptography/peace.test-crc-layers.js
```

`CRC_PROBE` 환경 변수에 실제 빌드한 probe 경로를 지정하면 `--pages-sha512` 출력과 서버의 독립 SHA-512 결과도 비교합니다. 경로를 지정하지 않은 시험은 실제 Native 비교를 SKIP으로 표시합니다. 소스 계약 시험과 JavaScript 시험 통과는 실제 Delphi 컴파일·Windows 실행을 대신하지 않습니다. 이 변경을 작성한 환경에서 실제 Windows 실행과 peak working set 관측은 **NOT_RUN**입니다.
