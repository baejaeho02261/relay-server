# 최종 발급 A 읽기·서명 검증

`Cozy.Launcher.ReadConfig`는 이미 열어 둔 동일 파일 핸들로 `Cozy.IssuedA.ReadVerifiedIssuedAConfig`를 먼저 호출합니다. 검증을 통과한 바이트만 `ParsePublicConfig`에 전달하므로 호스트·포트·TLS 핀·서버 공개키를 인증 전에 사용하지 않습니다. 만료 시각은 프로필을 읽은 직후 검사하고, 전체 최종 파일 해시와 실행 코드 무결성도 기존대로 검사합니다.

이 서명은 애플리케이션에서 확인하는 발급 서명입니다. Windows Authenticode 게시자 서명·SmartScreen 평판·실제 Windows 실행 시험을 대신하지 않습니다. 공격자가 프로그램 검증 코드 자체를 수정할 수 있는 환경까지 자체 검사만으로 방어한다고 보장하지 않습니다.

## 형식과 신뢰 기준

최종 파일은 `원본 A 템플릿 | 공개 V3 설정 | 헤더 184바이트 | RSA 서명 256바이트 | 끝 표식 13바이트`입니다. 끝 표식은 `COZYA4SIGNED!`이며 뒤에 한 바이트라도 더 붙으면 거절합니다.

헤더는 16바이트 도메인 `COZY-ISSUED-A-V1`(NUL 없음), 템플릿 크기, 설정 크기, 발급 공개키 ID, 템플릿 전체 SHA-512, 설정 전체 SHA-512를 담습니다. 서버는 이 헤더에 RSA-2048 PKCS#1/SHA-256 서명을 생성합니다. A는 CNG `BCryptVerifySignature`로 서명을 검증하고, 실제 읽은 템플릿·설정의 SHA-512를 비교합니다. 이름만 바꾼 해시 확인을 서명 검증으로 표시하지 않습니다.

A의 신뢰 기준은 `Railway/Cozy.Source/Cozy.Configuration/Cozy.IssuedA.Trust.inc`에 컴파일한 **공개** 확인 키입니다. 파일 안의 서명이나 설정에서 새 신뢰 키를 받아들이지 않습니다. 공개 키는 비밀이 아니며, 개인키는 서버의 발급 키 설정에만 있어야 합니다. 서버 키와 다른 공개키를 넣어 빌드한 A는 발급에 사용할 수 없습니다. 키를 바꾸면 해당 공개키로 A를 다시 빌드하고 승인·배포 자료를 다시 만들어야 합니다.

공개 확인 키 생성·적용 방법과 서버 키 설정은 `issued-a-signing.ko.md`를 함께 확인합니다. 서버 키 설정이 없는 배포에서는 `ISSUED_A_SIGNING_KEY_NOT_CONFIGURED`로 거절합니다. 공개 include가 있다고 서버 키 설정까지 완료된 것은 아닙니다.

## 범위와 자원

- 템플릿은 512바이트 이상이며, 설정·서명 꼬리까지 포함한 **최종 A 전체가 64MiB 이하**여야 합니다. 기존 전체 파일 무결성 검사 상한을 유지합니다.
- 설정은 16바이트 이상, 8KiB 이하입니다. 서명 꼬리는 정확히 453바이트입니다.
- 템플릿 해시는 64KiB 버퍼로 읽으며 전체 파일 복사본을 만들지 않습니다.
- 검증 시간 예산은 30초입니다. 각 읽기 구간과 암호 연산 이후 기한을 확인합니다.
- 성공·실패 모두 호출자가 가진 파일 핸들의 원래 위치를 복원합니다. 파일 핸들 소유권을 가져오거나 닫지 않습니다.
- 임시 설정·해시·키 버퍼를 비우고, 생성한 CNG 키·알고리즘 핸들을 해제합니다.
- 구형 무서명 `COZYA3CONFIG!` 발급 A로 되돌아가는 경로는 없습니다. 구형 등록 A의 읽기 형식은 이 새 A와 호환되지 않으므로 새 빌드가 필요합니다.

## 실제 Windows 검사

RAD Studio IDE에서 다음 프로젝트를 **Win64 / Release**로 빌드합니다.

`cozy-peace\Railway\Cozy.Tests\Cozy.Security\Cozy.IssuedASignatureProbe.dproj`

EXE는 같은 프로젝트 폴더에, DCU는 해당 폴더의 `dcu` 아래에 생성됩니다. 프로젝트 자체에 `GAME_ISSUED_A_TESTS`가 설정되어 있습니다. 이 시험용 임의 공개키 입력은 A/B/O 애플리케이션 빌드에서는 컴파일 오류로 차단됩니다.

전체 소스의 최상위 폴더에서 실행합니다.

```bat
"cozy-peace\Railway\Cozy.Tests\Cozy.Security\Cozy.IssuedASignatureProbe.exe" "cozy-peace\Relay Server\tests\fixtures\bootstrap\issued-a-native-v1.json"
```

시험 파일은 공개키와 합성 서명 자료만 담고 있습니다. 개인키와 운영 발급 데이터는 포함하지 않습니다. 실제 CNG 성공 벡터, 코드·설정·헤더·서명·끝 표식 변조, 453가지 꼬리 잘림, 뒤에 붙인 미서명 바이트, 잘못된 키, 미설정 키, 크기 불일치와 파일 위치 복원을 검사합니다. 실패는 종료 코드 1이며 예외를 무시해 PASS로 바꾸지 않습니다.

이 소스 갱신 환경에서 Node/OpenSSL 교차 벡터·변조 시험과 소스 계약 검사는 수행할 수 있습니다. Delphi 빌드·Windows CNG 실행·실제 발급 A의 A/B/O 전체 실행은 Windows에서 별도로 확인해야 하며, 실행하지 않았다면 **NOT_RUN**입니다.

## API 규격 근거

- Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature
- Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob

`RSAPUBLICBLOB`의 헤더 DWORD는 little-endian이며 지수·모듈러스는 big-endian입니다. Node/OpenSSL에서 생성한 표준 RSA 서명 바이트는 뒤집지 않고 CNG에 전달합니다. 고정 교차 벡터는 역순 서명이 거절되는 것도 확인합니다.
