# 네이티브 릴레이 소켓: 시간 예산과 IPv6

`Cozy.Relay.Socket.pas`는 DNS 조회부터 TCP 연결, TLS 인증서 핀 검사, 쓰기, 줄 수신까지 하나의 절대 마감을 사용합니다. 주소 후보별 연결 시도는 최대 1초이며 전체 마감에서 차감합니다. 후보 수는 8개, DNS 결과 목록 탐색은 64개로 제한합니다. IPv4와 IPv6의 sockaddr를 길이·주소군 확인 후 복사하고 중복을 제거합니다. 한 번 TCP 연결에 성공하면 TLS 실패를 다른 주소 재시도나 핀 완화로 바꾸지 않습니다.

IPv6 운영 연결은 기존 서버 프로필의 DNS 이름에 AAAA 레코드를 설정해 사용합니다. 프로필 자체의 DNS/IPv4 문자열 규격은 유지합니다. 시험 도구는 `::1` 직접 연결도 검사합니다. 인증용 TLS 서버 이름과 현재/전환 핀은 연결 주소군과 무관하게 그대로 유지합니다. 이 소스의 대상은 Windows 10/11 Win64입니다.

## 취소와 소유권

요청 취소 또는 명시적 `Close`가 발생하면 다음 네트워크 단계로 진행하지 않습니다. 대기 중인 요청은 최대 25ms 단위로 취소·전체 마감을 다시 확인합니다. `Close`는 먼저 취소 상태를 표시한 뒤 진행 중인 TLS/소켓 작업의 소유권 반환을 기다려 정리합니다. TLS 객체를 읽기 도중 해제하거나 다른 요청의 소켓 핸들을 닫지 않습니다. 명시적 `Close`는 이 인스턴스의 최종 종료이며 재요청은 새 인스턴스를 만듭니다. `Destroy` 전에는 호출자 작업을 먼저 합류시켜야 합니다.

DNS 공급자가 지연되면 요청 호출자는 마감에 맞춰 반환하지만 OS 공급자 호출을 강제로 종료하지 않습니다. 최대 4개인 소유 작업자가 문자열·결과·Winsock 참조를 보존하며 동기 `GetAddrInfoExW`가 실제 반환한 뒤 해제합니다. 지연 결과는 취소 또는 만료 후 성공으로 채택하지 않습니다. 공급자가 영구 정지하면 그 작업자와 해당 슬롯은 프로세스 종료까지 남을 수 있고 새 조회는 용량 오류로 거절합니다. 따라서 무제한 작업자 생성은 막지만 OS 드라이버가 즉시 종료된다고 보장하지 않습니다.

이 설계는 `GetAddrInfoExCancel`이 완료를 알린 뒤에도 오래된 동기 DNS 공급자가 계속 실행할 수 있다는 Windows 계약을 고려합니다. 취소 알림을 공급자 종료로 오인하여 슬롯을 재사용하지 않습니다.

- [Microsoft GetAddrInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw)
- [Microsoft GetAddrInfoExCancel의 공급자 수명 설명](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexcancel)

## Windows 확인 방법

1. RAD Studio IDE에서 `cozy-peace\Railway\Cozy.Tests\Cozy.Network\Cozy.RelaySocketProbe.dproj`를 엽니다. Win64 / Release를 선택해 빌드합니다. EXE는 프로젝트 폴더에, DCU는 그 안의 `dcu`에 생성됩니다.
2. 생성된 `Cozy.RelaySocketProbe.exe --contracts`를 실행합니다. 실제 소켓 유닛의 주소 후보 복사·중복·상한, 취소와 DNS 완료 경합, 지연 DNS의 소유권 유지, 용량 제한, 닫힌 클라이언트의 단계 진입 거절을 검사합니다. DNS 지연은 전용 시험 빌드에만 들어가는 제어된 공급자 대역으로 재현합니다. 이 정의는 A/B/O 빌드에서 컴파일 오류로 차단됩니다.
3. Relay Server 폴더에서 아래 명령을 실행합니다. OpenSSL이 PATH에 없으면 `--openssl`에 실제 OpenSSL 실행 파일의 절대 경로를 추가합니다. 출력 파일은 새 경로를 사용합니다.

```bat
node tools\network\peace.native-socket-tests.js --probe "C:\실제경로\Cozy.RelaySocketProbe.exe" --output "C:\실제경로\socket-result.json"
```

별도 로컬 TLS 서버로 10개 경로를 검사합니다: IPv4/IPv6와 DNS 이름 연결, 한글 UTF-8 분할 수신, DNS 시작 전 취소, 수신 중 취소와 동시 Close, 전체 마감 초과, 줄 길이 초과, 두 주소군의 핀 불일치 거절. 테스트 자체가 만든 인증서·키·실행 파일 복사본·리스너·소켓은 완료 후 정리하며 시스템 인증서 저장소는 변경하지 않습니다. IPv6가 없는 환경은 IPv6 항목을 NOT_RUN, 전체를 INCOMPLETE로 표시합니다.

현재 이 변경을 작성한 Linux 환경에서는 Delphi 컴파일과 실제 WinSock/SChannel 실행을 하지 않았습니다. 결과는 **NOT_RUN**입니다. `node --test tests/network/peace.test-native-socket-priorities.js`의 실제 루프백 TLS 시험은 Node 시험 장치의 분할 전송·취소 정리 검증이며 Windows 실행 증거를 대신하지 않습니다.
