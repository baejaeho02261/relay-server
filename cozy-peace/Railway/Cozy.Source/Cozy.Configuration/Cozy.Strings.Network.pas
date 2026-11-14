unit Cozy.Strings.Network;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas:451 }
  CozyText_Relay_Socket_DNS_NOT_COMPLETE_51a87470 = 'DNS_NOT_COMPLETE';
  { Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas:381 }
  CozyText_Relay_Socket_DNS_RESOLVER_CAPACITY_0254f2e1 = 'DNS_RESOLVER_CAPACITY';
  { Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas:476 }
  CozyText_Relay_Socket_RELAY_LINE_LIMIT_e5c24e34 = 'RELAY_LINE_LIMIT';
  { Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas:794 }
  CozyText_Relay_Socket_kernel32_dll_542befce = 'kernel32.dll';
  { Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas:798 }
  CozyText_Relay_Socket_ws2_32_dll_7e077a44 = 'ws2_32.dll';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:82 }
  CozyText_Server_Profile_A_exe_a500a22a = '서버 인계 정보가 올바르지 않습니다. 관리자에게 새 A.exe를 받으세요.';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:65 }
  CozyText_Server_Profile_GAME_CONNECT_4_245dd76b = 'GAME-CONNECT-4';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:73 }
  CozyText_Server_Profile_host_0641da68 = 'host';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:74 }
  CozyText_Server_Profile_port_25ea07ca = 'port';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:72 }
  CozyText_Server_Profile_protocol_339a97c5 = 'protocol';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:75 }
  CozyText_Server_Profile_serverKeyId_d1ff78c8 = 'serverKeyId';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:76 }
  CozyText_Server_Profile_serverPublicKey_e4bd8c76 = 'serverPublicKey';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:78 }
  CozyText_Server_Profile_tlsCertificateSha256_0b04d80c = 'tlsCertificateSha256';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:79 }
  CozyText_Server_Profile_tlsPinState_6ab6346f = 'tlsPinState';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:77 }
  CozyText_Server_Profile_tlsServerName_c15a064b = 'tlsServerName';
  { Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas:71 }
  CozyText_Server_Profile_version_fb3048c8 = 'version';
  { Cozy.Source/Cozy.Network/Cozy.Tls.pas:789 }
  CozyText_Tls_Microsoft_Unified_Security_Protocol_Provider_44633ef0 = 'Microsoft Unified Security Protocol Provider';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:6 }
  CozyText_Tls_PinWindow_GAME_TLS_PIN_WINDOW_V1_7e9afbc4 = 'GAME-TLS-PIN-WINDOW-V1';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:150 }
  CozyText_Tls_PinWindow_TLS_PIN_CERTIFICATE_OUTSIDE_WINDOW_9e323ea1 = 'TLS_PIN_CERTIFICATE_OUTSIDE_WINDOW';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:121 }
  CozyText_Tls_PinWindow_TLS_PIN_ENDPOINT_CHANGED_a5177191 = 'TLS_PIN_ENDPOINT_CHANGED';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:183 }
  CozyText_Tls_PinWindow_TLS_PIN_GENERATION_CONFLICT_0b2f3854 = 'TLS_PIN_GENERATION_CONFLICT';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:191 }
  CozyText_Tls_PinWindow_TLS_PIN_HISTORY_CAPACITY_c5a89c70 = 'TLS_PIN_HISTORY_CAPACITY';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:58 }
  CozyText_Tls_PinWindow_TLS_PIN_PLAN_INVALID_f1f2dcc1 = 'TLS_PIN_PLAN_INVALID';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:190 }
  CozyText_Tls_PinWindow_TLS_PIN_ROLLBACK_FORBIDDEN_13a86568 = 'TLS_PIN_ROLLBACK_FORBIDDEN';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:177 }
  CozyText_Tls_PinWindow_TLS_PIN_TRUST_CHAIN_INVALID_1dc8f8fe = 'TLS_PIN_TRUST_CHAIN_INVALID';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:225 }
  CozyText_Tls_PinWindow_contract_f569c72b = 'contract';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:124 }
  CozyText_Tls_PinWindow_currentPin_3b8bb112 = 'currentPin';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:227 }
  CozyText_Tls_PinWindow_floor_b84cf89c = 'floor';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:122 }
  CozyText_Tls_PinWindow_generation_f47154a7 = 'generation';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:119 }
  CozyText_Tls_PinWindow_host_976ccbf3 = 'host';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:127 }
  CozyText_Tls_PinWindow_issuedAt_b190554e = 'issuedAt';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:124 }
  CozyText_Tls_PinWindow_nextPin_76888740 = 'nextPin';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:127 }
  CozyText_Tls_PinWindow_notBefore_126137f9 = 'notBefore';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:128 }
  CozyText_Tls_PinWindow_oldNotAfter_78ca6c19 = 'oldNotAfter';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:226 }
  CozyText_Tls_PinWindow_plan_8fd236a9 = 'plan';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:119 }
  CozyText_Tls_PinWindow_port_c52491ee = 'port';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:228 }
  CozyText_Tls_PinWindow_retiredPins_2836045f = 'retiredPins';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:120 }
  CozyText_Tls_PinWindow_serverKeyId_c8f1e9fb = 'serverKeyId';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:120 }
  CozyText_Tls_PinWindow_tlsServerName_b7fd4d27 = 'tlsServerName';
  { Cozy.Source/Cozy.Network/Cozy.Tls.PinWindow.pas:118 }
  CozyText_Tls_PinWindow_version_6f902017 = 'version';
  { Cozy.Source/Cozy.Network/Cozy.Tls.pas:750 }
  CozyText_Tls_SHA256_2c91bdc1 = 'SHA256';
  { Cozy.Source/Cozy.Network/Cozy.Tls.pas:555 }
  CozyText_Tls_TLS_requires_Windows_64_bit_record_layout_ab91efbd = 'TLS requires Windows 64-bit record layout.';
  { Cozy.Source/Cozy.Network/Cozy.Tls.pas:557 }
  CozyText_Tls_TLS_requires_read_and_write_callbacks_6b5dcf61 = 'TLS requires read and write callbacks.';
  { Cozy.Source/Cozy.Network/Cozy.Tls.pas:1044 }
  CozyText_Tls_crypt32_dll_634271fc = 'crypt32.dll';
  { Cozy.Source/Cozy.Network/Cozy.Tls.pas:1036 }
  CozyText_Tls_secur32_dll_8c1308f4 = 'secur32.dll';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:664 }
  CozyText_Transport_AES_e4de2176 = 'AES';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:488 }
  CozyText_Transport_A_4905d724 = '관리자가 발급한 A 실행 파일에서 서버 연결을 전달받아야 합니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:590 }
  CozyText_Transport_Authenticated_TLS_pin_update_was_rejected_360a10f1 = 'Authenticated TLS pin update was rejected.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:780 }
  CozyText_Transport_CONNECT_AUTHENTICATION_FAILED_a99efd74 = 'CONNECT_AUTHENTICATION_FAILED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:297 }
  CozyText_Transport_CONNECT_CANCELLED_539a9bd0 = 'CONNECT_CANCELLED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:340 }
  CozyText_Transport_CONNECT_CRYPTO_FAILED_8a140893 = 'CONNECT_CRYPTO_FAILED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:589 }
  CozyText_Transport_CONNECT_FAILED_0e77cb75 = 'CONNECT_FAILED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:333 }
  CozyText_Transport_CONNECT_INVALID_RESPONSE_695727cd = 'CONNECT_INVALID_RESPONSE';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:630 }
  CozyText_Transport_CONNECT_OPERATION_INVALID_4592c542 = 'CONNECT_OPERATION_INVALID';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:491 }
  CozyText_Transport_CONNECT_PLATFORM_INVALID_b5b4b993 = 'CONNECT_PLATFORM_INVALID';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:487 }
  CozyText_Transport_CONNECT_PROFILE_REQUIRED_cccdaa6c = 'CONNECT_PROFILE_REQUIRED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:731 }
  CozyText_Transport_CONNECT_RECEIVE_FAILED_6e6fb52f = 'CONNECT_RECEIVE_FAILED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:632 }
  CozyText_Transport_CONNECT_REQUEST_INVALID_1bc92c29 = 'CONNECT_REQUEST_INVALID';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:648 }
  CozyText_Transport_CONNECT_REQUEST_TOO_LARGE_f6b52573 = 'CONNECT_REQUEST_TOO_LARGE';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:727 }
  CozyText_Transport_CONNECT_SEND_FAILED_a7f20ad5 = 'CONNECT_SEND_FAILED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:299 }
  CozyText_Transport_CONNECT_TIMEOUT_b3f71146 = 'CONNECT_TIMEOUT';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:724 }
  CozyText_Transport_CONNECT_UNAVAILABLE_b1c0cb85 = 'CONNECT_UNAVAILABLE';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:112 }
  CozyText_Transport_ChainingModeGCM_52dc3d90 = 'ChainingModeGCM';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:665 }
  CozyText_Transport_ChainingMode_bc99d0e4 = 'ChainingMode';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:104 }
  CozyText_Transport_GAME_CONNECT_4_e3fdb954 = 'GAME-CONNECT-4';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:647 }
  CozyText_Transport_REQUEST_ENVELOPE_LIMIT_5d964901 = 'REQUEST_ENVELOPE_LIMIT';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:679 }
  CozyText_Transport_REQUEST_d12fceaa = 'REQUEST';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:766 }
  CozyText_Transport_RESPONSE_7c348372 = 'RESPONSE';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:497 }
  CozyText_Transport_RSAPUBLICBLOB_77898084 = 'RSAPUBLICBLOB';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:496 }
  CozyText_Transport_RSA_b94db0f4 = 'RSA';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:299 }
  CozyText_Transport_Request_deadline_expired_fb214276 = 'Request deadline expired.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:648 }
  CozyText_Transport_Request_is_too_large_c15ffa1f = 'Request is too large.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:297 }
  CozyText_Transport_Request_was_cancelled_7b0bf9b8 = 'Request was cancelled.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:671 }
  CozyText_Transport_SHA256_48c1f8ac = 'SHA256';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:289 }
  CozyText_Transport_TRANSPORT_GENERATION_EXHAUSTED_275c82cf = 'TRANSPORT_GENERATION_EXHAUSTED';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:287 }
  CozyText_Transport_TRANSPORT_STILL_IN_USE_bc762d31 = 'TRANSPORT_STILL_IN_USE';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:676 }
  CozyText_Transport_Text_0207d94b = '서버 공개 키 암호화에 실패했습니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:709 }
  CozyText_Transport_Text_02e008de = '암호화된 요청 크기가 너무 큽니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:713 }
  CozyText_Transport_Text_116e93af = '서버 요청 시간이 초과되었습니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:691 }
  CozyText_Transport_Text_1cb97d6e = '서버 요청 암호화에 실패했습니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:632 }
  CozyText_Transport_Text_3799ef82 = '서버 요청이 비어 있습니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:334 }
  CozyText_Transport_Text_7c73d273 = '서버 응답을 확인할 수 없습니다. 연결 파일과 서버 상태를 확인하세요.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:781 }
  CozyText_Transport_Text_8edfbce9 = '서버 응답의 보안 검증에 실패했습니다. 연결을 중단했습니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:728 }
  CozyText_Transport_Text_a5938463 = '서버에 요청을 보내지 못했습니다. 다시 확인하세요.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:652 }
  CozyText_Transport_Text_bdacb438 = '서버 요청 크기가 너무 큽니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:807 }
  CozyText_Transport_Text_c0afdc2c = '보안 서버 연결을 완료할 수 없습니다. 잠시 후 다시 시도하세요.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:630 }
  CozyText_Transport_Text_c2c01286 = '지원하지 않는 서버 요청입니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:654 }
  CozyText_Transport_Text_d57b3c15 = '보안 요청 번호를 만들 수 없습니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:725 }
  CozyText_Transport_Text_ea42d423 = '서버에 연결할 수 없습니다. 인터넷 연결과 관리자의 서버 상태를 확인하세요.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:732 }
  CozyText_Transport_Text_f56d9902 = '서버 응답을 받지 못했습니다. 연결 상태를 확인하고 다시 시도하세요.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:341 }
  CozyText_Transport_Windows_292bdf8d = 'Windows 보안 연결을 준비할 수 없습니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:492 }
  CozyText_Transport_Windows_64_64ae4a0c = '이 프로그램은 Windows 64비트 빌드에서 실행해야 합니다.';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:790 }
  CozyText_Transport_authenticated_plain_90443b15 = 'authenticated-plain';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:834 }
  CozyText_Transport_bcrypt_dll_8e6256e8 = 'bcrypt.dll';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:772 }
  CozyText_Transport_before_decrypt_1bf9eebc = 'before-decrypt';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:574 }
  CozyText_Transport_before_publication_bb6d404e = 'before-publication';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:628 }
  CozyText_Transport_bootstrap_b2e494e5 = 'bootstrap';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:627 }
  CozyText_Transport_challenge_9e384e4b = 'challenge';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:701 }
  CozyText_Transport_ciphertext_30a2d71e = 'ciphertext';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:629 }
  CozyText_Transport_device_88d0d84b = 'device';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:627 }
  CozyText_Transport_execute_b76629f3 = 'execute';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:832 }
  CozyText_Transport_kernel32_dll_321762c1 = 'kernel32.dll';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:697 }
  CozyText_Transport_keyId_70570c2b = 'keyId';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:700 }
  CozyText_Transport_nonce_2bb29dca = 'nonce';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:629 }
  CozyText_Transport_overlay_a9bfd131 = 'overlay';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:799 }
  CozyText_Transport_parsed_json_f607f5aa = 'parsed-json';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:629 }
  CozyText_Transport_policy_eca10e22 = 'policy';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:628 }
  CozyText_Transport_report_c323c6fc = 'report';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:698 }
  CozyText_Transport_requestId_d67f3acd = 'requestId';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:685 }
  CozyText_Transport_request_plain_50377d2e = 'request-plain';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:629 }
  CozyText_Transport_security_018694b5 = 'security';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:702 }
  CozyText_Transport_tag_1d13256a = 'tag';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:566 }
  CozyText_Transport_tlsPinPlan_d42e652f = 'tlsPinPlan';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:699 }
  CozyText_Transport_wrappedKey_f62b2737 = 'wrappedKey';
  { Cozy.Source/Cozy.Network/Cozy.Transport.pas:833 }
  CozyText_Transport_ws2_32_dll_9a035509 = 'ws2_32.dll';

implementation
end.
