unit Cozy.Strings.Security;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:393 }
  CozyText_Security_0123456789ABCDEF_5404eb8e = '0123456789ABCDEF';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:491 }
  CozyText_Security_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv_f1f45af2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:644 }
  CozyText_Security_CLAIM_82bd8309 = 'CLAIM';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:644 }
  CozyText_Security_DELEGATION_756578d3 = 'DELEGATION';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:496 }
  CozyText_Security_DEVICE_BASE64_TOO_LARGE_719ba37c = 'DEVICE_BASE64_TOO_LARGE';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:323 }
  CozyText_Security_DEVICE_HASH_INPUT_TOO_LARGE_eb72b9f9 = 'DEVICE_HASH_INPUT_TOO_LARGE';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:683 }
  CozyText_Security_GAME_HANDOFF_31644f6f = 'GAME-HANDOFF-';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:674 }
  CozyText_Security_HANDOFF_CANONICAL_INVALID_b49f9a7c = 'HANDOFF_CANONICAL_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:749 }
  CozyText_Security_HANDOFF_CLAIM_BINDING_INVALID_d299ddd7 = 'HANDOFF_CLAIM_BINDING_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:647 }
  CozyText_Security_HANDOFF_DELEGATION_INVALID_eaaea118 = 'HANDOFF_DELEGATION_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:621 }
  CozyText_Security_HANDOFF_PUBLIC_KEY_INVALID_a14478dc = 'HANDOFF_PUBLIC_KEY_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:427 }
  CozyText_Security_Key_Usage_b1f7d66a = 'Key Usage';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:425 }
  CozyText_Security_Length_8cf71aa9 = 'Length';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:97 }
  CozyText_Security_Microsoft_Software_Key_Storage_Provider_538976fd = 'Microsoft Software Key Storage Provider';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:518 }
  CozyText_Security_OBJECT_CLOSING_d0c2ed32 = 'OBJECT_CLOSING';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:100 }
  CozyText_Security_RSAPUBLICBLOB_54b4e104 = 'RSAPUBLICBLOB';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:98 }
  CozyText_Security_RSA_35359569 = 'RSA';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:806 }
  CozyText_Security_SECURITY_FIELD_INVALID_b597bac4 = 'SECURITY_FIELD_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:99 }
  CozyText_Security_SHA256_a83f6e23 = 'SHA256';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:334 }
  CozyText_Security_SHA_256_25af6872 = 'SHA-256 계산';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:331 }
  CozyText_Security_SHA_256_75e82dd1 = 'SHA-256 초기화';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:338 }
  CozyText_Security_SHA_256_a6171e89 = 'SHA-256 완료';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:328 }
  CozyText_Security_SHA_256_e827d5f9 = 'SHA-256 공급자 열기';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:429 }
  CozyText_Security_Text_02c94e94 = '임시 기기 키 준비';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:566 }
  CozyText_Security_Text_124d1e4e = '기기 서명';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:596 }
  CozyText_Security_Text_13fb7914 = '서명 요청이 너무 큽니다.';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:411 }
  CozyText_Security_Text_1b613c55 = '임시 기기 키 공급자 열기';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:474 }
  CozyText_Security_Text_2418f270 = '공개 키를 읽지 못했습니다.';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:426 }
  CozyText_Security_Text_6a50c977 = '기기 키 길이 설정';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:471 }
  CozyText_Security_Text_8d117129 = '공개 키 내보내기';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:569 }
  CozyText_Security_Text_9bb7ab80 = '기기 서명을 완료하지 못했습니다.';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:466 }
  CozyText_Security_Text_ab06b760 = '공개 키 크기가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:464 }
  CozyText_Security_Text_c1d0333b = '공개 키 크기 확인';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:422 }
  CozyText_Security_Text_d8565d75 = '임시 기기 키 생성';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:428 }
  CozyText_Security_Text_dc8043d7 = '기기 키 용도 설정';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:556 }
  CozyText_Security_Text_e3ba2847 = '서명 크기 확인';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:558 }
  CozyText_Security_Text_f1ef77c9 = '서명 크기가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:481 }
  CozyText_Security_Text_faeaff1b = '공개 키 형식이 올바르지 않습니다.';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:684 }
  CozyText_Security_V3_c65e5274 = '-V3';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:839 }
  CozyText_Security_bcrypt_dll_5d33225d = 'bcrypt.dll';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:832 }
  CozyText_Security_ncrypt_dll_96f4320f = 'ncrypt.dll';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:294 }
  CozyText_Security_s_0x_s_f913b20a = '%s에 실패했습니다. (0x%s)';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:550 }
  CozyText_Security_sign_digest_b3d8d720 = 'sign-digest';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:544 }
  CozyText_Security_sign_input_e5ed50c1 = 'sign-input';
  { Cozy.Source/Cozy.Security/Cozy.Security.pas:571 }
  CozyText_Security_sign_signature_a1118132 = 'sign-signature';
  { Cozy.Source/Cozy.Security/Cozy.SensitiveText.pas:60 }
  CozyText_SensitiveText_SECRET_SIZE_INVALID_099110fc = 'SECRET_SIZE_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.SensitiveText.pas:118 }
  CozyText_SensitiveText_SECRET_SOURCE_INVALID_d1235b06 = 'SECRET_SOURCE_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.SensitiveText.pas:89 }
  CozyText_SensitiveText_SECRET_TOO_LONG_c3555c81 = 'SECRET_TOO_LONG';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:77 }
  CozyText_ServerAuthority_CLIENT_STOPPING_1829bd1c = 'CLIENT_STOPPING';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:173 }
  CozyText_ServerAuthority_CONNECT_RECEIVE_FAILED_c7440a32 = 'CONNECT_RECEIVE_FAILED';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:173 }
  CozyText_ServerAuthority_CONNECT_SEND_FAILED_bb1a979b = 'CONNECT_SEND_FAILED';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:172 }
  CozyText_ServerAuthority_CONNECT_TIMEOUT_e18c1f98 = 'CONNECT_TIMEOUT';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:172 }
  CozyText_ServerAuthority_CONNECT_UNAVAILABLE_348a6c0f = 'CONNECT_UNAVAILABLE';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:51 }
  CozyText_ServerAuthority_GAME_AUTHORITY_V2_8ae9fd0f = 'GAME-AUTHORITY-V2';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:392 }
  CozyText_ServerAuthority_INDETERMINATE_f930248a = 'INDETERMINATE';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:378 }
  CozyText_ServerAuthority_Isolated_report_stop_test_bc3bb9f6 = 'Isolated report-stop test.';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:408 }
  CozyText_ServerAuthority_MEASUREMENT_UNAVAILABLE_41cca989 = 'MEASUREMENT_UNAVAILABLE';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:393 }
  CozyText_ServerAuthority_MISMATCH_99711c35 = 'MISMATCH';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:174 }
  CozyText_ServerAuthority_NETWORK_UNAVAILABLE_429d6e4b = 'NETWORK_UNAVAILABLE';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:392 }
  CozyText_ServerAuthority_PASS_c0904000 = 'PASS';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:378 }
  CozyText_ServerAuthority_PRODUCT_FAULT_REPORT_STOPPED_67736fb8 = 'PRODUCT_FAULT_REPORT_STOPPED';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:181 }
  CozyText_ServerAuthority_Pattern_084c1bd6 = '^[A-Z][A-Z0-9_]{1,79}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:255 }
  CozyText_ServerAuthority_Pattern_1413addd = '^[a-f0-9]{128}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:298 }
  CozyText_ServerAuthority_Pattern_1b2bcaae = '^[a-f0-9]{48}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:185 }
  CozyText_ServerAuthority_SECURITY_CAPACITY_1df6b4d3 = 'SECURITY_CAPACITY';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:184 }
  CozyText_ServerAuthority_SECURITY_CHALLENGE_INVALID_01125686 = 'SECURITY_CHALLENGE_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:183 }
  CozyText_ServerAuthority_SECURITY_FRESH_OBSERVATION_REQUIRED_b268784a = 'SECURITY_FRESH_OBSERVATION_REQUIRED';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:113 }
  CozyText_ServerAuthority_SECURITY_OBSERVATION_BUSY_f35596ed = 'SECURITY_OBSERVATION_BUSY';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:80 }
  CozyText_ServerAuthority_SECURITY_OBSERVATION_TIMEOUT_8c795aca = 'SECURITY_OBSERVATION_TIMEOUT';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:406 }
  CozyText_ServerAuthority_SECURITY_OBSERVATION_e9752426 = 'SECURITY_OBSERVATION_';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:184 }
  CozyText_ServerAuthority_SECURITY_RATE_LIMIT_eabda515 = 'SECURITY_RATE_LIMIT';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:62 }
  CozyText_ServerAuthority_SECURITY_RESPONSE_INVALID_ae0f58bd = 'SECURITY_RESPONSE_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:77 }
  CozyText_ServerAuthority_Session_is_closing_b81bf06a = 'Session is closing.';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:182 }
  CozyText_ServerAuthority_Text_4311750c = '서버 보안 확인을 완료하지 못했습니다. 다시 확인해 주세요.';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:81 }
  CozyText_ServerAuthority_Text_6007d1b9 = '서버 보안 확인 시간이 초과되었습니다. 다시 확인해 주세요.';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:63 }
  CozyText_ServerAuthority_Text_72f3251a = '서버 보안 확인 응답을 검증하지 못했습니다.';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:114 }
  CozyText_ServerAuthority_Text_848d7235 = '같은 작업의 보안 확인이 진행 중입니다.';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:407 }
  CozyText_ServerAuthority_Text_a2b88c6b = '서버 보안 확인으로 작업이 보류되었습니다. 다시 확인해 주세요.';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:388 }
  CozyText_ServerAuthority_accepted_93e25289 = 'accepted';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:244 }
  CozyText_ServerAuthority_action_3cf8ef05 = 'action';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:346 }
  CozyText_ServerAuthority_apiSealed_6447305e = 'apiSealed';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:347 }
  CozyText_ServerAuthority_apiSlots_17b25661 = 'apiSlots';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:389 }
  CozyText_ServerAuthority_attested_d629bbbf = 'attested';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:272 }
  CozyText_ServerAuthority_authorityChallenge_7c9cc734 = 'authorityChallenge';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:361 }
  CozyText_ServerAuthority_authorityPayload_56056ffe = 'authorityPayload';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:383 }
  CozyText_ServerAuthority_authorityReply_ebe1af0d = 'authorityReply';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:312 }
  CozyText_ServerAuthority_authority_measurement_skipped_53a3d46f = 'authority-measurement-skipped';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:375 }
  CozyText_ServerAuthority_authority_report_stopped_014a1f8d = 'authority-report-stopped';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:250 }
  CozyText_ServerAuthority_binding_308e17a7 = 'binding';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:349 }
  CozyText_ServerAuthority_cfg_0b4824d7 = 'cfg';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:295 }
  CozyText_ServerAuthority_challengeId_6dd74210 = 'challengeId';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:259 }
  CozyText_ServerAuthority_challenge_662ced51 = 'challenge';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:339 }
  CozyText_ServerAuthority_codeBlake3_c9cf06fa = 'codeBlake3';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:337 }
  CozyText_ServerAuthority_codeCrc64_00e5aa47 = 'codeCrc64';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:336 }
  CozyText_ServerAuthority_codeSha512_008274fe = 'codeSha512';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:338 }
  CozyText_ServerAuthority_codeXxh3_128_2645c76b = 'codeXxh3_128';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:343 }
  CozyText_ServerAuthority_crcLayers_a1b12042 = 'crcLayers';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:187 }
  CozyText_ServerAuthority_data_b9326ab6 = 'data';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:286 }
  CozyText_ServerAuthority_deviceSignalsRequested_c9b9d556 = 'deviceSignalsRequested';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:264 }
  CozyText_ServerAuthority_deviceSignalsVersion_0a96eb08 = 'deviceSignalsVersion';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:305 }
  CozyText_ServerAuthority_dynamicCode_20202cec = 'dynamicCode';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:297 }
  CozyText_ServerAuthority_epoch_4ee28422 = 'epoch';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:180 }
  CozyText_ServerAuthority_error_9eefe280 = 'error';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:303 }
  CozyText_ServerAuthority_expiresAt_936e4de3 = 'expiresAt';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:335 }
  CozyText_ServerAuthority_fileCrc64_f8383054 = 'fileCrc64';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:334 }
  CozyText_ServerAuthority_fileSha512_0effe453 = 'fileSha512';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:332 }
  CozyText_ServerAuthority_hashVersion_f0b7fb6d = 'hashVersion';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:249 }
  CozyText_ServerAuthority_intent_83992ce4 = 'intent';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:248 }
  CozyText_ServerAuthority_machineId_b7bf7b62 = 'machineId';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:333 }
  CozyText_ServerAuthority_measurement_ef68f65d = 'measurement';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:350 }
  CozyText_ServerAuthority_mitigationDiagnostics_bd6aefb3 = 'mitigationDiagnostics';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:269 }
  CozyText_ServerAuthority_mitigationEnvironment_c0780a83 = 'mitigationEnvironment';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:268 }
  CozyText_ServerAuthority_mitigationProfileVersion_c5166409 = 'mitigationProfileVersion';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:279 }
  CozyText_ServerAuthority_mitigationProfile_ce0336da = 'mitigationProfile';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:54 }
  CozyText_ServerAuthority_nhwChallenge_5bfa1ea9 = 'nhwChallenge';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:55 }
  CozyText_ServerAuthority_nhwVerdict_6af42903 = 'nhwVerdict';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:53 }
  CozyText_ServerAuthority_nhwVersion_d3612220 = 'nhwVersion';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:296 }
  CozyText_ServerAuthority_nonce_5928ba20 = 'nonce';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:178 }
  CozyText_ServerAuthority_ok_9ea7db66 = 'ok';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:340 }
  CozyText_ServerAuthority_ownMeasurement_75447b40 = 'ownMeasurement';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:372 }
  CozyText_ServerAuthority_payload_042d9fd9 = 'payload';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:394 }
  CozyText_ServerAuthority_proceed_b2275828 = 'proceed';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:390 }
  CozyText_ServerAuthority_reason_95413850 = 'reason';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:302 }
  CozyText_ServerAuthority_revision_93adf670 = 'revision';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:168 }
  CozyText_ServerAuthority_security_70a7e1e8 = 'security';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:301 }
  CozyText_ServerAuthority_sequence_9e85f21c = 'sequence';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:246 }
  CozyText_ServerAuthority_sessionId_63d5bd84 = 'sessionId';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:247 }
  CozyText_ServerAuthority_sessionToken_ddf86030 = 'sessionToken';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:373 }
  CozyText_ServerAuthority_signature_aed6856e = 'signature';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:245 }
  CozyText_ServerAuthority_stage_dc5b7edd = 'stage';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:391 }
  CozyText_ServerAuthority_status_09762dac = 'status';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:370 }
  CozyText_ServerAuthority_submit_665a2c63 = 'submit';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:155 }
  CozyText_ServerAuthority_true_5a5135e9 = 'true';
  { Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas:294 }
  CozyText_ServerAuthority_version_3101a476 = 'version';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:330 }
  CozyText_ServerOperations_CONNECT_RECEIVE_FAILED_aa008182 = 'CONNECT_RECEIVE_FAILED';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:331 }
  CozyText_ServerOperations_CONNECT_TIMEOUT_a4040567 = 'CONNECT_TIMEOUT';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:71 }
  CozyText_ServerOperations_COZY_SERVER_OPERATION_ARGUMENT_INVALID_fa040681 = 'COZY_SERVER_OPERATION_ARGUMENT_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:232 }
  CozyText_ServerOperations_COZY_SERVER_OPERATION_CANCELLED_09ad299c = 'COZY_SERVER_OPERATION_CANCELLED';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:66 }
  CozyText_ServerOperations_COZY_SERVER_OPERATION_FUNCTION_INVALID_3ccdcb22 = 'COZY_SERVER_OPERATION_FUNCTION_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:60 }
  CozyText_ServerOperations_COZY_SERVER_OPERATION_RESPONSE_INVALID_842a3fd4 = 'COZY_SERVER_OPERATION_RESPONSE_INVALID';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:55 }
  CozyText_ServerOperations_COZY_SERVER_OPERATION_V1_86c494eb = 'COZY-SERVER-OPERATION-V1';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:341 }
  CozyText_ServerOperations_Pattern_31d70624 = '^[A-Za-z0-9_-]{8,80}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:298 }
  CozyText_ServerOperations_Pattern_7afc92c8 = '^[a-f0-9]{48}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:266 }
  CozyText_ServerOperations_Pattern_8b847247 = '^[A-Z][A-Z0-9_]{1,79}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:342 }
  CozyText_ServerOperations_Pattern_93496fd2 = '^[a-f0-9]{64}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:304 }
  CozyText_ServerOperations_Pattern_a8dff57a = '^[a-f0-9]{128}$';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:245 }
  CozyText_ServerOperations_action_e140259c = 'action';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:305 }
  CozyText_ServerOperations_argsSha512_9bad8e76 = 'argsSha512';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:250 }
  CozyText_ServerOperations_args_c4a3346d = 'args';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:304 }
  CozyText_ServerOperations_binding_b2d365bb = 'binding';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:298 }
  CozyText_ServerOperations_challengeId_41663b56 = 'challengeId';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:296 }
  CozyText_ServerOperations_challenge_3a044d15 = 'challenge';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:269 }
  CozyText_ServerOperations_data_71a5ee08 = 'data';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:300 }
  CozyText_ServerOperations_epoch_b3e447e7 = 'epoch';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:266 }
  CozyText_ServerOperations_error_3fe1b525 = 'error';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:303 }
  CozyText_ServerOperations_expiresAt_8f4f4554 = 'expiresAt';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:249 }
  CozyText_ServerOperations_functionId_50c848cd = 'functionId';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:320 }
  CozyText_ServerOperations_invoke_e4beb29a = 'invoke';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:247 }
  CozyText_ServerOperations_machineId_56c42224 = 'machineId';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:299 }
  CozyText_ServerOperations_nonce_94916313 = 'nonce';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:308 }
  CozyText_ServerOperations_observe_599a8378 = 'observe';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:262 }
  CozyText_ServerOperations_ok_a12076d3 = 'ok';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:302 }
  CozyText_ServerOperations_operationsRevision_7b18ca10 = 'operationsRevision';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:248 }
  CozyText_ServerOperations_policyId_6eee1741 = 'policyId';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:258 }
  CozyText_ServerOperations_policy_8c903ccc = 'policy';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:247 }
  CozyText_ServerOperations_requestId_60a0fd94 = 'requestId';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:334 }
  CozyText_ServerOperations_result_2a0548b1 = 'result';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:301 }
  CozyText_ServerOperations_revision_9a9708c6 = 'revision';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:246 }
  CozyText_ServerOperations_sessionId_d05f0852 = 'sessionId';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:246 }
  CozyText_ServerOperations_sessionToken_1ce33cfb = 'sessionToken';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:321 }
  CozyText_ServerOperations_signature_2faec8bd = 'signature';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:245 }
  CozyText_ServerOperations_stage_0a4eb366 = 'stage';
  { Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas:297 }
  CozyText_ServerOperations_version_a31f027e = 'version';

implementation
end.
