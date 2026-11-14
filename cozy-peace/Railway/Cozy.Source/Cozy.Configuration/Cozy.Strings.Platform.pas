unit Cozy.Strings.Platform;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1381 }
  CozyText_Api_ACKNOWLEDGED_3e71d2a8 = 'ACKNOWLEDGED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:258 }
  CozyText_Api_ACTIVATION_NOT_FOUND_38fe5b7a = 'ACTIVATION_NOT_FOUND';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:259 }
  CozyText_Api_ACTIVATION_REVOKED_3e71b57b = 'ACTIVATION_REVOKED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1513 }
  CozyText_Api_AUTHORIZATION_FAILED_dd7fd3f9 = 'AUTHORIZATION_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:258 }
  CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394 = 'AUTHORIZATION_REQUIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:323 }
  CozyText_Api_A_6fb2a102 = 'A 실행 파일의 인증된 실행 세션이 필요합니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:358 }
  CozyText_Api_A_c6a4461b = 'A 실행 파일에서 인증된 서버 연결을 전달받아야 합니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1276 }
  CozyText_Api_A_live_license_is_required_ec8c1aef = 'A live license is required.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:322 }
  CozyText_Api_BOOTSTRAP_REQUIRED_eaf73372 = 'BOOTSTRAP_REQUIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:263 }
  CozyText_Api_CHALLENGE_EXPIRED_7ad45ede = 'CHALLENGE_EXPIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1167 }
  CozyText_Api_CHALLENGE_INVALID_58648ff0 = 'CHALLENGE_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1175 }
  CozyText_Api_CHALLENGE_MISMATCH_c7e4897d = 'CHALLENGE_MISMATCH';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:876 }
  CozyText_Api_CLIENT_STOPPING_99bc92f1 = 'CLIENT_STOPPING';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1235 }
  CozyText_Api_CLOCK_INVALID_7c73ca62 = 'CLOCK_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1381 }
  CozyText_Api_CLOSE_RESPONSE_c2e102cf = 'CLOSE_RESPONSE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1066 }
  CozyText_Api_CONNECT_RECEIVE_FAILED_0d3884c0 = 'CONNECT_RECEIVE_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1066 }
  CozyText_Api_CONNECT_SEND_FAILED_a8fbf652 = 'CONNECT_SEND_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1053 }
  CozyText_Api_CONNECT_TIMEOUT_d0dd2772 = 'CONNECT_TIMEOUT';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1065 }
  CozyText_Api_CONNECT_UNAVAILABLE_84dc2a9f = 'CONNECT_UNAVAILABLE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:459 }
  CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa = 'COZY_SERVER_OPERATION_CANCELLED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1674 }
  CozyText_Api_COZY_SERVER_OPERATION_LICENSE_REQUIRED_c843e348 = 'COZY_SERVER_OPERATION_LICENSE_REQUIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:405 }
  CozyText_Api_Contracts_API_BUFFER_CAPACITY_d5fbcca4 = 'API_BUFFER_CAPACITY';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:428 }
  CozyText_Api_Contracts_API_BUFFER_OVERLAP_ad4e964c = 'API_BUFFER_OVERLAP';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:391 }
  CozyText_Api_Contracts_API_BUFFER_RANGE_17bfadf0 = 'API_BUFFER_RANGE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:412 }
  CozyText_Api_Contracts_API_BUFFER_READ_ONLY_95c30e95 = 'API_BUFFER_READ_ONLY';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:447 }
  CozyText_Api_Contracts_API_CNG_LENGTH_986fdebc = 'API_CNG_LENGTH';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:441 }
  CozyText_Api_Contracts_API_COMMAND_EMBEDDED_NUL_3a5b9df6 = 'API_COMMAND_EMBEDDED_NUL';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:437 }
  CozyText_Api_Contracts_API_COMMAND_LENGTH_3163ea58 = 'API_COMMAND_LENGTH';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:439 }
  CozyText_Api_Contracts_API_COMMAND_TERMINATOR_da284e92 = 'API_COMMAND_TERMINATOR';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:418 }
  CozyText_Api_Contracts_API_RESULT_LENGTH_8817f1ef = 'API_RESULT_LENGTH';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:143 }
  CozyText_Api_Contracts_API_SENSITIVE_CAPACITY_3fe22bc3 = 'API_SENSITIVE_CAPACITY';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:230 }
  CozyText_Api_Contracts_API_SENSITIVE_CLOSED_5d20ef8c = 'API_SENSITIVE_CLOSED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:160 }
  CozyText_Api_Contracts_API_SENSITIVE_ENCODING_ef3c59a3 = 'API_SENSITIVE_ENCODING';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:231 }
  CozyText_Api_Contracts_API_SENSITIVE_SCOPE_ACTIVE_32c7429c = 'API_SENSITIVE_SCOPE_ACTIVE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:232 }
  CozyText_Api_Contracts_API_SENSITIVE_SCOPE_EXHAUSTED_53ffb961 = 'API_SENSITIVE_SCOPE_EXHAUSTED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:243 }
  CozyText_Api_Contracts_API_SENSITIVE_VIEW_REVOKED_127d77b0 = 'API_SENSITIVE_VIEW_REVOKED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:386 }
  CozyText_Api_Contracts_API_STRUCT_SIZE_b731c1b7 = 'API_STRUCT_SIZE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas:384 }
  CozyText_Api_Contracts_API_TARGET_REQUIRED_0ba34107 = 'API_TARGET_REQUIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:238 }
  CozyText_Api_DESKTOP_ACTIVATION_INVALID_797d982e = 'DESKTOP_ACTIVATION_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:242 }
  CozyText_Api_DESKTOP_CAPACITY_cdec56f4 = 'DESKTOP_CAPACITY';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:263 }
  CozyText_Api_DESKTOP_CHALLENGE_EXPIRED_bd352e6b = 'DESKTOP_CHALLENGE_EXPIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:236 }
  CozyText_Api_DESKTOP_DEVICE_MISMATCH_41fd9983 = 'DESKTOP_DEVICE_MISMATCH';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:234 }
  CozyText_Api_DESKTOP_EXPIRED_b6b3ee68 = 'DESKTOP_EXPIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:338 }
  CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f = 'DESKTOP_INTEGRITY_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:226 }
  CozyText_Api_DESKTOP_KEY_INVALID_7368322e = 'DESKTOP_KEY_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:228 }
  CozyText_Api_DESKTOP_KEY_USED_46deffda = 'DESKTOP_KEY_USED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:846 }
  CozyText_Api_DESKTOP_MODULE_INVENTORY_INVALID_a6d11253 = 'DESKTOP_MODULE_INVENTORY_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:240 }
  CozyText_Api_DESKTOP_PROOF_INVALID_0b662a1e = 'DESKTOP_PROOF_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:261 }
  CozyText_Api_DESKTOP_RATE_LIMITED_e00faa3e = 'DESKTOP_RATE_LIMITED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:242 }
  CozyText_Api_DESKTOP_RATE_LIMIT_1b0aaf4c = 'DESKTOP_RATE_LIMIT';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:232 }
  CozyText_Api_DESKTOP_RELEASED_36e42d39 = 'DESKTOP_RELEASED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:471 }
  CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f = 'DESKTOP_REPORT_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:230 }
  CozyText_Api_DESKTOP_REVOKED_661962ca = 'DESKTOP_REVOKED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:325 }
  CozyText_Api_DEVICE_ID_INVALID_6b6230a3 = 'DEVICE_ID_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:256 }
  CozyText_Api_DEVICE_MISMATCH_29be812e = 'DEVICE_MISMATCH';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1171 }
  CozyText_Api_GAME_DESKTOP_V2_7238710e = 'GAME-DESKTOP-V2';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:484 }
  CozyText_Api_GAME_INTEGRITY_REPORT_V2_25fd5853 = 'GAME-INTEGRITY-REPORT-V2';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Guid.pas:62 }
  CozyText_Api_Guid_ole32_dll_32775c3b = 'ole32.dll';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1448 }
  CozyText_Api_HANDOFF_BOOTSTRAP_INVALID_16d8c760 = 'HANDOFF_BOOTSTRAP_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1449 }
  CozyText_Api_HANDOFF_CHILD_BINDING_INVALID_effd6ca8 = 'HANDOFF_CHILD_BINDING_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1453 }
  CozyText_Api_HANDOFF_CHILD_EXITED_93181d3b = 'HANDOFF_CHILD_EXITED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1446 }
  CozyText_Api_HANDOFF_CIPHER_FAILED_a6983cc2 = 'HANDOFF_CIPHER_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1447 }
  CozyText_Api_HANDOFF_DELEGATION_INVALID_94f45f94 = 'HANDOFF_DELEGATION_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1445 }
  CozyText_Api_HANDOFF_KEY_EXPORT_FAILED_412ca6e9 = 'HANDOFF_KEY_EXPORT_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1452 }
  CozyText_Api_HANDOFF_PIPE_FAILED_8fecb4f4 = 'HANDOFF_PIPE_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1451 }
  CozyText_Api_HANDOFF_PIPE_TIMEOUT_f9e14f2f = 'HANDOFF_PIPE_TIMEOUT';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1450 }
  CozyText_Api_HANDOFF_PROCESS_CREATE_FAILED_cd404ddf = 'HANDOFF_PROCESS_CREATE_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1454 }
  CozyText_Api_HANDOFF_READY_TIMEOUT_99fd59d8 = 'HANDOFF_READY_TIMEOUT';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1455 }
  CozyText_Api_HANDOFF_WAIT_FAILED_cf9dd5b4 = 'HANDOFF_WAIT_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:601 }
  CozyText_Api_INTEGRITY_SNAPSHOT_STALE_9b2efe72 = 'INTEGRITY_SNAPSHOT_STALE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1124 }
  CozyText_Api_Image_integrity_unavailable_1d286b86 = 'Image integrity unavailable.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:581 }
  CozyText_Api_Image_measurement_failed_06492857 = 'Image measurement failed.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:498 }
  CozyText_Api_Integrity_report_was_not_accepted_3699d2c9 = 'Integrity report was not accepted.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1362 }
  CozyText_Api_Invalid_Overlay_identifier_eee9a3c6 = 'Invalid Overlay identifier.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:338 }
  CozyText_Api_Invalid_authenticated_code_baseline_27ec04d1 = 'Invalid authenticated code baseline.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:733 }
  CozyText_Api_Invalid_module_inventory_12dbfc0e = 'Invalid module inventory';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:483 }
  CozyText_Api_Invalid_report_challenge_1b82cf1a = 'Invalid report challenge.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1241 }
  CozyText_Api_LEASE_EXPIRED_1390b833 = 'LEASE_EXPIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:255 }
  CozyText_Api_LICENSE_ALREADY_USED_22a6e1fa = 'LICENSE_ALREADY_USED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:256 }
  CozyText_Api_LICENSE_DEVICE_MISMATCH_dcee6322 = 'LICENSE_DEVICE_MISMATCH';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:253 }
  CozyText_Api_LICENSE_DISABLED_bc026452 = 'LICENSE_DISABLED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:251 }
  CozyText_Api_LICENSE_EXPIRED_efcf4b27 = 'LICENSE_EXPIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:249 }
  CozyText_Api_LICENSE_INVALID_40254b1e = 'LICENSE_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:255 }
  CozyText_Api_LICENSE_IN_USE_4d5b6a1e = 'LICENSE_IN_USE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:248 }
  CozyText_Api_LICENSE_KEY_INVALID_6126d5ed = 'LICENSE_KEY_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:248 }
  CozyText_Api_LICENSE_NOT_FOUND_0fe2cc38 = 'LICENSE_NOT_FOUND';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:992 }
  CozyText_Api_LICENSE_RESPONSE_INVALID_0053ab4b = 'LICENSE_RESPONSE_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:253 }
  CozyText_Api_LICENSE_REVOKED_19e05c16 = 'LICENSE_REVOKED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:534 }
  CozyText_Api_MEASUREMENT_FAILED_5762724e = 'MEASUREMENT_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:505 }
  CozyText_Api_MODULE_INVENTORY_6b4ac364 = 'MODULE_INVENTORY';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1135 }
  CozyText_Api_Measurement_changed_during_proof_403d04ba = 'Measurement changed during proof.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:847 }
  CozyText_Api_Module_inventory_could_not_be_measured_2fc0fe29 = 'Module inventory could not be measured.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:714 }
  CozyText_Api_Module_inventory_unavailable_9b3a2db5 = 'Module inventory unavailable';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:246 }
  CozyText_Api_NETWORK_UNAVAILABLE_bad73935 = 'NETWORK_UNAVAILABLE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1441 }
  CozyText_Api_OVERLAY_DOWNLOAD_TICKET_EXPIRED_4fa3e2c5 = 'OVERLAY_DOWNLOAD_TICKET_EXPIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1440 }
  CozyText_Api_OVERLAY_DOWNLOAD_TIMEOUT_a34f9d07 = 'OVERLAY_DOWNLOAD_TIMEOUT';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1365 }
  CozyText_Api_OVERLAY_LAUNCH_FAILED_51d8326a = 'OVERLAY_LAUNCH_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1266 }
  CozyText_Api_OVERLAY_PREPARE_FAILED_e31af1a1 = 'OVERLAY_PREPARE_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1272 }
  CozyText_Api_OVERLAY_PROFILE_ALREADY_SELECTED_dddc9b9c = 'OVERLAY_PROFILE_ALREADY_SELECTED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1362 }
  CozyText_Api_OVERLAY_RESPONSE_INVALID_66fcc234 = 'OVERLAY_RESPONSE_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1370 }
  CozyText_Api_OVERLAY_START_FAILED_098b973b = 'OVERLAY_START_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1284 }
  CozyText_Api_OVERLAY_START_TIMEOUT_a2c90d7f = 'OVERLAY_START_TIMEOUT';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:556 }
  CozyText_Api_OVERLAY_START_b6fd3d2d = 'OVERLAY_START';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1373 }
  CozyText_Api_OVERLAY_TRANSFER_FAILED_4689b519 = 'OVERLAY_TRANSFER_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:533 }
  CozyText_Api_OWN_IMAGE_a1cda560 = 'OWN_IMAGE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1370 }
  CozyText_Api_Overlay_authorization_failed_97ba51f2 = 'Overlay authorization failed.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1272 }
  CozyText_Api_Overlay_profile_is_already_selected_d190f2de = 'Overlay profile is already selected.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1286 }
  CozyText_Api_Overlay_startup_stopped_94aa2ba7 = 'Overlay startup stopped.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:967 }
  CozyText_Api_PENDING_OPERATION_MISSING_74a69c39 = 'PENDING_OPERATION_MISSING';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:951 }
  CozyText_Api_PENDING_OPERATION_f345beda = 'PENDING_OPERATION';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:661 }
  CozyText_Api_PERIODIC_c91b2405 = 'PERIODIC';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1293 }
  CozyText_Api_Parent_authorization_expired_25d3018b = 'Parent authorization expired.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1311 }
  CozyText_Api_Parent_renewal_missed_its_lease_99546c89 = 'Parent renewal missed its lease.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1361 }
  CozyText_Api_Pattern_1e820360 = '^[A-F0-9]{24}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:995 }
  CozyText_Api_Pattern_22fd33b1 = '^[a-f0-9]{64}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:480 }
  CozyText_Api_Pattern_23f9cb7d = '^[A-Za-z0-9_-]{12,128}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:337 }
  CozyText_Api_Pattern_2fa9066c = '^[A-F0-9]{16}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:324 }
  CozyText_Api_Pattern_67c2fa3e = '^[A-F0-9]{64}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:481 }
  CozyText_Api_Pattern_9cabc583 = '^[A-Za-z0-9_-]{20,256}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:991 }
  CozyText_Api_Pattern_aee8d3e4 = '^(?:DL-)?[A-F0-9]{24}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:336 }
  CozyText_Api_Pattern_b8863bd8 = '^[a-f0-9]{128}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1090 }
  CozyText_Api_Pattern_da1e7df9 = '^[A-Z][A-Z0-9_]{1,79}$';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:111 }
  CozyText_Api_Pointer_API_pointer_codec_is_already_initialized_88eb4f5d = 'API pointer codec is already initialized.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:171 }
  CozyText_Api_Pointer_API_pointer_codec_is_not_initialized_3dd20dd8 = 'API pointer codec is not initialized.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:156 }
  CozyText_Api_Pointer_API_pointer_slot_is_not_bound_395aa09e = 'API pointer slot is not bound.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:158 }
  CozyText_Api_Pointer_API_pointer_slot_ownership_changed_9be03981 = 'API pointer slot ownership changed.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:131 }
  CozyText_Api_Pointer_API_storage_configuration_is_invalid_c8139d14 = 'API storage configuration is invalid.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:128 }
  CozyText_Api_Pointer_API_storage_initialization_order_is_invalid_3505beb9 = 'API storage initialization order is invalid.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:236 }
  CozyText_Api_Pointer_API_storage_is_not_initialized_d67187ff = 'API storage is not initialized.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:175 }
  CozyText_Api_Pointer_API_storage_is_unavailable_sealed_or_already_bou_4cc0b8de = 'API storage is unavailable, sealed or already bound.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:240 }
  CozyText_Api_Pointer_API_storage_protection_changed_876ad6c5 = 'API storage protection changed.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:211 }
  CozyText_Api_Pointer_A_decoded_API_pointer_is_missing_a103484c = 'A decoded API pointer is missing.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:114 }
  CozyText_Api_Pointer_A_required_API_pointer_codec_address_is_missing_6c645288 = 'A required API pointer codec address is missing.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:137 }
  CozyText_Api_Pointer_Cannot_allocate_API_pointer_storage_eed600ef = 'Cannot allocate API pointer storage.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:173 }
  CozyText_Api_Pointer_Cannot_bind_a_missing_API_address_8254a66b = 'Cannot bind a missing API address.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:247 }
  CozyText_Api_Pointer_Cannot_seal_API_pointer_storage_ff429f19 = 'Cannot seal API pointer storage.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:250 }
  CozyText_Api_Pointer_Cannot_verify_sealed_API_pointer_storage_113288a7 = 'Cannot verify sealed API pointer storage.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:291 }
  CozyText_Api_Pointer_OWN_POINTER_GRAPH_CHANGED_8a6c236d = 'OWN_POINTER_GRAPH_CHANGED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:183 }
  CozyText_Api_Pointer_OWN_POINTER_REGISTRATION_INVALID_627e18b1 = 'OWN_POINTER_REGISTRATION_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:351 }
  CozyText_Api_Pointer_PROBE_PROTECTION_FAILED_017c3de1 = 'PROBE_PROTECTION_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Pointer.pas:356 }
  CozyText_Api_Pointer_PROBE_RESTORE_FAILED_2d94ec39 = 'PROBE_RESTORE_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:261 }
  CozyText_Api_RATE_LIMITED_87e1616b = 'RATE_LIMITED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:499 }
  CozyText_Api_REJECTED_ed32f000 = 'REJECTED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1617 }
  CozyText_Api_RELEASE_FAILED_c9e94c85 = 'RELEASE_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:977 }
  CozyText_Api_RELEASE_RESPONSE_INVALID_4c87df03 = 'RELEASE_RESPONSE_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:275 }
  CozyText_Api_REQUEST_ID_FAILED_7cc586ce = 'REQUEST_ID_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:195 }
  CozyText_Api_RESPONSE_INVALID_7c33082c = 'RESPONSE_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:297 }
  CozyText_Api_RUNTIME_GRAPH_REQUIRED_8db6bde0 = 'RUNTIME_GRAPH_REQUIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:471 }
  CozyText_Api_Report_exceeds_its_bound_b11981a5 = 'Report exceeds its bound.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1053 }
  CozyText_Api_Request_retry_deadline_expired_f15f3bab = 'Request retry deadline expired.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:356 }
  CozyText_Api_SERVER_PROFILE_REQUIRED_c8eed0ab = 'SERVER_PROFILE_REQUIRED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1091 }
  CozyText_Api_SERVER_RESPONSE_INVALID_bc45605f = 'SERVER_RESPONSE_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:246 }
  CozyText_Api_SERVER_UNAVAILABLE_218c8e9e = 'SERVER_UNAVAILABLE';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:265 }
  CozyText_Api_SERVICE_DISABLED_60b15675 = 'SERVICE_DISABLED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:244 }
  CozyText_Api_STORAGE_SAVE_FAILED_0de27f28 = 'STORAGE_SAVE_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:503 }
  CozyText_Api_Server_rejected_image_integrity_9cd6cafb = 'Server rejected image integrity.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:876 }
  CozyText_Api_Session_is_closing_e8e98ec3 = 'Session is closing.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:259 }
  CozyText_Api_TOKEN_INVALID_54eb26e0 = 'TOKEN_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:325 }
  CozyText_Api_Text_0693b48a = '실행 인증 키가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:968 }
  CozyText_Api_Text_0832d1c7 = '재확인할 인증 요청이 없습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:200 }
  CozyText_Api_Text_0bc06c70 = '서버 응답에 필요한 정보가 없습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:257 }
  CozyText_Api_Text_0d378b71 = '다른 기기에서 사용 중인 라이선스입니다. 관리자에게 문의해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:260 }
  CozyText_Api_Text_11b8d3a4 = '라이선스 인증이 필요합니다. 새 키를 입력하거나 관리자에게 문의해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1569 }
  CozyText_Api_Text_13e2c01f = '기기 인증을 확인하지 못했습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:264 }
  CozyText_Api_Text_1592915b = '인증 요청 시간이 지났습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:237 }
  CozyText_Api_Text_32af3b77 = '라이선스가 연결된 실행 세션에서 확인하세요. 종료한 세션은 복구할 수 없습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:254 }
  CozyText_Api_Text_3b9a3fa9 = '이용이 중지된 라이선스입니다. 관리자에게 문의해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1232 }
  CozyText_Api_Text_42c513be = '라이선스 유효 기간을 검증하지 못했습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1236 }
  CozyText_Api_Text_4ecf7ffb = '기기 시간을 확인할 수 없습니다. 다시 실행해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1176 }
  CozyText_Api_Text_5ca9d35c = '기기 인증 요청이 일치하지 않습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:210 }
  CozyText_Api_Text_63e20645 = '서버 응답의 시간을 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:227 }
  CozyText_Api_Text_71616e78 = '라이선스 키를 확인해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:262 }
  CozyText_Api_Text_745e1447 = '요청이 많습니다. 잠시 후 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1619 }
  CozyText_Api_Text_77b8608e = '라이선스 연결 해제를 완료하지 못했습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:247 }
  CozyText_Api_Text_7e4042dc = '서버에 연결하지 못했습니다. 인터넷 연결을 확인해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1168 }
  CozyText_Api_Text_805f0f69 = '기기 인증 요청을 검증하지 못했습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1515 }
  CozyText_Api_Text_895eea7d = '기기 인증을 완료하지 못했습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:243 }
  CozyText_Api_Text_9757ef58 = '인증 요청이 많습니다. 잠시 후 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:213 }
  CozyText_Api_Text_9f015d49 = '서버 응답의 값을 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:266 }
  CozyText_Api_Text_a0b0229f = '서비스가 일시 중지되었습니다. 잠시 후 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:276 }
  CozyText_Api_Text_a819bfcb = '인증 요청을 만들지 못했습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:231 }
  CozyText_Api_Text_a8c07451 = '관리자가 이 라이선스를 해지했습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:993 }
  CozyText_Api_Text_c3f33356 = '라이선스 인증 응답을 검증하지 못했습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:267 }
  CozyText_Api_Text_cf7744db = '요청을 완료하지 못했습니다. (';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:239 }
  CozyText_Api_Text_e2bf45d3 = '인증 정보를 확인할 수 없습니다. 관리자에게 재발급을 요청해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:196 }
  CozyText_Api_Text_e5363b36 = '서버 응답을 확인할 수 없습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:978 }
  CozyText_Api_Text_ecd8e220 = '라이선스 연결 해제를 확인하지 못했습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:235 }
  CozyText_Api_Text_edc810c7 = '라이선스가 만료되었습니다.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:229 }
  CozyText_Api_Text_f0bbeba9 = '이미 사용한 라이선스 키입니다. 관리자에게 문의해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1242 }
  CozyText_Api_Text_f1a4f1aa = '인증 확인 시간이 지났습니다. 다시 시도해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:233 }
  CozyText_Api_Text_f3e46ffd = '연결 해제된 라이선스입니다. 새 키를 입력해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:241 }
  CozyText_Api_Text_f8e29556 = '기기 서명을 확인하지 못했습니다. 다시 실행해 주세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.Types.pas:101 }
  CozyText_Api_Types_USED_9d9f0b1d = 'USED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:974 }
  CozyText_Api_USED_f24e3598 = 'USED';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:289 }
  CozyText_Api_Windows_PC_7f64a651 = 'Windows PC';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:497 }
  CozyText_Api_accepted_3194d58e = 'accepted';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:437 }
  CozyText_Api_action_a7b64efd = 'action';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1212 }
  CozyText_Api_activatedAt_f231270f = 'activatedAt';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:994 }
  CozyText_Api_activationToken_43b27685 = 'activationToken';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1356 }
  CozyText_Api_appVersion_95a577ca = 'appVersion';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:507 }
  CozyText_Api_batchCount_cf30cc7e = 'batchCount';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:506 }
  CozyText_Api_batchIndex_10fbd448 = 'batchIndex';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:422 }
  CozyText_Api_binaryCrc64_d5a2c3b3 = 'binaryCrc64';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:421 }
  CozyText_Api_binarySha512_f63e79ae = 'binarySha512';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:435 }
  CozyText_Api_body_2422e5c9 = 'body';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:929 }
  CozyText_Api_bootstrapSessionId_95160bd3 = 'bootstrapSessionId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:930 }
  CozyText_Api_bootstrapSessionToken_8157afed = 'bootstrapSessionToken';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1174 }
  CozyText_Api_canonical_cc5c5ef4 = 'canonical';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1161 }
  CozyText_Api_challengeId_61686f91 = 'challengeId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:473 }
  CozyText_Api_challenge_1e1bb128 = 'challenge';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:505 }
  CozyText_Api_check_73cb80a0 = 'check';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:914 }
  CozyText_Api_codeBlake3_70bf223e = 'codeBlake3';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:424 }
  CozyText_Api_codeCrc64_edb1d41f = 'codeCrc64';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:423 }
  CozyText_Api_codeSha512_dc876766 = 'codeSha512';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:914 }
  CozyText_Api_codeXxh3_128_dfad56f5 = 'codeXxh3_128';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:665 }
  CozyText_Api_complete_8da1b623 = 'complete';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:679 }
  CozyText_Api_coverage_bd2f2d35 = 'coverage';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:916 }
  CozyText_Api_crcLayers_e725ed1c = 'crcLayers';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1097 }
  CozyText_Api_data_e477ee02 = 'data';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:976 }
  CozyText_Api_deviceId_017320c2 = 'deviceId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1500 }
  CozyText_Api_deviceName_03461804 = 'deviceName';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:678 }
  CozyText_Api_deviceSignals_36203103 = 'deviceSignals';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1087 }
  CozyText_Api_error_86fcd5bb = 'error';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1187 }
  CozyText_Api_execute_2b208510 = 'execute';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:479 }
  CozyText_Api_expiresAt_519a6450 = 'expiresAt';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:913 }
  CozyText_Api_fileBlake3_a9a49431 = 'fileBlake3';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:911 }
  CozyText_Api_fileCrc64_6df83a91 = 'fileCrc64';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:911 }
  CozyText_Api_fileSha512_75b0f42d = 'fileSha512';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:913 }
  CozyText_Api_fileXxh3_128_776d82de = 'fileXxh3_128';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:468 }
  CozyText_Api_hashVersion_6d224b4f = 'hashVersion';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1211 }
  CozyText_Api_issuedAt_77d618f1 = 'issuedAt';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1906 }
  CozyText_Api_kernel32_dll_bb32e033 = 'kernel32.dll';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1210 }
  CozyText_Api_label_ebaa42f0 = 'label';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1214 }
  CozyText_Api_leaseExpiresAt_82ef4d75 = 'leaseExpiresAt';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:991 }
  CozyText_Api_licenseId_d119b21e = 'licenseId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1492 }
  CozyText_Api_licenseKey_01a73f12 = 'licenseKey';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:420 }
  CozyText_Api_machineId_3117889a = 'machineId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:668 }
  CozyText_Api_measuredModules_9b4c96c7 = 'measuredModules';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:671 }
  CozyText_Api_measurementContract_afb97f46 = 'measurementContract';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:674 }
  CozyText_Api_measurementFinishedTick_ae874b0c = 'measurementFinishedTick';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:672 }
  CozyText_Api_measurementPlanVersion_2590335d = 'measurementPlanVersion';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:673 }
  CozyText_Api_measurementStartedTick_9c04910f = 'measurementStartedTick';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:675 }
  CozyText_Api_moduleGenerationStable_bb4b09ef = 'moduleGenerationStable';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:676 }
  CozyText_Api_moduleGenerationStatus_722cc8c3 = 'moduleGenerationStatus';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:731 }
  CozyText_Api_modules_18634d83 = 'modules';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:478 }
  CozyText_Api_nonce_3c39b97d = 'nonce';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1084 }
  CozyText_Api_ok_23bc0a4e = 'ok';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:432 }
  CozyText_Api_operation_9a9df433 = 'operation';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1360 }
  CozyText_Api_overlayId_19d7deba = 'overlayId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1142 }
  CozyText_Api_overlay_78ab122b = 'overlay';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:917 }
  CozyText_Api_ownMeasurement_d9d850bd = 'ownMeasurement';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:537 }
  CozyText_Api_own_a6da0945 = 'own';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1159 }
  CozyText_Api_payloadHash_db98f451 = 'payloadHash';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1183 }
  CozyText_Api_payloadJSON_5d9b8ea1 = 'payloadJSON';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:441 }
  CozyText_Api_payload_72cc18dd = 'payload';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1158 }
  CozyText_Api_publicKey_f3142087 = 'publicKey';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:534 }
  CozyText_Api_reason_9ed63c85 = 'reason';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1188 }
  CozyText_Api_redeem_5ba76ca4 = 'redeem';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:972 }
  CozyText_Api_release_dca62424 = 'release';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:975 }
  CozyText_Api_released_64258304 = 'released';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:439 }
  CozyText_Api_reportId_a121727c = 'reportId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:432 }
  CozyText_Api_report_2eb959c9 = 'report';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1156 }
  CozyText_Api_requestId_0cae8d65 = 'requestId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1216 }
  CozyText_Api_revision_5f36f9e0 = 'revision';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:669 }
  CozyText_Api_scope_fb032832 = 'scope';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:615 }
  CozyText_Api_serverTime_ac0470bc = 'serverTime';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:418 }
  CozyText_Api_sessionId_853f6b3a = 'sessionId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:419 }
  CozyText_Api_sessionToken_1de43d9f = 'sessionToken';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:440 }
  CozyText_Api_signature_f5c615b8 = 'signature';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:610 }
  CozyText_Api_snapshotBudget_872fe930 = 'snapshotBudget';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:614 }
  CozyText_Api_snapshotId_840c328a = 'snapshotId';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:499 }
  CozyText_Api_status_5b6d5c76 = 'status';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:437 }
  CozyText_Api_submit_b60bb019 = 'submit';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:499 }
  CozyText_Api_terminate_67d71b83 = 'terminate';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:677 }
  CozyText_Api_threadInventory_267c3eb8 = 'threadInventory';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:433 }
  CozyText_Api_tlsPinVersion_0f5dfadf = 'tlsPinVersion';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:667 }
  CozyText_Api_totalModules_e6e48497 = 'totalModules';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:221 }
  CozyText_Api_true_6c21d98e = 'true';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:666 }
  CozyText_Api_truncated_744f21d1 = 'truncated';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:670 }
  CozyText_Api_trust_190cf8eb = 'trust';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:1142 }
  CozyText_Api_verify_b7cb75a0 = 'verify';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:245 }
  CozyText_Api_verify_ba43c0c6 = '서버에 저장하지 못했습니다. verify로 같은 요청을 재확인하세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:952 }
  CozyText_Api_verify_cfdb221d = '이전 인증 요청이 남아 있습니다. verify 명령으로 같은 요청을 재확인하세요.';
  { Cozy.Source/Cozy.Platform/Cozy.Api.pas:532 }
  CozyText_Api_version_edcaca86 = 'version';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:47 }
  CozyText_Clock_CLOCK_API_UNAVAILABLE_7a5d1b63 = 'CLOCK_API_UNAVAILABLE';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:64 }
  CozyText_Clock_CLOCK_COUNTER_OVERFLOW_53af3cef = 'CLOCK_COUNTER_OVERFLOW';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:136 }
  CozyText_Clock_CLOCK_FREQUENCY_INVALID_d11f427f = 'CLOCK_FREQUENCY_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:45 }
  CozyText_Clock_CLOCK_MODULE_UNAVAILABLE_5316e621 = 'CLOCK_MODULE_UNAVAILABLE';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:59 }
  CozyText_Clock_CLOCK_READ_FAILED_47bcf620 = 'CLOCK_READ_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:107 }
  CozyText_Clock_CLOCK_WAIT_FAILED_e7319768 = 'CLOCK_WAIT_FAILED';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:85 }
  CozyText_Clock_CLOCK_WAIT_UNAVAILABLE_fedfb776 = 'CLOCK_WAIT_UNAVAILABLE';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:125 }
  CozyText_Clock_CloseHandle_316c7c58 = 'CloseHandle';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:123 }
  CozyText_Clock_CreateEventW_17a9fb00 = 'CreateEventW';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:126 }
  CozyText_Clock_GetLastError_3b71a19f = 'GetLastError';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.Math.pas:16 }
  CozyText_Clock_Math_CLOCK_COUNTER_INVALID_dd6677db = 'CLOCK_COUNTER_INVALID';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.Math.pas:21 }
  CozyText_Clock_Math_CLOCK_COUNTER_OVERFLOW_9aa13e7c = 'CLOCK_COUNTER_OVERFLOW';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.Math.pas:51 }
  CozyText_Clock_Math_CLOCK_DEADLINE_OVERFLOW_bb948c48 = 'CLOCK_DEADLINE_OVERFLOW';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:121 }
  CozyText_Clock_QueryPerformanceCounter_2b979b4b = 'QueryPerformanceCounter';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:122 }
  CozyText_Clock_QueryPerformanceFrequency_649eba80 = 'QueryPerformanceFrequency';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:127 }
  CozyText_Clock_SetLastError_527b0897 = 'SetLastError';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:124 }
  CozyText_Clock_WaitForSingleObject_5ebf7fd7 = 'WaitForSingleObject';
  { Cozy.Source/Cozy.Platform/Cozy.Clock.pas:44 }
  CozyText_Clock_kernel32_dll_cc35ee58 = 'kernel32.dll';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:689 }
  CozyText_Platform_ExportResolver_API_target_module_cannot_be_retained_2b7d8286 = 'API target module cannot be retained.';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:616 }
  CozyText_Platform_ExportResolver_A_System32_DLL_basename_is_required_85e5d8f1 = 'A System32 DLL basename is required.';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:571 }
  CozyText_Platform_ExportResolver_Cannot_bootstrap_the_Windows_loader_from_loaded__85d8bcbb = 'Cannot bootstrap the Windows loader from loaded core exports.';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:553 }
  CozyText_Platform_ExportResolver_Cannot_initialize_Windows_loader_API_hash_0x_s_84d7037e = 'Cannot initialize Windows loader API hash: 0x%s';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:632 }
  CozyText_Platform_ExportResolver_Cannot_load_Windows_API_module_s_bd5421bb = 'Cannot load Windows API module: %s';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:627 }
  CozyText_Platform_ExportResolver_Cannot_locate_the_Windows_system_directory_b1493665 = 'Cannot locate the Windows system directory.';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:678 }
  CozyText_Platform_ExportResolver_Cannot_resolve_Windows_API_hash_s_0x_s_271d0985 = 'Cannot resolve Windows API hash: %s!0x%s';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:661 }
  CozyText_Platform_ExportResolver_Cannot_resolve_Windows_API_s_s_df9eac69 = 'Cannot resolve Windows API: %s!%s';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:615 }
  CozyText_Platform_ExportResolver_Text_d036592e = '..';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:702 }
  CozyText_Platform_ExportResolver_Unexpected_x64_API_resolver_record_layout_f393ad27 = 'Unexpected x64 API resolver record layout.';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:614 }
  CozyText_Platform_ExportResolver_dll_91a5217f = '.dll';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:561 }
  CozyText_Platform_ExportResolver_kernel32_dll_276e9510 = 'kernel32.dll';
  { Cozy.Source/Cozy.Platform/Cozy.Platform.ExportResolver.pas:562 }
  CozyText_Platform_ExportResolver_kernelbase_dll_4b82d848 = 'kernelbase.dll';
  { Cozy.Source/Cozy.Platform/Cozy.WinApi.pas:349 }
  CozyText_WinApi_Windows_x64_API_record_layout_mismatch_eb8eeee2 = 'Windows x64 API record layout mismatch.';

implementation
end.
