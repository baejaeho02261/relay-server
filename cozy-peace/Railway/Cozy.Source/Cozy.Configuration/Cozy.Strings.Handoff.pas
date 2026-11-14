unit Cozy.Strings.Handoff;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:942 }
  CozyText_Handoff_APPDATA_e18f8cd9 = 'APPDATA';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:943 }
  CozyText_Handoff_COMPUTERNAME_c705651c = 'COMPUTERNAME';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1417 }
  CozyText_Handoff_Cannot_complete_overlay_handoff_e26390f1 = 'Cannot complete overlay handoff.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:942 }
  CozyText_Handoff_CommonProgramFiles_4ea68291 = 'CommonProgramFiles';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:943 }
  CozyText_Handoff_CommonProgramFiles_x86_83122864 = 'CommonProgramFiles(x86)';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:576 }
  CozyText_Handoff_Crypto_0123456789ABCDEF_03b40e34 = '0123456789ABCDEF';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:342 }
  CozyText_Handoff_Crypto_AES_fc846d7d = 'AES';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:68 }
  CozyText_Handoff_Crypto_ChainingModeGCM_c260fccf = 'ChainingModeGCM';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:343 }
  CozyText_Handoff_Crypto_ChainingMode_b7a55120 = 'ChainingMode';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:69 }
  CozyText_Handoff_Crypto_GAME_HANDOFF_V3_069e73ba = 'GAME-HANDOFF-V3';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:354 }
  CozyText_Handoff_Crypto_HANDOFF_CIPHER_ABI_INVALID_08de973d = 'HANDOFF_CIPHER_ABI_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:464 }
  CozyText_Handoff_Crypto_HANDOFF_CIPHER_ALREADY_CONSUMED_971ef676 = 'HANDOFF_CIPHER_ALREADY_CONSUMED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:299 }
  CozyText_Handoff_Crypto_HANDOFF_CIPHER_CANCELLED_3b14ba85 = 'HANDOFF_CIPHER_CANCELLED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:250 }
  CozyText_Handoff_Crypto_HANDOFF_CIPHER_FAILED_ec741754 = 'HANDOFF_CIPHER_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:478 }
  CozyText_Handoff_Crypto_HANDOFF_CIPHER_HEADER_INVALID_0e24d39c = 'HANDOFF_CIPHER_HEADER_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:264 }
  CozyText_Handoff_Crypto_HANDOFF_CIPHER_KEY_INVALID_14e8e72e = 'HANDOFF_CIPHER_KEY_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:257 }
  CozyText_Handoff_Crypto_HANDOFF_CIPHER_SIZE_INVALID_3e917e7c = 'HANDOFF_CIPHER_SIZE_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:528 }
  CozyText_Handoff_Crypto_PROTECTION_CIPHER_INPUT_INVALID_8007aa94 = 'PROTECTION_CIPHER_INPUT_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:374 }
  CozyText_Handoff_Crypto_RSAPUBLICBLOB_1d6cf82c = 'RSAPUBLICBLOB';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:355 }
  CozyText_Handoff_Crypto_RSA_f7d17c25 = 'RSA';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:277 }
  CozyText_Handoff_Crypto_SHA256_66e684b3 = 'SHA256';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas:592 }
  CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6 = 'bcrypt.dll';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1664 }
  CozyText_Handoff_DELEGATION_c9c9ca0d = 'DELEGATION';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:976 }
  CozyText_Handoff_GAME_PRODUCT_FAULT_ROOT_53ff6984 = 'GAME_PRODUCT_FAULT_ROOT=';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1139 }
  CozyText_Handoff_HANDOFF_BOOTSTRAP_INVALID_517fe843 = 'HANDOFF_BOOTSTRAP_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1713 }
  CozyText_Handoff_HANDOFF_CANCELLED_008c77a9 = 'HANDOFF_CANCELLED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1238 }
  CozyText_Handoff_HANDOFF_CHILD_BINDING_INVALID_1bedf988 = 'HANDOFF_CHILD_BINDING_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1717 }
  CozyText_Handoff_HANDOFF_CHILD_EXITED_3a4d1e65 = 'HANDOFF_CHILD_EXITED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1152 }
  CozyText_Handoff_HANDOFF_ENVELOPE_SIZE_b5eadb47 = 'HANDOFF_ENVELOPE_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:964 }
  CozyText_Handoff_HANDOFF_ENVIRONMENT_CHANGED_b33d1f33 = 'HANDOFF_ENVIRONMENT_CHANGED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:961 }
  CozyText_Handoff_HANDOFF_ENVIRONMENT_INVALID_c015f407 = 'HANDOFF_ENVIRONMENT_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:989 }
  CozyText_Handoff_HANDOFF_ENVIRONMENT_TOO_LARGE_8d09471d = 'HANDOFF_ENVIRONMENT_TOO_LARGE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1048 }
  CozyText_Handoff_HANDOFF_HELLO_INVALID_3bd73add = 'HANDOFF_HELLO_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1006 }
  CozyText_Handoff_HANDOFF_HELLO_SIZE_1e8c0f1e = 'HANDOFF_HELLO_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1008 }
  CozyText_Handoff_HANDOFF_HELLO_WRITE_c5ca140e = 'HANDOFF_HELLO_WRITE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1055 }
  CozyText_Handoff_HANDOFF_NONCE_INVALID_f3730e62 = 'HANDOFF_NONCE_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1160 }
  CozyText_Handoff_HANDOFF_PAYLOAD_SIZE_c583a842 = 'HANDOFF_PAYLOAD_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1939 }
  CozyText_Handoff_HANDOFF_PIPE_FAILED_e2a9e904 = 'HANDOFF_PIPE_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1933 }
  CozyText_Handoff_HANDOFF_PIPE_TIMEOUT_59183af5 = 'HANDOFF_PIPE_TIMEOUT';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1880 }
  CozyText_Handoff_HANDOFF_PROCESS_CREATE_FAILED_ee850506 = 'HANDOFF_PROCESS_CREATE_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1723 }
  CozyText_Handoff_HANDOFF_READY_TIMEOUT_e041c0ad = 'HANDOFF_READY_TIMEOUT';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:876 }
  CozyText_Handoff_HANDOFF_READ_RANGE_INVALID_2ce37b3a = 'HANDOFF_READ_RANGE_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1827 }
  CozyText_Handoff_HANDOFF_REPLY_PIPE_CREATE_dff45df5 = 'HANDOFF_REPLY_PIPE_CREATE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1142 }
  CozyText_Handoff_HANDOFF_REPLY_PIPE_INVALID_5152c5e0 = 'HANDOFF_REPLY_PIPE_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1828 }
  CozyText_Handoff_HANDOFF_REPLY_PIPE_PROTECT_c587b148 = 'HANDOFF_REPLY_PIPE_PROTECT';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1802 }
  CozyText_Handoff_HANDOFF_RESTRICTED_PROFILE_O_ONLY_f244533e = 'HANDOFF_RESTRICTED_PROFILE_O_ONLY';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:971 }
  CozyText_Handoff_HANDOFF_SYSTEM_ROOT_REQUIRED_11654d87 = 'HANDOFF_SYSTEM_ROOT_REQUIRED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1085 }
  CozyText_Handoff_HANDOFF_TRANSCRIPT_INVALID_575081d0 = 'HANDOFF_TRANSCRIPT_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1714 }
  CozyText_Handoff_HANDOFF_WAIT_FAILED_f021a214 = 'HANDOFF_WAIT_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1721 }
  CozyText_Handoff_HANDOFF_WAIT_HANDLE_INVALID_29420634 = 'HANDOFF_WAIT_HANDLE_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1508 }
  CozyText_Handoff_Image_integrity_evidence_is_unavailable_09d8ad23 = 'Image integrity evidence is unavailable.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1346 }
  CozyText_Handoff_Independent_image_integrity_binding_changed_dfe83f8d = 'Independent image integrity binding changed.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1376 }
  CozyText_Handoff_Invalid_overlay_handoff_state_d66122e9 = 'Invalid overlay handoff state.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1434 }
  CozyText_Handoff_Invalid_parent_retirement_4789b7a0 = 'Invalid parent retirement.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Kdf.pas:34 }
  CozyText_Handoff_Kdf_Invalid_handoff_key_derivation_input_997b0e1e = 'Invalid handoff key derivation input.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Kdf.pas:27 }
  CozyText_Handoff_Kdf_cozy_Client_Handoff_V3_AES256GCM_ContentKey_v1_65f49ab9 = 'cozy.Client.Handoff.V3.AES256GCM.ContentKey.v1';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:943 }
  CozyText_Handoff_LOCALAPPDATA_811c5840 = 'LOCALAPPDATA';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:934 }
  CozyText_Handoff_NUL_129b6eb6 = '실행 연결 문자열에 NUL이 있습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:944 }
  CozyText_Handoff_NUMBER_OF_PROCESSORS_dc92622b = 'NUMBER_OF_PROCESSORS';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:944 }
  CozyText_Handoff_OS_a4cb0728 = 'OS';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1416 }
  CozyText_Handoff_Overlay_authorization_cannot_complete_ef5fe7de = 'Overlay authorization cannot complete.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1269 }
  CozyText_Handoff_Overlay_handoff_cannot_retire_its_parent_605694a6 = 'Overlay handoff cannot retire its parent.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1391 }
  CozyText_Handoff_Overlay_image_binding_changed_00c4ca6b = 'Overlay image binding changed.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1437 }
  CozyText_Handoff_Overlay_parent_has_not_exited_ace1a391 = 'Overlay parent has not exited.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1380 }
  CozyText_Handoff_Overlay_parent_is_unavailable_cdd05f72 = 'Overlay parent is unavailable.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1382 }
  CozyText_Handoff_Overlay_process_binding_changed_bdd16710 = 'Overlay process binding changed.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:972 }
  CozyText_Handoff_PATH_d58a596b = 'PATH=';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:944 }
  CozyText_Handoff_PROCESSOR_ARCHITECTURE_e086747d = 'PROCESSOR_ARCHITECTURE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:716 }
  CozyText_Handoff_Pinned_image_sharing_is_read_only_dde66996 = 'Pinned image sharing is read-only.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:944 }
  CozyText_Handoff_ProgramData_3131e9cd = 'ProgramData';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:945 }
  CozyText_Handoff_ProgramFiles_5920380c = 'ProgramFiles';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:945 }
  CozyText_Handoff_ProgramFiles_x86_30fc5f6e = 'ProgramFiles(x86)';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:292 }
  CozyText_Handoff_Restricted_OVERLAY_CHILD_PROCESS_SLOT_NOT_EMPTY_2feb45fd = 'OVERLAY_CHILD_PROCESS_SLOT_NOT_EMPTY';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:281 }
  CozyText_Handoff_Restricted_OVERLAY_CHILD_TOKEN_OPEN_FAILED_a5f6a97d = 'OVERLAY_CHILD_TOKEN_OPEN_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:169 }
  CozyText_Handoff_Restricted_OVERLAY_INTERACTIVE_SESSION_REQUIRED_89fe3012 = 'OVERLAY_INTERACTIVE_SESSION_REQUIRED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:302 }
  CozyText_Handoff_Restricted_OVERLAY_RESTRICTED_PROCESS_CREATE_FAILED_2a7f139c = 'OVERLAY_RESTRICTED_PROCESS_CREATE_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:307 }
  CozyText_Handoff_Restricted_OVERLAY_RESTRICTED_PROCESS_RESUME_FAILED_78ff7ef9 = 'OVERLAY_RESTRICTED_PROCESS_RESUME_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:256 }
  CozyText_Handoff_Restricted_OVERLAY_RESTRICTED_TOKEN_CREATE_FAILED_eb9f1925 = 'OVERLAY_RESTRICTED_TOKEN_CREATE_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:177 }
  CozyText_Handoff_Restricted_OVERLAY_SERVICE_ACCOUNT_FORBIDDEN_b36f02e1 = 'OVERLAY_SERVICE_ACCOUNT_FORBIDDEN';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:247 }
  CozyText_Handoff_Restricted_OVERLAY_SOURCE_INTEGRITY_UNSUPPORTED_a8f84778 = 'OVERLAY_SOURCE_INTEGRITY_UNSUPPORTED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:244 }
  CozyText_Handoff_Restricted_OVERLAY_SOURCE_TOKEN_OPEN_FAILED_7e48ef01 = 'OVERLAY_SOURCE_TOKEN_OPEN_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:294 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_ABI_UNSUPPORTED_73e1f72d = 'OVERLAY_TOKEN_ABI_UNSUPPORTED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:198 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_GROUPS_BOUNDS_781fd6ef = 'OVERLAY_TOKEN_GROUPS_BOUNDS';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:194 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_GROUPS_SIZE_6eeab213 = 'OVERLAY_TOKEN_GROUPS_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:264 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_INTEGRITY_CAP_FAILED_fcfe9c04 = 'OVERLAY_TOKEN_INTEGRITY_CAP_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:187 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_INTEGRITY_TOO_HIGH_b5438147 = 'OVERLAY_TOKEN_INTEGRITY_TOO_HIGH';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:160 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_LABEL_INVALID_3d59098a = 'OVERLAY_TOKEN_LABEL_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:156 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_LABEL_SIZE_b8740861 = 'OVERLAY_TOKEN_LABEL_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:210 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGED_GROUP_ed415f8a = 'OVERLAY_TOKEN_PRIVILEGED_GROUP';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:219 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGES_REMAIN_931f9f76 = 'OVERLAY_TOKEN_PRIVILEGES_REMAIN';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:215 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGES_SIZE_d86f74ca = 'OVERLAY_TOKEN_PRIVILEGES_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:213 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGE_LOOKUP_04439171 = 'OVERLAY_TOKEN_PRIVILEGE_LOOKUP';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:125 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_QUERY_FAILED_2f9561d2 = 'OVERLAY_TOKEN_QUERY_FAILED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:120 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_QUERY_SIZE_b4b9ec0c = 'OVERLAY_TOKEN_QUERY_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:139 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_COUNT_e6345cd2 = 'OVERLAY_TOKEN_SID_COUNT';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:133 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_INVALID_1673534c = 'OVERLAY_TOKEN_SID_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:136 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_RANGE_4a069d82 = 'OVERLAY_TOKEN_SID_RANGE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:137 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_REVISION_1b722121 = 'OVERLAY_TOKEN_SID_REVISION';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:190 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_STILL_ELEVATED_d3c6ac90 = 'OVERLAY_TOKEN_STILL_ELEVATED';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:171 }
  CozyText_Handoff_Restricted_OVERLAY_TOKEN_USER_SIZE_5911f8b8 = 'OVERLAY_TOKEN_USER_SIZE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:213 }
  CozyText_Handoff_Restricted_SeChangeNotifyPrivilege_487ec2fd = 'SeChangeNotifyPrivilege';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:312 }
  CozyText_Handoff_Restricted_advapi32_dll_08b0e050 = 'advapi32.dll';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas:317 }
  CozyText_Handoff_Restricted_kernel32_dll_bb8acc01 = 'kernel32.dll';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:945 }
  CozyText_Handoff_SESSIONNAME_2b72395f = 'SESSIONNAME';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1545 }
  CozyText_Handoff_Shutdown_image_identity_changed_1e844966 = 'Shutdown image identity changed.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:972 }
  CozyText_Handoff_System32_680269e8 = 'System32;';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:945 }
  CozyText_Handoff_SystemDrive_e676e146 = 'SystemDrive';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:946 }
  CozyText_Handoff_SystemRoot_2a19f8f4 = 'SystemRoot';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:946 }
  CozyText_Handoff_TEMP_0e40382f = 'TEMP';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:946 }
  CozyText_Handoff_TMP_61eb352a = 'TMP';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:858 }
  CozyText_Handoff_Text_004d804d = '실행 연결 핸들이 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1855 }
  CozyText_Handoff_Text_00ca898c = '실행 핸들 목록 크기가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:844 }
  CozyText_Handoff_Text_07314e95 = '실행 인수가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:611 }
  CozyText_Handoff_Text_0790dacf = '실행 파일 경로가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:908 }
  CozyText_Handoff_Text_0cfe59f1 = '실행 연결이 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:744 }
  CozyText_Handoff_Text_0e151eab = '실행 파일의 실제 경로가 다릅니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:790 }
  CozyText_Handoff_Text_124d511d = '현재 실행 파일의 고유 정보 또는 내용이 변경되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:740 }
  CozyText_Handoff_Text_1908b783 = '연결된 실행 파일은 사용할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:785 }
  CozyText_Handoff_Text_1bfbe90b = '현재 실행 파일만 정리할 수 있습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1834 }
  CozyText_Handoff_Text_1fe10888 = '시작 프로그램의 제한된 핸들을 만들 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:628 }
  CozyText_Handoff_Text_2119f2e8 = '로컬 드라이브의 실행 파일만 사용할 수 있습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:881 }
  CozyText_Handoff_Text_2669e92a = '실행 연결이 중단되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:926 }
  CozyText_Handoff_Text_28293dcb = '실행 연결 데이터가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1129 }
  CozyText_Handoff_Text_2f24cd32 = '상속된 실행 파이프가 필요합니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1297 }
  CozyText_Handoff_Text_2fe42bc6 = '실행 파일의 내용이 변경되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:831 }
  CozyText_Handoff_Text_342e0cc0 = '현재 실행 파일의 고유 정보가 변경되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1124 }
  CozyText_Handoff_Text_3a3af42f = '이 실행 파일은 시작 프로그램을 통해 실행해야 합니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1803 }
  CozyText_Handoff_Text_3eb70708 = '실행 연결 정보가 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1678 }
  CozyText_Handoff_Text_40b4f5b2 = '실행 연결 데이터가 너무 큽니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1234 }
  CozyText_Handoff_Text_41951c88 = '시작 프로그램의 고유 정보 또는 해시가 일치하지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1306 }
  CozyText_Handoff_Text_47ff511a = '시작 프로그램이 종료되지 않아 안전하게 정리할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1226 }
  CozyText_Handoff_Text_4a46bfee = '실행 파일의 해시가 일치하지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:692 }
  CozyText_Handoff_Text_4bf4af98 = '실행 폴더를 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:640 }
  CozyText_Handoff_Text_4edbaa9f = '..';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1824 }
  CozyText_Handoff_Text_5442867f = '실행 파이프를 만들 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1284 }
  CozyText_Handoff_Text_56363717 = '정리할 시작 프로그램의 위치가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1196 }
  CozyText_Handoff_Text_5906b045 = '시작 프로그램의 프로세스가 일치하지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:734 }
  CozyText_Handoff_Text_5a82a889 = '실행 파일을 안전하게 열 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:879 }
  CozyText_Handoff_Text_5c2f7171 = '실행 연결 수신 시간이 초과되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1300 }
  CozyText_Handoff_Text_645b04e0 = '시작 프로그램에 완료를 알릴 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:736 }
  CozyText_Handoff_Text_65a263d5 = '실행 파일 형식이 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1169 }
  CozyText_Handoff_Text_67dc1d83 = '실행 연결에 필수 정보가 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1819 }
  CozyText_Handoff_Text_688dca9d = '실행 파일의 해시가 변경되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:636 }
  CozyText_Handoff_Text_70b64acc = '실행 파일 경로에 허용되지 않는 문자가 있습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1180 }
  CozyText_Handoff_Text_77a22930 = '실행 연결 항목 크기가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1830 }
  CozyText_Handoff_Text_77cbc404 = '실행 완료 이벤트를 만들 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1278 }
  CozyText_Handoff_Text_7e4d1518 = '시작 프로그램이 실행 연결을 기다리지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:862 }
  CozyText_Handoff_Text_7efa7748 = '실행 연결을 보호할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:641 }
  CozyText_Handoff_Text_81460d90 = '실행 파일 경로에 별칭을 사용할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1294 }
  CozyText_Handoff_Text_85899adf = '정리할 시작 프로그램의 고유 정보가 일치하지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:913 }
  CozyText_Handoff_Text_873ccf4f = '실행 연결에 불필요한 데이터가 있습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:698 }
  CozyText_Handoff_Text_8950df3f = '실행 폴더의 실제 경로가 다릅니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1219 }
  CozyText_Handoff_Text_91b750f0 = '실행 파일과 시작 프로그램은 같은 폴더의 서로 다른 파일이어야 합니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:737 }
  CozyText_Handoff_Text_94669c37 = '실행 파일을 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:689 }
  CozyText_Handoff_Text_979346f7 = '실행 폴더를 안전하게 열 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1172 }
  CozyText_Handoff_Text_979c85bf = '실행 연결 크기가 일치하지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:929 }
  CozyText_Handoff_Text_997ae802 = '실행 연결 문자열이 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:743 }
  CozyText_Handoff_Text_9ceaeb61 = '실행 파일의 고유 정보를 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:813 }
  CozyText_Handoff_Text_a531ea32 = '실행 파일 정리가 완료되지 않았습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:860 }
  CozyText_Handoff_Text_a613a0fb = '상속된 실행 연결이 필요합니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:665 }
  CozyText_Handoff_Text_a65e9fc3 = '\\?\';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1222 }
  CozyText_Handoff_Text_a8f85391 = '실행 중인 프로그램의 경로가 일치하지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1316 }
  CozyText_Handoff_Text_b084e304 = '종료된 시작 프로그램의 정보가 변경되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1165 }
  CozyText_Handoff_Text_b40b884f = '실행 연결 헤더가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:663 }
  CozyText_Handoff_Text_b54b72de = '파일의 실제 경로를 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1927 }
  CozyText_Handoff_Text_b576dd8a = '실행 연결 전송을 시작할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1816 }
  CozyText_Handoff_Text_b5fb5dfb = '시작 프로그램을 실행 파일로 사용할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:800 }
  CozyText_Handoff_Text_bc0ad16e = '현재 실행 파일을 안전하게 정리할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1862 }
  CozyText_Handoff_Text_be913fa0 = '실행 핸들 상속을 제한할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:695 }
  CozyText_Handoff_Text_bfe20937 = '연결된 폴더에서는 실행할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:890 }
  CozyText_Handoff_Text_c4279bb6 = '실행 연결을 읽을 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1811 }
  CozyText_Handoff_Text_c4ea254a = '실행 파일은 시작 프로그램과 같은 폴더에 있어야 합니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1858 }
  CozyText_Handoff_Text_c5ff6d0b = '실행 핸들 목록을 초기화할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:933 }
  CozyText_Handoff_Text_c6124ad9 = '실행 연결 문자열을 읽을 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:651 }
  CozyText_Handoff_Text_c6191033 = '실행 파일의 전체 경로를 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1324 }
  CozyText_Handoff_Text_caa1db3a = '시작 프로그램을 안전하게 정리할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1281 }
  CozyText_Handoff_Text_cf8d7197 = '실행 중인 프로그램의 경로가 변경되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1826 }
  CozyText_Handoff_Text_d05ccac1 = '실행 파이프를 보호할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1488 }
  CozyText_Handoff_Text_dbd1685a = '실행 연결이 완료되지 않았습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:768 }
  CozyText_Handoff_Text_e5593090 = '실행 파일 해시가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:653 }
  CozyText_Handoff_Text_ebbcdf1a = '실행 파일 경로가 정규화되어 있지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:610 }
  CozyText_Handoff_Text_f2c2b692 = '실행 파일 경로를 확인할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1912 }
  CozyText_Handoff_Text_f8b08cd1 = '실행 전송 취소 이벤트를 만들 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1199 }
  CozyText_Handoff_Text_f935adb6 = '시작 프로그램이 더 이상 대기 중이 아닙니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1916 }
  CozyText_Handoff_Text_f98304bb = '실행 전송 이벤트를 복제할 수 없습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:904 }
  CozyText_Handoff_Text_f9b96a69 = '실행 연결 종료 시간이 초과되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1270 }
  CozyText_Handoff_Text_ff81ad00 = '실행 연결은 이미 완료되었습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1468 }
  CozyText_Handoff_Transferred_parent_cleanup_failed_c5482baa = 'Transferred parent cleanup failed.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1461 }
  CozyText_Handoff_Transferred_parent_cleanup_identity_changed_87d48ded = 'Transferred parent cleanup identity changed.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1453 }
  CozyText_Handoff_Transferred_parent_identity_changed_ec563a87 = 'Transferred parent identity changed.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:946 }
  CozyText_Handoff_USERDOMAIN_ffb263cc = 'USERDOMAIN';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:946 }
  CozyText_Handoff_USERNAME_f9d6a799 = 'USERNAME';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:946 }
  CozyText_Handoff_USERPROFILE_27d9a131 = 'USERPROFILE';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:573 }
  CozyText_Handoff_Windows_64_9f8cb582 = 'Windows 64비트 실행 구조가 올바르지 않습니다.';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1867 }
  CozyText_Handoff_game_handoff_2077ff3a = '" --game-handoff ';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:867 }
  CozyText_Handoff_game_handoff_43b89bd7 = '--game-handoff';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1865 }
  CozyText_Handoff_game_overlay_bd4c3917 = '" --game-overlay ';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1123 }
  CozyText_Handoff_game_overlay_c16e7097 = '--game-overlay';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1922 }
  CozyText_Handoff_handoff_body_ab_a5d31a28 = 'handoff-body-ab';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:1921 }
  CozyText_Handoff_handoff_body_bo_d217df46 = 'handoff-body-bo';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:2070 }
  CozyText_Handoff_kernel32_dll_74783ecd = 'kernel32.dll';
  { Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas:974 }
  CozyText_Handoff_windir_105c0036 = 'windir=';
  { Cozy.Source/Cozy.Handoff/Cozy.JsonEnvelope.pas:29 }
  CozyText_JsonEnvelope_JsonFixture_fbede879 = '{"operation":"';
  { Cozy.Source/Cozy.Handoff/Cozy.JsonEnvelope.pas:19 }
  CozyText_JsonEnvelope_REQUEST_ENVELOPE_ARGUMENT_03c057bd = 'REQUEST_ENVELOPE_ARGUMENT';
  { Cozy.Source/Cozy.Handoff/Cozy.JsonEnvelope.pas:32 }
  CozyText_JsonEnvelope_REQUEST_ENVELOPE_LIMIT_7d84dcd8 = 'REQUEST_ENVELOPE_LIMIT';
  { Cozy.Source/Cozy.Handoff/Cozy.JsonEnvelope.pas:29 }
  CozyText_JsonEnvelope_tlsPinVersion_1_body_54e32be7 = '","tlsPinVersion":1,"body":';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:52 }
  CozyText_ProtocolJson_PROTOCOL_JSON_INVALID_c3741c2d = 'PROTOCOL_JSON_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:219 }
  CozyText_ProtocolJson_PROTOCOL_SCHEMA_INVALID_ad38e3a7 = 'PROTOCOL_SCHEMA_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:33 }
  CozyText_ProtocolJson_PROTOCOL_UTF8_INVALID_fd8d9d7f = 'PROTOCOL_UTF8_INVALID';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:361 }
  CozyText_ProtocolJson_action_e06f26e2 = 'action';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:324 }
  CozyText_ProtocolJson_allOrNone_e2d92130 = 'allOrNone';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:250 }
  CozyText_ProtocolJson_anyOf_78bd2974 = 'anyOf';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:301 }
  CozyText_ProtocolJson_array_1bfa66e4 = 'array';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:369 }
  CozyText_ProtocolJson_body_f06ac25c = 'body';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:363 }
  CozyText_ProtocolJson_commands_3268d067 = 'commands';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:183 }
  CozyText_ProtocolJson_constructor_214dce11 = 'constructor';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:246 }
  CozyText_ProtocolJson_definitions_73e05fa3 = 'definitions';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:346 }
  CozyText_ProtocolJson_documents_42e76750 = 'documents';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:265 }
  CozyText_ProtocolJson_enum_445c81f9 = 'enum';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:378 }
  CozyText_ProtocolJson_envelope_f6c56618 = 'envelope';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:331 }
  CozyText_ProtocolJson_exactlyOne_edc3fa73 = 'exactlyOne';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:158 }
  CozyText_ProtocolJson_false_f39810a9 = 'false';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:294 }
  CozyText_ProtocolJson_integer_86575e9c = 'integer';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:306 }
  CozyText_ProtocolJson_items_b1becea9 = 'items';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:283 }
  CozyText_ProtocolJson_maxBytes_382f1471 = 'maxBytes';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:304 }
  CozyText_ProtocolJson_maxItems_396efcf6 = 'maxItems';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:281 }
  CozyText_ProtocolJson_maxLength_1bc84f8d = 'maxLength';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:299 }
  CozyText_ProtocolJson_maximum_a222126b = 'maximum';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:279 }
  CozyText_ProtocolJson_minLength_67c89d4a = 'minLength';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:298 }
  CozyText_ProtocolJson_minimum_17f90ec0 = 'minimum';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:159 }
  CozyText_ProtocolJson_null_63843753 = 'null';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:308 }
  CozyText_ProtocolJson_object_ef053355 = 'object';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:367 }
  CozyText_ProtocolJson_operation_48c2bf10 = 'operation';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:285 }
  CozyText_ProtocolJson_pattern_358b2f19 = 'pattern';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:311 }
  CozyText_ProtocolJson_properties_e0f18dec = 'properties';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:183 }
  CozyText_ProtocolJson_proto_7538e122 = '__proto__';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:184 }
  CozyText_ProtocolJson_prototype_721ca8c8 = 'prototype';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:243 }
  CozyText_ProtocolJson_ref_dbc6f224 = '$ref';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:320 }
  CozyText_ProtocolJson_required_c238e75f = 'required';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:291 }
  CozyText_ProtocolJson_s_S_00d4b003 = '(?![\s\S])';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:275 }
  CozyText_ProtocolJson_string_24371e40 = 'string';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:157 }
  CozyText_ProtocolJson_true_cee8b631 = 'true';
  { Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas:273 }
  CozyText_ProtocolJson_type_5eaaf2e7 = 'type';

implementation
end.
