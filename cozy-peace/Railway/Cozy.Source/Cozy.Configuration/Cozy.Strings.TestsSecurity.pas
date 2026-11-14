unit Cozy.Strings.TestsSecurity;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:145 }
  CozyText_DeviceSecurityOwnedProbe_ALTERED_DIGEST_ACCEPTED_d932b753 = 'ALTERED_DIGEST_ACCEPTED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:29 }
  CozyText_DeviceSecurityOwnedProbe_API_SENSITIVE_VIEW_REVOKED_cd75fcaa = 'API_SENSITIVE_VIEW_REVOKED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:160 }
  CozyText_DeviceSecurityOwnedProbe_CALLER_TEXT_MUTATED_b5020c9b = 'CALLER_TEXT_MUTATED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:138 }
  CozyText_DeviceSecurityOwnedProbe_CANONICAL_BASE64_bfe5076f = 'CANONICAL_BASE64';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:191 }
  CozyText_DeviceSecurityOwnedProbe_CLAIM_50a56d67 = 'CLAIM';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:226 }
  CozyText_DeviceSecurityOwnedProbe_CLOSED_SIGNER_REUSED_be432859 = 'CLOSED_SIGNER_REUSED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:217 }
  CozyText_DeviceSecurityOwnedProbe_CLOSE_DID_NOT_DRAIN_ADMITTED_SIGNER_1144c4c7 = 'CLOSE_DID_NOT_DRAIN_ADMITTED_SIGNER';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:220 }
  CozyText_DeviceSecurityOwnedProbe_CLOSE_DID_NOT_JOIN_281b3a08 = 'CLOSE_DID_NOT_JOIN';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:223 }
  CozyText_DeviceSecurityOwnedProbe_CLOSE_FAILED_26fb6790 = 'CLOSE_FAILED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:216 }
  CozyText_DeviceSecurityOwnedProbe_CLOSE_NOT_OBSERVED_8a1d3ca3 = 'CLOSE_NOT_OBSERVED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:222 }
  CozyText_DeviceSecurityOwnedProbe_CLOSE_PUBLISHED_SIGNATURE_00e3b8f3 = 'CLOSE_PUBLISHED_SIGNATURE';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:188 }
  CozyText_DeviceSecurityOwnedProbe_DELEGATION_e23dd667 = 'DELEGATION';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:240 }
  CozyText_DeviceSecurityOwnedProbe_FAIL_bafd246a = 'FAIL: ';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:167 }
  CozyText_DeviceSecurityOwnedProbe_FAULT_PUBLISHED_SIGNATURE_1c8d4abb = 'FAULT_PUBLISHED_SIGNATURE';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:197 }
  CozyText_DeviceSecurityOwnedProbe_HANDOFF_LIVE_BINDING_NOT_CLEARED_59564f6a = 'HANDOFF_LIVE_BINDING_NOT_CLEARED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:161 }
  CozyText_DeviceSecurityOwnedProbe_MISSING_REAL_SIGN_STAGES_fec1001b = 'MISSING_REAL_SIGN_STAGES';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:222 }
  CozyText_DeviceSecurityOwnedProbe_OBJECT_CLOSING_3a6c16dc = 'OBJECT_CLOSING';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:173 }
  CozyText_DeviceSecurityOwnedProbe_OVERSIZE_REACHED_SIGNER_278f5a6c = 'OVERSIZE_REACHED_SIGNER';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:194 }
  CozyText_DeviceSecurityOwnedProbe_OWNED_CANONICAL_CHANGED_WIRE_SIGNATURE_cd4931bb = 'OWNED_CANONICAL_CHANGED_WIRE_SIGNATURE';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:239 }
  CozyText_DeviceSecurityOwnedProbe_PASS_7004e6d5 = 'PASS: ';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:88 }
  CozyText_DeviceSecurityOwnedProbe_PROBE_BLOCK_TIMEOUT_1d52981a = 'PROBE_BLOCK_TIMEOUT';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:24 }
  CozyText_DeviceSecurityOwnedProbe_PROBE_CNG_FAILED_f3dbe44e = 'PROBE_CNG_FAILED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:84 }
  CozyText_DeviceSecurityOwnedProbe_PROBE_INJECTED_FAILURE_acc05bdc = 'PROBE_INJECTED_FAILURE';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:143 }
  CozyText_DeviceSecurityOwnedProbe_REAL_CNG_SIGNATURE_VERIFY_5ee10da8 = 'REAL_CNG_SIGNATURE_VERIFY';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:141 }
  CozyText_DeviceSecurityOwnedProbe_RSAPUBLICBLOB_3369ee46 = 'RSAPUBLICBLOB';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:140 }
  CozyText_DeviceSecurityOwnedProbe_RSA_06de8397 = 'RSA';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:30 }
  CozyText_DeviceSecurityOwnedProbe_SCOPED_VIEW_NOT_REVOKED_c75022df = 'SCOPED_VIEW_NOT_REVOKED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:142 }
  CozyText_DeviceSecurityOwnedProbe_SHA256_7da5b670 = 'SHA256';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:137 }
  CozyText_DeviceSecurityOwnedProbe_SIGNATURE_WIDTH_6bcd16aa = 'SIGNATURE_WIDTH';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:219 }
  CozyText_DeviceSecurityOwnedProbe_SIGNER_DID_NOT_STOP_3246afb3 = 'SIGNER_DID_NOT_STOP';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:211 }
  CozyText_DeviceSecurityOwnedProbe_SIGN_STAGE_NOT_REACHED_ae8ad70b = 'SIGN_STAGE_NOT_REACHED';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:158 }
  CozyText_DeviceSecurityOwnedProbe_Text_a68b698f = '서명 입력 ';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:225 }
  CozyText_DeviceSecurityOwnedProbe_afterclose_aa3fb467 = 'afterclose';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:186 }
  CozyText_DeviceSecurityOwnedProbe_bounded_claim_08884e4a = 'bounded 한국어 claim ';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:111 }
  CozyText_DeviceSecurityOwnedProbe_native_concurrent_signing_3b76469b = 'native concurrent signing 한글';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:239 }
  CozyText_DeviceSecurityOwnedProbe_real_CNG_ownership_wire_and_Close_drain_checks_n_1b4a49d2 = ' real CNG ownership, wire and Close-drain checks; no server authorization claimed.';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:82 }
  CozyText_DeviceSecurityOwnedProbe_sign_digest_208df152 = 'sign-digest';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:81 }
  CozyText_DeviceSecurityOwnedProbe_sign_input_a1ee8699 = 'sign-input';
  { Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr:83 }
  CozyText_DeviceSecurityOwnedProbe_sign_signature_c8b7f2e2 = 'sign-signature';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:59 }
  CozyText_HardeningContractsProbe_CREATE_d99e0519 = 'CREATE';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:68 }
  CozyText_HardeningContractsProbe_CreateSymbolicLinkW_6204ea6c = 'CreateSymbolicLinkW';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:200 }
  CozyText_HardeningContractsProbe_FILE_CHANGED_7c4806be = 'FILE_CHANGED';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:97 }
  CozyText_HardeningContractsProbe_GameMeasurement_ac1aabf4 = 'GameMeasurement-';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:179 }
  CozyText_HardeningContractsProbe_GameOwnInventory_4b8ff380 = 'GameOwnInventory-';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:9 }
  CozyText_HardeningContractsProbe_HARDENING_PROBE_85d59f65 = 'HARDENING_PROBE: ';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:21 }
  CozyText_HardeningContractsProbe_JsonFixture_0423f79a = '{"a":[1,]}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:20 }
  CozyText_HardeningContractsProbe_JsonFixture_12aee432 = '{"a":"\udc00"}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:19 }
  CozyText_HardeningContractsProbe_JsonFixture_299ab5bc = '{"a":1} trailing';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:20 }
  CozyText_HardeningContractsProbe_JsonFixture_736bbd61 = '{"a":1e999}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:19 }
  CozyText_HardeningContractsProbe_JsonFixture_78b45de0 = '{"a":9007199254740992}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:20 }
  CozyText_HardeningContractsProbe_JsonFixture_8de94da7 = '{"__proto__":{}}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:30 }
  CozyText_HardeningContractsProbe_JsonFixture_ad28054e = '{"a":9007199254740991,"b":"\ud83d\ude00","c":[true,null,-1.5]}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:19 }
  CozyText_HardeningContractsProbe_JsonFixture_afd1e590 = '{"a":1,}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:18 }
  CozyText_HardeningContractsProbe_JsonFixture_b68ecaab = '{"a":1,"\u0061":2}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:19 }
  CozyText_HardeningContractsProbe_JsonFixture_be3e708c = '{"a":01}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:18 }
  CozyText_HardeningContractsProbe_JsonFixture_c7282ffd = '{"a":1,"a":2}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:20 }
  CozyText_HardeningContractsProbe_JsonFixture_cdc0251a = '{"a":"\ud800"}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:21 }
  CozyText_HardeningContractsProbe_JsonFixture_eb26c36a = '{"a":undefined}';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:193 }
  CozyText_HardeningContractsProbe_MATCH_LOCAL_FILE_c0e24f41 = 'MATCH_LOCAL_FILE';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:149 }
  CozyText_HardeningContractsProbe_NOT_RUN_kernel_slow_I_O_fault_injection_see_comp_1d643cac = 'NOT_RUN kernel slow-I/O fault injection: see compatibility matrix';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:59 }
  CozyText_HardeningContractsProbe_OOM_76bcf97c = 'OOM';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:60 }
  CozyText_HardeningContractsProbe_OVERLAY_GRAPHICS_DEVICE_LOST_5c9cd7b1 = 'OVERLAY_GRAPHICS_DEVICE_LOST';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:59 }
  CozyText_HardeningContractsProbe_OVERLAY_GRAPHICS_OUT_OF_MEMORY_46ff7b8b = 'OVERLAY_GRAPHICS_OUT_OF_MEMORY';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:61 }
  CozyText_HardeningContractsProbe_OVERLAY_GRAPHICS_RESIZE_FAILED_af42921c = 'OVERLAY_GRAPHICS_RESIZE_FAILED';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:55 }
  CozyText_HardeningContractsProbe_OVERLAY_LEASE_EXPIRED_04786cd2 = 'OVERLAY_LEASE_EXPIRED';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:44 }
  CozyText_HardeningContractsProbe_OVERLAY_STATE_TRANSITION_INVALID_cc05d4a3 = 'OVERLAY_STATE_TRANSITION_INVALID';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:202 }
  CozyText_HardeningContractsProbe_PARTIAL_064ea338 = 'PARTIAL';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:15 }
  CozyText_HardeningContractsProbe_PASS_3ad6f8f9 = 'PASS ';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:125 }
  CozyText_HardeningContractsProbe_PASS_original_duplicate_shared_position_and_simu_15766a9a = 'PASS original/duplicate shared position and simultaneous independent hashing';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:139 }
  CozyText_HardeningContractsProbe_PASS_pinned_file_rename_replacement_and_parent_p_17b7c60c = 'PASS pinned file rename, replacement and parent path replacement';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:87 }
  CozyText_HardeningContractsProbe_PASS_reparse_point_rejection_at_retained_image_b_afb06632 = 'PASS reparse-point rejection at retained image boundary';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:203 }
  CozyText_HardeningContractsProbe_PASS_retained_own_image_inventory_rename_replace_5d5086b5 = 'PASS retained own-image inventory rename, replacement, fresh mutation and partial coverage';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:62 }
  CozyText_HardeningContractsProbe_PASS_strict_JSON_UTF8_all_36_lifecycle_edges_lea_b64d21b0 = 'PASS strict JSON, UTF8, all 36 lifecycle edges, lease and graphics classification';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:60 }
  CozyText_HardeningContractsProbe_PRESENT_8f9f35ad = 'PRESENT';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:61 }
  CozyText_HardeningContractsProbe_RESIZE_0fdaf193 = 'RESIZE';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:76 }
  CozyText_HardeningContractsProbe_Reparse_fixture_creation_failed_ff56a661 = 'Reparse fixture creation failed: ';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:69 }
  CozyText_HardeningContractsProbe_SKIP_reparse_probe_API_unavailable_17d58ae8 = 'SKIP reparse probe: API unavailable';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:74 }
  CozyText_HardeningContractsProbe_SKIP_reparse_probe_enable_Developer_Mode_or_syml_6f432b79 = 'SKIP reparse probe: enable Developer Mode or symlink privilege';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:212 }
  CozyText_HardeningContractsProbe_Text_b8c6e1e4 = ': ';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:192 }
  CozyText_HardeningContractsProbe_UNVERIFIED_BASELINE_bf5c9a55 = 'UNVERIFIED_BASELINE';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:15 }
  CozyText_HardeningContractsProbe_accepted_5ca538b3 = ': accepted';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:98 }
  CozyText_HardeningContractsProbe_active_15f2df72 = 'active';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:127 }
  CozyText_HardeningContractsProbe_byte_budget_32bab082 = 'byte budget';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:129 }
  CozyText_HardeningContractsProbe_cancel_budget_c53d8658 = 'cancel budget';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:144 }
  CozyText_HardeningContractsProbe_changed_file_distinct_status_806a0946 = 'changed file distinct status';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:193 }
  CozyText_HardeningContractsProbe_codeStatus_5ae65f34 = 'codeStatus';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:123 }
  CozyText_HardeningContractsProbe_concurrent_duplicate_read_e5edc82e = 'concurrent duplicate read';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:124 }
  CozyText_HardeningContractsProbe_concurrent_position_568811bd = 'concurrent position';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:202 }
  CozyText_HardeningContractsProbe_coverage_5239c623 = 'coverage';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:131 }
  CozyText_HardeningContractsProbe_deadline_budget_34c2b245 = 'deadline budget';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:60 }
  CozyText_HardeningContractsProbe_device_lost_6102366b = 'device lost';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:107 }
  CozyText_HardeningContractsProbe_duplicate_332b360d = 'duplicate';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:169 }
  CozyText_HardeningContractsProbe_duplicate_own_inventory_row_eff32df4 = 'duplicate own inventory row';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:58 }
  CozyText_HardeningContractsProbe_expired_lease_dfc46a97 = 'expired lease';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:202 }
  CozyText_HardeningContractsProbe_failed_retained_row_claimed_full_coverage_7cff23a1 = 'failed retained row claimed full coverage';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:201 }
  CozyText_HardeningContractsProbe_failed_retained_row_reused_old_digest_6562176d = 'failed retained row reused old digest';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:194 }
  CozyText_HardeningContractsProbe_fileSha512_97bce501 = 'fileSha512';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:143 }
  CozyText_HardeningContractsProbe_flush_mutation_d0b54c41 = 'flush mutation';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:198 }
  CozyText_HardeningContractsProbe_flush_retained_mutation_e80dd4f6 = 'flush retained mutation';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:110 }
  CozyText_HardeningContractsProbe_hash_altered_shared_position_737b054b = 'hash altered shared position';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:52 }
  CozyText_HardeningContractsProbe_immediate_renewal_4d0596d4 = 'immediate renewal';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:68 }
  CozyText_HardeningContractsProbe_kernel32_dll_d00139ee = 'kernel32.dll';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:55 }
  CozyText_HardeningContractsProbe_lease_error_code_6ff59961 = 'lease error code';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:140 }
  CozyText_HardeningContractsProbe_linked_bin_426c5d9d = 'linked.bin';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:50 }
  CozyText_HardeningContractsProbe_long_lease_c9c88f66 = 'long lease';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:163 }
  CozyText_HardeningContractsProbe_modules_3b152eee = 'modules';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:98 }
  CozyText_HardeningContractsProbe_moved_fae4eed5 = 'moved';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:197 }
  CozyText_HardeningContractsProbe_mutate_retained_file_d6337f50 = 'mutate retained file';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:167 }
  CozyText_HardeningContractsProbe_name_6c5d132e = 'name';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:106 }
  CozyText_HardeningContractsProbe_open_file_36c8887d = 'open file';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:82 }
  CozyText_HardeningContractsProbe_open_reparse_node_not_target_d03e64fa = 'open reparse node, not target';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:186 }
  CozyText_HardeningContractsProbe_open_retained_own_fixture_372dd770 = 'open retained own fixture';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:34 }
  CozyText_HardeningContractsProbe_overlong_UTF8_3bc47666 = 'overlong UTF8';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:173 }
  CozyText_HardeningContractsProbe_own_inventory_row_missing_68780b23 = 'own inventory row missing';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:138 }
  CozyText_HardeningContractsProbe_parent_replacement_followed_a2f816cf = 'parent replacement followed';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:135 }
  CozyText_HardeningContractsProbe_pathname_replacement_followed_3a66ce79 = 'pathname replacement followed';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:148 }
  CozyText_HardeningContractsProbe_read_handle_failure_distinct_status_1a60d74b = 'read handle failure distinct status';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:48 }
  CozyText_HardeningContractsProbe_rejected_transition_mutated_state_b1679653 = 'rejected transition mutated state';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:136 }
  CozyText_HardeningContractsProbe_rename_parent_32a04a4a = 'rename parent';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:133 }
  CozyText_HardeningContractsProbe_rename_pinned_file_2dc960f5 = 'rename pinned file';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:189 }
  CozyText_HardeningContractsProbe_rename_retained_own_fixture_ae84e0e0 = 'rename retained own fixture';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:133 }
  CozyText_HardeningContractsProbe_renamed_189b5718 = '.renamed';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:86 }
  CozyText_HardeningContractsProbe_reparse_node_entered_a_pinned_image_measurement_539212fd = 'reparse node entered a pinned image measurement';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:111 }
  CozyText_HardeningContractsProbe_reset_position_c55aa70a = 'reset position';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:61 }
  CozyText_HardeningContractsProbe_resize_11afbc57 = 'resize';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:180 }
  CozyText_HardeningContractsProbe_retained_exe_85514913 = 'retained.exe';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:200 }
  CozyText_HardeningContractsProbe_retained_mutation_was_hidden_by_path_reopen_38692d3e = 'retained mutation was hidden by path reopen';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:193 }
  CozyText_HardeningContractsProbe_retained_own_code_status_d9605696 = 'retained own code status';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:194 }
  CozyText_HardeningContractsProbe_retained_own_digest_79e83369 = 'retained own digest';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:192 }
  CozyText_HardeningContractsProbe_retained_own_file_status_399edbea = 'retained own file status';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:99 }
  CozyText_HardeningContractsProbe_sample_bin_c3672683 = 'sample.bin';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:140 }
  CozyText_HardeningContractsProbe_sample_bin_renamed_ab8e2e89 = 'sample.bin.renamed';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:196 }
  CozyText_HardeningContractsProbe_seek_retained_mutation_de7069c6 = 'seek retained mutation';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:141 }
  CozyText_HardeningContractsProbe_set_mutation_position_15db5c3a = 'set mutation position';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:108 }
  CozyText_HardeningContractsProbe_set_position_78c5cf07 = 'set position';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:51 }
  CozyText_HardeningContractsProbe_short_lease_a6f50e0f = 'short lease';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:40 }
  CozyText_HardeningContractsProbe_state_matrix_664dd8f1 = 'state matrix';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:192 }
  CozyText_HardeningContractsProbe_status_b0d4d2bf = 'status';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:28 }
  CozyText_HardeningContractsProbe_strict_JSON_26af187a = 'strict JSON ';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:44 }
  CozyText_HardeningContractsProbe_transition_error_code_bfbb0f60 = 'transition error code';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:47 }
  CozyText_HardeningContractsProbe_transition_result_9d010fb8 = 'transition result';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:142 }
  CozyText_HardeningContractsProbe_write_mutation_76e425c1 = 'write mutation';
  { Cozy.Tests/Cozy.Security/Cozy.HardeningContractsProbe.dpr:14 }
  CozyText_HardeningContractsProbe_wrong_status_2f9630ee = ': wrong status';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:94 }
  CozyText_IssuedASignatureProbe_FIXTURE_ANCHOR_LENGTH_e8406212 = 'FIXTURE_ANCHOR_LENGTH';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:29 }
  CozyText_IssuedASignatureProbe_FIXTURE_BASE64_a0216ad1 = 'FIXTURE_BASE64';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:24 }
  CozyText_IssuedASignatureProbe_FIXTURE_FIELD_LIMIT_da34b2e4 = 'FIXTURE_FIELD_LIMIT';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:22 }
  CozyText_IssuedASignatureProbe_FIXTURE_FIELD_TYPE_90203a23 = 'FIXTURE_FIELD_TYPE';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:81 }
  CozyText_IssuedASignatureProbe_FIXTURE_FILE_LIMIT_fd934ad9 = 'FIXTURE_FILE_LIMIT';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:97 }
  CozyText_IssuedASignatureProbe_FIXTURE_LENGTHS_17119bed = 'FIXTURE_LENGTHS';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:88 }
  CozyText_IssuedASignatureProbe_FIXTURE_OBJECT_5ccc249d = 'FIXTURE_OBJECT';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:90 }
  CozyText_IssuedASignatureProbe_FIXTURE_SCOPE_c20c676c = 'FIXTURE_SCOPE';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:54 }
  CozyText_IssuedASignatureProbe_ISSUED_A_ACCEPTANCE_MISMATCH_974b42af = 'ISSUED_A_ACCEPTANCE_MISMATCH';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:57 }
  CozyText_IssuedASignatureProbe_ISSUED_A_CONFIG_MISMATCH_6ed86787 = 'ISSUED_A_CONFIG_MISMATCH';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:150 }
  CozyText_IssuedASignatureProbe_JsonFixture_576ee6b1 = '{"status":"FAIL","scope":"WINDOWS_CNG_ISSUED_A_SIGNATURE"}';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:134 }
  CozyText_IssuedASignatureProbe_JsonFixture_7365886b = '{"status":"PASS","scope":"WINDOWS_CNG_ISSUED_A_SIGNATURE",';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:53 }
  CozyText_IssuedASignatureProbe_PINNED_STREAM_POSITION_NOT_RESTORED_d8057d13 = 'PINNED_STREAM_POSITION_NOT_RESTORED';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:90 }
  CozyText_IssuedASignatureProbe_SYNTHETIC_PUBLIC_ONLY_NATIVE_CNG_VECTOR_08a722cb = 'SYNTHETIC_PUBLIC_ONLY_NATIVE_CNG_VECTOR';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:151 }
  CozyText_IssuedASignatureProbe_Text_8a9b1928 = ': ';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:77 }
  CozyText_IssuedASignatureProbe_USAGE_PROBE_PUBLIC_VECTOR_JSON_4a4c04e2 = 'USAGE_PROBE_PUBLIC_VECTOR_JSON';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:135 }
  CozyText_IssuedASignatureProbe_actualNativeExecuted_true_cases_5689bbfa = '"actualNativeExecuted":true,"cases":';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:91 }
  CozyText_IssuedASignatureProbe_anchorBase64_2ac006fc = 'anchorBase64';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:92 }
  CozyText_IssuedASignatureProbe_configBase64_eec8c0ff = 'configBase64';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:93 }
  CozyText_IssuedASignatureProbe_finalBase64_33d3410d = 'finalBase64';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:90 }
  CozyText_IssuedASignatureProbe_scope_63ff8b96 = 'scope';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:95 }
  CozyText_IssuedASignatureProbe_templateBytes_42bf8f32 = 'templateBytes';
  { Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr:136 }
  CozyText_IssuedASignatureProbe_wholeAboExecution_NOT_RUN_authenticode_false_3f80993f = ',"wholeAboExecution":"NOT_RUN","authenticode":false}';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:89 }
  CozyText_LicenseStateProbe_ACTIVE_098f897d = 'ACTIVE';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:124 }
  CozyText_LicenseStateProbe_Already_expired_license_d2570549 = 'Already expired license';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:31 }
  CozyText_LicenseStateProbe_DL_00112233445566778899AABB_6aaaaec1 = 'DL-00112233445566778899AABB';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:136 }
  CozyText_LicenseStateProbe_Elapsed_time_cannot_wrap_signed_Int64_86451a9c = 'Elapsed time cannot wrap signed Int64';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:102 }
  CozyText_LicenseStateProbe_Empty_local_lease_637024ee = 'Empty local lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:110 }
  CozyText_LicenseStateProbe_Empty_server_lease_8c3ec735 = 'Empty server lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:71 }
  CozyText_LicenseStateProbe_Exact_lease_expiry_88f7515e = 'Exact lease expiry';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:69 }
  CozyText_LicenseStateProbe_Exact_second_elapsed_b6c1c18a = 'Exact second elapsed';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:161 }
  CozyText_LicenseStateProbe_FAIL_fc41398e = 'FAIL: ';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:147 }
  CozyText_LicenseStateProbe_Final_millisecond_near_Int64_maximum_38b06ba8 = 'Final millisecond near Int64 maximum';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:149 }
  CozyText_LicenseStateProbe_Finite_license_rounding_cannot_overflow_Int64_1cc2bbb6 = 'Finite license rounding cannot overflow Int64';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:67 }
  CozyText_LicenseStateProbe_Full_authorized_lease_c1bf70bb = 'Full authorized lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:98 }
  CozyText_LicenseStateProbe_Future_verification_clock_bad77461 = 'Future verification clock';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:45 }
  CozyText_LicenseStateProbe_IsActive_5bc67a7a = ': IsActive';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:46 }
  CozyText_LicenseStateProbe_IsActive_clock_sample_4fff7a08 = ': IsActive clock sample';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:70 }
  CozyText_LicenseStateProbe_Last_authorized_millisecond_37f45ca4 = 'Last authorized millisecond';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:132 }
  CozyText_LicenseStateProbe_Lease_cannot_overflow_Integer_seconds_9f4b4ab0 = 'Lease cannot overflow Integer seconds';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:126 }
  CozyText_LicenseStateProbe_Lease_extends_beyond_license_1b54a719 = 'Lease extends beyond license';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:106 }
  CozyText_LicenseStateProbe_Local_deadline_exceeds_server_grant_7e2107bc = 'Local deadline exceeds server grant';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:141 }
  CozyText_LicenseStateProbe_Maximum_unsigned_clock_at_expiry_7d978e25 = 'Maximum unsigned clock at expiry';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:129 }
  CozyText_LicenseStateProbe_Maximum_unsigned_deadline_cannot_round_into_vali_a66449ba = 'Maximum unsigned deadline cannot round into validity';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:118 }
  CozyText_LicenseStateProbe_Minimum_signed_lease_expiry_2018db01 = 'Minimum signed lease expiry';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:120 }
  CozyText_LicenseStateProbe_Minimum_signed_license_expiry_3a025fb7 = 'Minimum signed license expiry';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:116 }
  CozyText_LicenseStateProbe_Minimum_signed_server_time_3b2b1329 = 'Minimum signed server time';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:94 }
  CozyText_LicenseStateProbe_Missing_device_identity_b9cdabb3 = 'Missing device identity';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:100 }
  CozyText_LicenseStateProbe_Missing_lease_deadline_bb8d6854 = 'Missing lease deadline';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:92 }
  CozyText_LicenseStateProbe_Missing_license_identity_d4f70be5 = 'Missing license identity';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:96 }
  CozyText_LicenseStateProbe_Missing_verification_clock_c4dae2af = 'Missing verification clock';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:73 }
  CozyText_LicenseStateProbe_Monotonic_clock_rollback_5662ad99 = 'Monotonic clock rollback';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:122 }
  CozyText_LicenseStateProbe_Negative_finite_expiry_9d34c098 = 'Negative finite expiry';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:75 }
  CozyText_LicenseStateProbe_Network_latency_shortens_lease_c15783bb = 'Network latency shortens lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:68 }
  CozyText_LicenseStateProbe_One_millisecond_elapsed_6ec6b9e7 = 'One millisecond elapsed';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:85 }
  CozyText_LicenseStateProbe_One_millisecond_grant_expired_e2facdad = 'One millisecond grant expired';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:84 }
  CozyText_LicenseStateProbe_One_millisecond_grant_rounds_up_021863af = 'One millisecond grant rounds up';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:156 }
  CozyText_LicenseStateProbe_PASS_5d779032 = 'PASS: ';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:54 }
  CozyText_LicenseStateProbe_PASS_bb0cffc5 = 'PASS ';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:72 }
  CozyText_LicenseStateProbe_Past_lease_expiry_6eb5201f = 'Past lease expiry';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:78 }
  CozyText_LicenseStateProbe_Perpetual_license_still_requires_a_live_lease_f82d7881 = 'Perpetual license still requires a live lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:79 }
  CozyText_LicenseStateProbe_Perpetual_license_with_expired_lease_fb2acb97 = 'Perpetual license with expired lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:157 }
  CozyText_LicenseStateProbe_Platform_clock_injection_only_not_a_Windows_serv_04b7f1cc = 'Platform clock injection only; not a Windows/server integration test.';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:104 }
  CozyText_LicenseStateProbe_Reversed_local_lease_d7841c5a = 'Reversed local lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:112 }
  CozyText_LicenseStateProbe_Reversed_server_lease_45623f23 = 'Reversed server lease';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:108 }
  CozyText_LicenseStateProbe_Server_lease_exceeds_protocol_bound_2b61717e = 'Server lease exceeds protocol bound';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:161 }
  CozyText_LicenseStateProbe_Text_1cd35884 = ': ';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:33 }
  CozyText_LicenseStateProbe_USED_403576ef = 'USED';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:90 }
  CozyText_LicenseStateProbe_Unapproved_status_c1f28190 = 'Unapproved status';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:88 }
  CozyText_LicenseStateProbe_Uninitialized_record_bd699ba5 = 'Uninitialized record';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:140 }
  CozyText_LicenseStateProbe_Valid_clock_near_UInt64_maximum_9cba250b = 'Valid clock near UInt64 maximum';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:146 }
  CozyText_LicenseStateProbe_Valid_timestamps_near_Int64_maximum_537dbe82 = 'Valid timestamps near Int64 maximum';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:114 }
  CozyText_LicenseStateProbe_Zero_server_time_84e347d0 = 'Zero server time';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:49 }
  CozyText_LicenseStateProbe_lease_clock_sample_d4706ba4 = ': lease clock sample';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:48 }
  CozyText_LicenseStateProbe_lease_seconds_713e9b5e = ': lease seconds';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:52 }
  CozyText_LicenseStateProbe_license_clock_sample_7b1ce052 = ': license clock sample';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:51 }
  CozyText_LicenseStateProbe_license_seconds_c5bc49da = ': license seconds';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:32 }
  CozyText_LicenseStateProbe_probe_device_540c20cd = 'probe-device';
  { Cozy.Tests/Cozy.Security/Cozy.LicenseStateProbe.dpr:156 }
  CozyText_LicenseStateProbe_production_license_state_boundary_cases_d074791b = ' production license-state boundary cases.';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:38 }
  CozyText_MitigationProbeSupport_AB_4603c932 = 'AB';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:19 }
  CozyText_MitigationProbeSupport_INVALID_ARGUMENT_0de5a79e = 'INVALID_ARGUMENT';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:39 }
  CozyText_MitigationProbeSupport_MITIGATION_ENVIRONMENT_UNAVAILABLE_44542239 = 'MITIGATION_ENVIRONMENT_UNAVAILABLE';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:43 }
  CozyText_MitigationProbeSupport_NATIVE_MITIGATION_OBSERVATION_bd50a831 = 'NATIVE_MITIGATION_OBSERVATION';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:57 }
  CozyText_MitigationProbeSupport_NATIVE_POLICY_READBACK_NOT_PRODUCT_WORKFLOW_597f7b4e = 'NATIVE_POLICY_READBACK_NOT_PRODUCT_WORKFLOW';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:56 }
  CozyText_MitigationProbeSupport_REAL_RENDERER_POLICY_AND_VISIBLE_PRESENT_b6e09a38 = 'REAL_RENDERER_POLICY_AND_VISIBLE_PRESENT';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:44 }
  CozyText_MitigationProbeSupport_componentScope_0d3a3999 = 'componentScope';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:27 }
  CozyText_MitigationProbeSupport_dynamicCode_014a8fa3 = 'dynamicCode';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:45 }
  CozyText_MitigationProbeSupport_environment_127c268e = 'environment';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:26 }
  CozyText_MitigationProbeSupport_id_fca860f8 = 'id';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:29 }
  CozyText_MitigationProbeSupport_imageLoadMask_3bea60bc = 'imageLoadMask';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:43 }
  CozyText_MitigationProbeSupport_kind_f6e1ea91 = 'kind';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:52 }
  CozyText_MitigationProbeSupport_observation_d8253779 = 'observation';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:14 }
  CozyText_MitigationProbeSupport_observe_79eadc49 = 'observe';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:53 }
  CozyText_MitigationProbeSupport_policyReadback_d0e1a437 = 'policyReadback';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:17 }
  CozyText_MitigationProbeSupport_prohibit_36748160 = 'prohibit';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:16 }
  CozyText_MitigationProbeSupport_prohibit_a541a1b9 = '--prohibit';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:54 }
  CozyText_MitigationProbeSupport_renderer_22329632 = 'renderer';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:18 }
  CozyText_MitigationProbeSupport_report_e8d0c17f = '--report';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:30 }
  CozyText_MitigationProbeSupport_requireCfg_4b636df0 = 'requireCfg';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:56 }
  CozyText_MitigationProbeSupport_scope_6bc7ce98 = 'scope';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:47 }
  CozyText_MitigationProbeSupport_settings_12ec0d77 = 'settings';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:28 }
  CozyText_MitigationProbeSupport_strictHandles_31ff1275 = 'strictHandles';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:25 }
  CozyText_MitigationProbeSupport_version_fd48f73c = 'version';
  { Cozy.Tests/Cozy.Security/Cozy.MitigationProbeSupport.pas:55 }
  CozyText_MitigationProbeSupport_visibleFrames_76518971 = 'visibleFrames';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:17 }
  CozyText_ProcessMitigationProfileProbe_AB_80d85eb8 = 'AB';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:28 }
  CozyText_ProcessMitigationProfileProbe_FAIL_641cfa14 = 'FAIL ';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:27 }
  CozyText_ProcessMitigationProfileProbe_FAIL_MITIGATION_READBACK_ab85dbc6 = 'FAIL MITIGATION_READBACK_';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:16 }
  CozyText_ProcessMitigationProfileProbe_MITIGATION_ENVIRONMENT_UNAVAILABLE_ad4fc4a5 = 'MITIGATION_ENVIRONMENT_UNAVAILABLE';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:20 }
  CozyText_ProcessMitigationProfileProbe_MITIGATION_READBACK_FAILED_d47a63a3 = 'MITIGATION_READBACK_FAILED';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:23 }
  CozyText_ProcessMitigationProfileProbe_NATIVE_POLICY_READBACK_NOT_GRAPHICS_COMPATIBILIT_36b89a7a = 'NATIVE_POLICY_READBACK_NOT_GRAPHICS_COMPATIBILITY';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:17 }
  CozyText_ProcessMitigationProfileProbe_NOT_RUN_f2ab8a47 = 'NOT_RUN';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:20 }
  CozyText_ProcessMitigationProfileProbe_PASS_f81b1894 = 'PASS';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:26 }
  CozyText_ProcessMitigationProfileProbe_PASS_process_profile_actual_policy_readback_8e977ff7 = 'PASS process profile actual policy readback';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:22 }
  CozyText_ProcessMitigationProfileProbe_environment_ba6d76ac = 'environment';
  { Cozy.Tests/Cozy.Security/Cozy.ProcessMitigationProfileProbe.dpr:23 }
  CozyText_ProcessMitigationProfileProbe_scope_ab3c211f = 'scope';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:10 }
  CozyText_ServerOperationsProtocolProbe_11111111_2222_3333_4444_555555555555_f2305a96 = '11111111-2222-3333-4444-555555555555';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:9 }
  CozyText_ServerOperationsProtocolProbe_Digest_aa6d774f = '2985f0d71603fc5c4e1fe47078bbaf7f14c7002eae59a042bc67b4d44e33c8a1797afe7f51dcc3c428a2c769ee2eed82f1efefd8efff1f0061c6e96e37e2155b';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:8 }
  CozyText_ServerOperationsProtocolProbe_Digest_c67072c0 = '3320a5e97eee3f3ad19146a8c349745f2feeed61a11bec5a4eeeac26f54d4a5f2ff05629ffd5cb43589c775a4e2ed6242c5dbb2535554f43e2127f22f6bf9e67';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:7 }
  CozyText_ServerOperationsProtocolProbe_Digest_f2ab4822 = 'db3ed6671edc57d950f9c2416c0a60b4860cc2344f5e810badb558f04b2375d7611a04127d3fc06d2e803124ff014f8522f1ef153370fbda9fbe3f5aa6a4e766';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:207 }
  CozyText_ServerOperationsProtocolProbe_JsonFixture_4ae4c689 = '[-2147483648,0,2147483647]';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:16 }
  CozyText_ServerOperationsProtocolProbe_PROTOCOL_VECTOR_MISMATCH_92907ec3 = 'PROTOCOL_VECTOR_MISMATCH';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:39 }
  CozyText_ServerOperationsProtocolProbe_UNKNOWN_PUBLIC_TEST_VECTOR_3fe78ec7 = 'UNKNOWN_PUBLIC_TEST_VECTOR';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:79 }
  CozyText_ServerOperationsProtocolProbe_changed_request_07c2ea14 = 'changed-request';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:122 }
  CozyText_ServerOperationsProtocolProbe_id_6e846bb4 = 'id';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:122 }
  CozyText_ServerOperationsProtocolProbe_valid_082f08bf = 'valid';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:121 }
  CozyText_ServerOperationsProtocolProbe_valid_id_6cb07c6b = 'valid-id';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr:123 }
  CozyText_ServerOperationsProtocolProbe_valid_id_da3e8ced = 'valid id';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:25 }
  CozyText_ServerOperationsProtocolVectors_Digest_0495e863 = 'f10874d1bf34080b60df047f613f7ecc4ce8bfbb4d7cc8cc85108daf0ee5498b76d2d1f3056df440dc3749f5b5ad7a528e8b63f6c046adb47d7120428aa83373';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:69 }
  CozyText_ServerOperationsProtocolVectors_Digest_0993b65d = '3061a4cfb84907109e357ba568956ba589caaff7ec8296f283f4d2167a892bceb21c6e4f37db5194a358d5e9388c03fd877b86691df4aae2f17134871a357492';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:110 }
  CozyText_ServerOperationsProtocolVectors_Digest_0eacbf74 = 'f34a078d83347716da3bab75c6a92319e60b89f78206f927f37066858dc01e7322ea7947a1fa06eeadabd7d7dc7d10fef1142fcfde3e6c2c08fd6b19cdf48dea';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:73 }
  CozyText_ServerOperationsProtocolVectors_Digest_13fed645 = '3667bc521630240fc2161d618eb5d9a37d73dd15741df96ab7a03b926895d71ba09da241ce13d398caf5efe137e0957d94297c7ffa6d983de16585a83c9e44ba';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:84 }
  CozyText_ServerOperationsProtocolVectors_Digest_14155d78 = 'bccfc6a553969471de0d3d6e094e532f891d9bc132d9d47f7df9e7afc2403ce8cd0f3c2372afc20e7ecf6e171c6cf17168204a524b462e13cc820732d1c6cb4b';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:23 }
  CozyText_ServerOperationsProtocolVectors_Digest_1701a560 = 'db3ed6671edc57d950f9c2416c0a60b4860cc2344f5e810badb558f04b2375d7611a04127d3fc06d2e803124ff014f8522f1ef153370fbda9fbe3f5aa6a4e766';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:31 }
  CozyText_ServerOperationsProtocolVectors_Digest_1c513308 = 'b671d80be1c07cba5b71e7c1060481d33a9e67909b2fccf85bec8f3b9c79a092aa04fc8ee706cd14af5f24456f6f78d9c781f31c99d073e374dac9e45135d96a';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:112 }
  CozyText_ServerOperationsProtocolVectors_Digest_1fb8155a = 'fc5351ad552efcfe189de561c17159b91b81d86aca63661d1e342c07f94e71292b67720d9f3f7c36695eba005cb6d398beaa9cbd5c1e903c1d2ea881be3c7375';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:77 }
  CozyText_ServerOperationsProtocolVectors_Digest_228ef90c = 'b4fef9145b2a448e234742a79aa5266d1a9c092d97988a947c3f44084d709b8e703b9da964ea61fe48cfd308b8061f74a8a7cf517afde6e5498e39931c3e7719';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:41 }
  CozyText_ServerOperationsProtocolVectors_Digest_26ad991a = '8741ba5dad9e9dcf3fe3f576ecfdf7eeccd6ee652d9ae3e11fb5cfeea7e950fb73c2ccc43f576a2af462156b654646b80348cc6aa02117ba453750394c4456ff';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:32 }
  CozyText_ServerOperationsProtocolVectors_Digest_2d9e1984 = 'd424d815c6916925af4c64337f14abf7335bae610f4afe7dc525b0ea1a88de33a56c083142da2a5e29d4fe2e37a1dab5ab660c7727eed38c345a0564e1655872';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:24 }
  CozyText_ServerOperationsProtocolVectors_Digest_2e18bf41 = '3c68f701a5768fd78363ff0e7523fa79f3b6a235b71a8831edfbfae65dbf0e7c5eb4f411a0f761679ba5ac86f2043d4f5fdf8c870f506fdc5d3c0b2398d4f412';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:94 }
  CozyText_ServerOperationsProtocolVectors_Digest_35378a54 = '42679c182b5f642c38a86d14680ca9607bc1a06a6ac130467e88fd09c0d38f78cbc650afb7cea26c41b7481567c224de6c63b6da2eb63f759fed380d04f45240';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:44 }
  CozyText_ServerOperationsProtocolVectors_Digest_3925d5f6 = '1c74193e57b8fc175269a68051bb23bc6e56f39bcc665d2d05e50ebb28d089de277c3974537271fd92ef8b13a75eaa91a0c0bb8b02d871ac6c524394e6fe1091';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:81 }
  CozyText_ServerOperationsProtocolVectors_Digest_3f2e5e00 = '1109cdf399fb582e3c41aff92b02fcd5c55ebe3a59cd5be44365d6e3d9127adb07bddbc9e067fe45e2a507c0a3b62787185e8f58aa257e9171d4cf46ee635917';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:93 }
  CozyText_ServerOperationsProtocolVectors_Digest_3fe8f9d9 = '88dd441977cbb2455872df50e9fbc373846276b99fd0f54743308a9e85079964681af610969afc1ac365fa9c92f16213c550ad4b6636702399297e6fa935c49c';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:36 }
  CozyText_ServerOperationsProtocolVectors_Digest_4210230c = 'c235afb21981417f661fa6a126487277f9d16b45110377e3461c1b0f726d21f16970899f4d01ec64a3dabba70805df3d80988bfd8a9455c78215993c08254042';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:104 }
  CozyText_ServerOperationsProtocolVectors_Digest_426bf1e1 = '15401ef7bdf537894694936d7b8268342962b5609613d69da1a88c35ee793fc74a130df83bba2e92667446e84523b8fadb83ed2629b6997075509f37538f9920';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:95 }
  CozyText_ServerOperationsProtocolVectors_Digest_534692fb = '393f5816939798e6a1d74e08f7a8037c2aaeeea528a8542611bdeb8082e3af5c386dd8ce2b04a52991a78f6af2d91f9b1372240432ae42cca8be882878be458b';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:106 }
  CozyText_ServerOperationsProtocolVectors_Digest_5613d352 = '624ef16b68dd374b4261d6fa3f68fa4d1347960d6021817e4bc43f9c289c2f44ffa0c6376ad6a28a6f68d19f8b1a923353117375db26d4c68b5ce36c34c12739';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:20 }
  CozyText_ServerOperationsProtocolVectors_Digest_5af92928 = '40db81d9e8586269a328641d54aff19d92440bc748c3ff7376934475d88aa62d263bda078b8d8b3c9ae4ff6b2a75c114a466f39a26a07415598951ebe8f87c19';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:60 }
  CozyText_ServerOperationsProtocolVectors_Digest_5b425d96 = '3dc2144e4cba27ed68a8ca3801f53a209de73f3404dbfd484d4cb1fab927d7f04904e56840191e2ebce6d8c74f33493b26211c94768e370643784a07e5f7afd4';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:97 }
  CozyText_ServerOperationsProtocolVectors_Digest_5b81c230 = '539c6094ea2ced639eb00d714b217d59e6154b3c5f01580433fd3dc29aff1fa9b513af1a49ac9fc6a6bca9a5bc2a42a01f529cdd372d7097de7300eaf8ea15a2';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:52 }
  CozyText_ServerOperationsProtocolVectors_Digest_5eb1acda = 'ee96d5a1864a63d5680bb38501c29d94a3f6de2c69d41649220abfea4f3769f18f3fe6e298d8867f3c95fe1f116ab5069ff30dd65dbbdeb08aaac575944bb72e';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:53 }
  CozyText_ServerOperationsProtocolVectors_Digest_6221c10f = 'caa739afd4e2b7a4e3851fccabe85923dbe64b07128044061b6257ae26cccec52c579ec630382bb2e7287df0e0de04eedc3333e01e95e1c30a424772cda7345b';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:96 }
  CozyText_ServerOperationsProtocolVectors_Digest_635b6885 = 'dc31f41a963df0047af28b8545e2fe828bb0ab906f265c1cd894e5ffb5dc2452b8eaa13f47c97d43404e3be888e746a074ef59436eeb0fea03de902c05068547';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:85 }
  CozyText_ServerOperationsProtocolVectors_Digest_658185f4 = '102935c72aea6d2c559795e5580bb296fb82b6086f0da37d8cdc9652bc23ac93382a30dd1cdeb9f8f050a2a8ba4b9b25e81a23c9593202af8d282b743a97b797';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:48 }
  CozyText_ServerOperationsProtocolVectors_Digest_66608115 = '3320a5e97eee3f3ad19146a8c349745f2feeed61a11bec5a4eeeac26f54d4a5f2ff05629ffd5cb43589c775a4e2ed6242c5dbb2535554f43e2127f22f6bf9e67';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:28 }
  CozyText_ServerOperationsProtocolVectors_Digest_677a6dbe = '714b89f8d0f68904c1db4204bb44e8fe9695114e7e9252dbcb9e61346270d8104ce22d46e2fb21b3188920afa51154d21fb377fbc58087e2f6c8cf7a406ba68b';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:64 }
  CozyText_ServerOperationsProtocolVectors_Digest_6c650b77 = '40bb871bea4e07395b9a2574d5bc066391f5b726674d58869c7b146f1c564ff69af4f273189aabf2496480056be3d289a06fded24e79236928404d6ea348454e';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:61 }
  CozyText_ServerOperationsProtocolVectors_Digest_6e8fa1fe = '5bf4454f6d2a8fd16242aab641815911099855547912b5107aa2a04c2f8391fa8450b776fa8c7ee45219cd442cc53e1372a3087c5098415ffb578c7fd3761531';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:37 }
  CozyText_ServerOperationsProtocolVectors_Digest_7724d04e = 'a98fac439cc514e9dc25039224b8e36f1d4319d83d38788e297cb9285ae9cb9a620d5141f29707c17aade98e019498d2a02de36fba5f56b9932fd38a141cd452';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:17 }
  CozyText_ServerOperationsProtocolVectors_Digest_793453d5 = '5b47d9d405c2433d25ce30d7a9da003e6cc160117d93e63b4c66cfc9447a20d987e2945deb9ffb071f86732340f8bc0a76510329b0e3ccfdeb7b35c03738ebe2';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:68 }
  CozyText_ServerOperationsProtocolVectors_Digest_91df8975 = '84c2d3aea56febed2f40a403b65713652d05f022524475c235478676634aafa6804c8934bc2d281f36ce318299f1fd256e5f3d0fc3273b54d3070733231715cf';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:108 }
  CozyText_ServerOperationsProtocolVectors_Digest_92464686 = 'a01b8f1bfad3cd2e7ade5f4202d0ef3d48ea6962707dcb89e91b9675ed738eb36f2eff04b545ec25ef04f1c6691e6bb8f2e919073015ec40b95c28e2d671420a';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:76 }
  CozyText_ServerOperationsProtocolVectors_Digest_b024dc73 = 'c9886ee01d73a6a2ee6a97334bc841b65cec81d7f82bae59ca41be9550c9f00bdbe3256a6a318d7f6cf18869e33163bcba1bbb15768026d6587f36372316867f';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:91 }
  CozyText_ServerOperationsProtocolVectors_Digest_b03c7979 = '14575f9f0418d6bcd6254344248c35b8d605dcdfcbac7f0d522ca4bb7be3d03d02ce81700eb876da1e237da78531af0d59992d00bab6ca200ba311eb284d2307';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:21 }
  CozyText_ServerOperationsProtocolVectors_Digest_b107936a = 'e861b6f912f6d0057b95946b3dbb76c2aa8f785dd3cc2bbeb78b95f2fccdf2a5c0b01dbf2c9f6636c67f3d53c44fc646868129fb008f23aa78bf6f9e67b6b81a';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:16 }
  CozyText_ServerOperationsProtocolVectors_Digest_b5a63650 = '60d3c2f6f49c5fe97576e9a8f64f2c8a1d62a4d5956c074a093a14e63f659f6996ca85f4059357523ec82397c661fc6784a8c6cf32e43ed534fc82f4256309e9';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:56 }
  CozyText_ServerOperationsProtocolVectors_Digest_b62aae61 = '340ac18cc2934075f712ca459a3f627e57645e800d35aadbda4e3dec7aa63f2f14c73499c9dd16848b11efd9f86c6b36cfcc1c1db00780873960931bf57037cd';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:80 }
  CozyText_ServerOperationsProtocolVectors_Digest_c0a0d15c = '0e8139951d9d4958de80d5f95a7fe363a0d3f0c7f549ddc1637b1081a7be56c7fe8c9355928c2dfab3840d62cbf8f59d798612a87de5b4d8b921c674ed8c10d5';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:15 }
  CozyText_ServerOperationsProtocolVectors_Digest_c403d28a = 'b25b294cb4deb69ea00a4c3cf3113904801b6015e5956bd019a8570b1fe1d6040e944ef3cdee16d0a46503ca6e659a25f21cf9ceddc13f352a3c98138c15d6af';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:29 }
  CozyText_ServerOperationsProtocolVectors_Digest_c41a7592 = '30762a44478f312741d9f77f3bf0391c0e0d4f369cb2b77ddc09541f21effffb5b255201111c6e31c57d9f35dba7adabfbc4bc1e2827679e93129593baa63d0c';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:72 }
  CozyText_ServerOperationsProtocolVectors_Digest_d47becf5 = '0c35ffc765eb4f3d9115beaf7942ed6112e1af1a1acb08f42b425dc7d93f6256dda559be9a343c09ee4963bca21b976f5bc99d2ad1c03e7db9d536c91e0bca4f';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:33 }
  CozyText_ServerOperationsProtocolVectors_Digest_d4b47104 = '3e382dd903c33945f6cef3a24d20a4ac1e2140ea46aaa950f72ffd86c627136197dbd5874874dfca800d504b70dafbe2fdf619dec7ef7215f69bc26709496582';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:92 }
  CozyText_ServerOperationsProtocolVectors_Digest_d5818022 = 'c83e408e471185ce48ca87914fd81239908037353736b6dfbd60b8b97ad7102b41994fefcea44ef726868a653ab513b24497d1e9ec3fb24971bb1134b3c5f7c9';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:40 }
  CozyText_ServerOperationsProtocolVectors_Digest_e88fb49a = '46ee2bb38997aeddd057de192d2d8b1d65420f562d76ee97ebcfbc94621b56ec301535d40c0bc561a1a53314d80b2da240b56d5127bfafd6768f9b808a7d76f7';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:45 }
  CozyText_ServerOperationsProtocolVectors_Digest_e9dfe410 = '7addf46bb277de72bea69965953e01f968a469d23f1ad8cc42930c59048e8fd7475d8b1db8701df01d552e813a61200c8297670f8d4be6d00e90ff5d8bf50347';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:65 }
  CozyText_ServerOperationsProtocolVectors_Digest_ef1519d1 = '8175e567e81f96afaf5be43bcf5830fc34b60c44c6711fba9cc0d438731717907a70723d9312ee510a11b4c97dc9024e0058fef5059a5802174451860acf9f32';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:98 }
  CozyText_ServerOperationsProtocolVectors_Digest_f0fa3a3d = '2e9738c0402632693652e2a10f13df6ad1596ed7b9e7c0c56cdb3543dae8fee80f53f46b9cc2e8370d2b202409b02425ca8453d8d699f61baaf3e85f868330f4';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:57 }
  CozyText_ServerOperationsProtocolVectors_Digest_f70c849b = '861979c445f0789abe93a9524b5a77da4a32cfd65284d98da1899e03c9aa9ce4edfd5daabe423aaf79a9189e8348d720d649ebc63a949e86f0e92c4d366770ca';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:49 }
  CozyText_ServerOperationsProtocolVectors_Digest_f8e30dbe = '2985f0d71603fc5c4e1fe47078bbaf7f14c7002eae59a042bc67b4d44e33c8a1797afe7f51dcc3c428a2c769ee2eed82f1efefd8efff1f0061c6e96e37e2155b';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc:114 }
  CozyText_ServerOperationsProtocolVectors_Digest_fff5acbf = '0a2d43e5d28078cce5fce36d28e309a82be43a822b84a00a7a023f6fe2ea97f2d3854beb8700c7c42819358ae2bdce386f1d3c1253a4d545f10e1f9a9f29bf6c';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperations.Example.pas:56 }
  CozyText_ServerOperations_Example_COZY_SERVER_OPERATION_ARGUMENT_INVALID_e8c2ffcf = 'COZY_SERVER_OPERATION_ARGUMENT_INVALID';
  { Cozy.Tests/Cozy.Security/Cozy.ServerOperations.Example.pas:50 }
  CozyText_ServerOperations_Example_COZY_SERVER_OPERATION_CANCELLED_219e0920 = 'COZY_SERVER_OPERATION_CANCELLED';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:29 }
  CozyText_ServerPolicyLocalProbe_API_SLOTS_d23639c7 = 'API_SLOTS=';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:30 }
  CozyText_ServerPolicyLocalProbe_API_STORAGE_READ_ONLY_3fc5dc9f = 'API_STORAGE=READ_ONLY';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:18 }
  CozyText_ServerPolicyLocalProbe_API_arena_is_not_read_only_b933bf4e = 'API arena is not read-only.';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:32 }
  CozyText_ServerPolicyLocalProbe_CFG_941c4260 = 'CFG=';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:31 }
  CozyText_ServerPolicyLocalProbe_DYNAMIC_CODE_64ed89cb = 'DYNAMIC_CODE=';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:39 }
  CozyText_ServerPolicyLocalProbe_FAIL_362def22 = 'FAIL: ';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:28 }
  CozyText_ServerPolicyLocalProbe_MITIGATION_OBSERVATION_92bf3d22 = 'MITIGATION_OBSERVATION=';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:35 }
  CozyText_ServerPolicyLocalProbe_No_server_connection_or_application_workflow_was_c1ff7780 = 'No server connection or application workflow was started.';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:13 }
  CozyText_ServerPolicyLocalProbe_Only_prohibit_is_accepted_default_is_observe_7065a0a9 = 'Only --prohibit is accepted; default is observe.';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:34 }
  CozyText_ServerPolicyLocalProbe_Opt_in_dynamic_code_restriction_was_not_establis_d34623db = 'Opt-in dynamic-code restriction was not established.';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:33 }
  CozyText_ServerPolicyLocalProbe_PROHIBITED_84db45ad = 'PROHIBITED';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:39 }
  CozyText_ServerPolicyLocalProbe_Text_85a71ebc = ': ';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:25 }
  CozyText_ServerPolicyLocalProbe_Unknown_mitigation_mode_was_accepted_3c7003a8 = 'Unknown mitigation mode was accepted.';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:21 }
  CozyText_ServerPolicyLocalProbe_invalid_mode_97a9d86b = 'invalid-mode';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:9 }
  CozyText_ServerPolicyLocalProbe_observe_2b198880 = 'observe';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:12 }
  CozyText_ServerPolicyLocalProbe_prohibit_3a85d63b = '--prohibit';
  { Cozy.Tests/Cozy.Security/Cozy.ServerPolicyLocalProbe.dpr:14 }
  CozyText_ServerPolicyLocalProbe_prohibit_5a02b784 = 'prohibit';

implementation
end.
