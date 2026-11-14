unit Cozy.Strings.TestsHandoff;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:109 }
  CozyText_DeviceSecurityHandoffProbe_API_pointer_storage_is_not_read_only_21a7b259 = 'API pointer storage is not read-only.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:44 }
  CozyText_DeviceSecurityHandoffProbe_CLAIM_e324b6bf = 'CLAIM';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:47 }
  CozyText_DeviceSecurityHandoffProbe_Child_claim_domain_differs_f70c6b3b = 'Child claim domain differs.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:32 }
  CozyText_DeviceSecurityHandoffProbe_Closed_key_admitted_a_new_operation_10ddc4cc = 'Closed key admitted a new operation.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:40 }
  CozyText_DeviceSecurityHandoffProbe_DELEGATION_6e14202b = 'DELEGATION';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:53 }
  CozyText_DeviceSecurityHandoffProbe_Delegation_was_not_cleared_4fe1f19d = 'Delegation was not cleared.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:67 }
  CozyText_DeviceSecurityHandoffProbe_Digest_3e2691ee = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:65 }
  CozyText_DeviceSecurityHandoffProbe_Digest_994e7fe7 = '9f6355aa784240522451364bb147aef5b8ff2c70ff3b266ab0e3994fd6fe50fd44bfbe39c4a2b98a8a23c115b64a84f9a7d8583c9ab6c8c7b9dec5336ba5541b';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:66 }
  CozyText_DeviceSecurityHandoffProbe_Digest_b9affd9e = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:114 }
  CozyText_DeviceSecurityHandoffProbe_FAIL_a5da5561 = 'FAIL: ';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:64 }
  CozyText_DeviceSecurityHandoffProbe_GAME_B85_CLAIM_V2_4729b503 = 'GAME-B85-CLAIM-V2';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:75 }
  CozyText_DeviceSecurityHandoffProbe_GAME_HANDOFF_CLAIM_V3_3c418bab = 'GAME-HANDOFF-CLAIM-V3';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:72 }
  CozyText_DeviceSecurityHandoffProbe_GAME_HANDOFF_DELEGATION_V3_044e6310 = 'GAME-HANDOFF-DELEGATION-V3';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:98 }
  CozyText_DeviceSecurityHandoffProbe_Independent_O_still_owns_its_key_80af392b = 'Independent O still owns its key.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:23 }
  CozyText_DeviceSecurityHandoffProbe_Invalid_delegation_operation_was_accepted_988b6341 = 'Invalid delegation operation was accepted.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:90 }
  CozyText_DeviceSecurityHandoffProbe_Key_identity_mismatch_1834d82c = 'Key identity mismatch.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:76 }
  CozyText_DeviceSecurityHandoffProbe_Known_UTF_8_claim_canonical_differs_from_server__9059d0ae = 'Known UTF-8 claim canonical differs from server vector.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:73 }
  CozyText_DeviceSecurityHandoffProbe_Known_UTF_8_delegation_canonical_differs_from_se_581c3fd9 = 'Known UTF-8 delegation canonical differs from server vector.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:91 }
  CozyText_DeviceSecurityHandoffProbe_Machine_binding_changed_cb9b0486 = 'Machine binding changed.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:92 }
  CozyText_DeviceSecurityHandoffProbe_Native_probe_parent_to_B_claim_bb12827b = 'Native probe parent-to-B claim';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:94 }
  CozyText_DeviceSecurityHandoffProbe_Native_probe_parent_to_O_claim_da536bc8 = 'Native probe parent-to-O claim';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:31 }
  CozyText_DeviceSecurityHandoffProbe_OBJECT_CLOSING_be8ab3c2 = 'OBJECT_CLOSING';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:98 }
  CozyText_DeviceSecurityHandoffProbe_O_signing_failed_6d9ac619 = 'O signing failed.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:102 }
  CozyText_DeviceSecurityHandoffProbe_PASS_independent_role_keys_bound_delegation_wron_771494cb = 'PASS: independent role keys, bound delegation, wrong-purpose rejection and cleanup.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:43 }
  CozyText_DeviceSecurityHandoffProbe_Parent_binding_changed_f1f6a147 = 'Parent binding changed.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:87 }
  CozyText_DeviceSecurityHandoffProbe_Role_signing_keys_must_be_independent_397e1366 = 'Role signing keys must be independent.';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:114 }
  CozyText_DeviceSecurityHandoffProbe_Text_f4d22b79 = ': ';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:64 }
  CozyText_DeviceSecurityHandoffProbe_UTF_8_150b21f4 = 'UTF-8: 한글';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:96 }
  CozyText_DeviceSecurityHandoffProbe_afterclose_2cb9e7cd = 'afterclose';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:48 }
  CozyText_DeviceSecurityHandoffProbe_changed_52bc1648 = 'changed';
  { Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr:64 }
  CozyText_DeviceSecurityHandoffProbe_contract_vector_ec26fa63 = 'contract-vector';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:282 }
  CozyText_HandoffCryptoProbe_000102030405060708090a0b_84f2465d = '000102030405060708090a0b';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:251 }
  CozyText_HandoffCryptoProbe_Active_decrypt_did_not_drain_d9960ec0 = 'Active decrypt did not drain.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:295 }
  CozyText_HandoffCryptoProbe_Bad_generic_tag_published_plaintext_8b07761e = 'Bad generic tag published plaintext.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:307 }
  CozyText_HandoffCryptoProbe_Borrowed_generic_key_was_modified_08681822 = 'Borrowed generic key was modified.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:127 }
  CozyText_HandoffCryptoProbe_Borrowed_input_was_modified_f2433e07 = 'Borrowed input was modified.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:126 }
  CozyText_HandoffCryptoProbe_Cancellation_published_output_3d76e8db = 'Cancellation published output.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:133 }
  CozyText_HandoffCryptoProbe_Cancellation_revived_consumed_decrypt_gate_5d631d18 = 'Cancellation revived consumed decrypt gate.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:255 }
  CozyText_HandoffCryptoProbe_Close_did_not_observe_caller_exit_63ebaaf7 = 'Close did not observe caller exit.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:238 }
  CozyText_HandoffCryptoProbe_Close_did_not_seal_admission_255f0ad5 = 'Close did not seal admission.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:258 }
  CozyText_HandoffCryptoProbe_Close_race_published_plaintext_or_failed_drain_c026abf4 = 'Close race published plaintext or failed drain.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:239 }
  CozyText_HandoffCryptoProbe_Close_returned_before_active_decrypt_drained_8d2036d9 = 'Close returned before active decrypt drained.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:61 }
  CozyText_HandoffCryptoProbe_Closed_cipher_admitted_a_new_call_f05c6031 = 'Closed cipher admitted a new call.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:245 }
  CozyText_HandoffCryptoProbe_Competing_decrypt_did_not_finish_832c81a0 = 'Competing decrypt did not finish.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:285 }
  CozyText_HandoffCryptoProbe_Digest_2e701768 = '3770bf6da491a736f924e4ff9c8d1919e2';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:285 }
  CozyText_HandoffCryptoProbe_Digest_4705cac3 = 'b6a3f882854a634bbcf8229d3802b75c';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:281 }
  CozyText_HandoffCryptoProbe_Digest_8a5a4ea8 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:327 }
  CozyText_HandoffCryptoProbe_FAIL_deb3e2a0 = 'FAIL: ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:227 }
  CozyText_HandoffCryptoProbe_First_decrypt_never_entered_6b38c314 = 'First decrypt never entered.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:290 }
  CozyText_HandoffCryptoProbe_Generic_GCM_fixture_mismatch_7e555ac4 = 'Generic GCM fixture mismatch.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:305 }
  CozyText_HandoffCryptoProbe_Generic_cancellation_published_plaintext_b89356a1 = 'Generic cancellation published plaintext.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:104 }
  CozyText_HandoffCryptoProbe_Good_envelope_revived_a_consumed_key_0fef053a = 'Good envelope revived a consumed key.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:103 }
  CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_ALREADY_CONSUMED_8d55e5b3 = 'HANDOFF_CIPHER_ALREADY_CONSUMED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:125 }
  CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_CANCELLED_c49cee74 = 'HANDOFF_CIPHER_CANCELLED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:97 }
  CozyText_HandoffCryptoProbe_HANDOFF_CIPHER_HEADER_INVALID_6304805b = 'HANDOFF_CIPHER_HEADER_INVALID';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:98 }
  CozyText_HandoffCryptoProbe_Malformed_first_attempt_was_not_rejected_13ad7eab = 'Malformed first attempt was not rejected.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:60 }
  CozyText_HandoffCryptoProbe_OBJECT_CLOSING_7e76a693 = 'OBJECT_CLOSING';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:325 }
  CozyText_HandoffCryptoProbe_PASS_actual_CNG_integrity_owned_output_cancellat_7800f479 = 'PASS: actual CNG integrity/owned-output/cancellation, invalid-first reuse rejection, concurrent one-use and Close drain.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:222 }
  CozyText_HandoffCryptoProbe_PROBE_BARRIER_TIMEOUT_588cdd11 = 'PROBE_BARRIER_TIMEOUT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:49 }
  CozyText_HandoffCryptoProbe_Plaintext_differs_0ca210ad = 'Plaintext differs.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:327 }
  CozyText_HandoffCryptoProbe_Text_63978312 = ': ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:248 }
  CozyText_HandoffCryptoProbe_Two_calls_consumed_the_same_wrapping_key_23fd1d3d = 'Two calls consumed the same wrapping key.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:51 }
  CozyText_HandoffCryptoProbe_Unauthenticated_plaintext_escaped_ddbb1db9 = 'Unauthenticated plaintext escaped.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:48 }
  CozyText_HandoffCryptoProbe_Valid_envelope_rejected_a33f5c65 = 'Valid envelope rejected.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:262 }
  CozyText_HandoffCryptoProbe_Winning_decrypt_failed_8d8e6d85 = 'Winning decrypt failed.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:56 }
  CozyText_HandoffCryptoProbe_Wrapping_key_decrypt_gate_reused_0e1d3055 = 'Wrapping key decrypt gate reused.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:283 }
  CozyText_HandoffCryptoProbe_handoff_probe_public_aad_384c8201 = 'handoff-probe-public-aad';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:284 }
  CozyText_HandoffCryptoProbe_private_test_data_f69b7cd9 = 'private-test-data';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:30 }
  CozyText_HandoffCryptoProbe_public_bootstrap_role_B_child_key_nonce_da98640d = 'public-bootstrap|role=B|child-key|nonce';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:82 }
  CozyText_HandoffCryptoProbe_public_test_role_B_key_nonce_6be2b493 = 'public-test|role=B|key|nonce';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr:81 }
  CozyText_HandoffCryptoProbe_temporary_private_handoff_test_payload_1baf0ad1 = 'temporary private handoff test payload';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:19 }
  CozyText_HandoffKdfProbe_Borrowed_seed_changed_345b11e4 = 'Borrowed seed changed';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:17 }
  CozyText_HandoffKdfProbe_Digest_40c22b53 = 'b145817b04a5edeb73fec608459213701b2fc7b16162690f9953c15368ec1e6f';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:33 }
  CozyText_HandoffKdfProbe_Fresh_seed_separation_failed_c2ef4cb2 = 'Fresh seed separation failed';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:15 }
  CozyText_HandoffKdfProbe_GAME_HANDOFF_V3_A_B_PUBLIC_TEST_b2414602 = 'GAME-HANDOFF-V3'#10'A->B'#10'PUBLIC-TEST';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:18 }
  CozyText_HandoffKdfProbe_Independent_upstream_KDF_vector_mismatch_b13609e5 = 'Independent upstream KDF vector mismatch';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:41 }
  CozyText_HandoffKdfProbe_Invalid_key_derivation_input_accepted_0da676c8 = 'Invalid key derivation input accepted';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:25 }
  CozyText_HandoffKdfProbe_Owned_KDF_differs_from_independent_vector_19a60728 = 'Owned KDF differs from independent vector';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:43 }
  CozyText_HandoffKdfProbe_PASS_HANDOFF_KDF_independent_vector_seed_transcr_7e7d0457 = 'PASS HANDOFF_KDF: independent vector, seed/transcript separation, borrowed input, bounds';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:30 }
  CozyText_HandoffKdfProbe_Transcript_separation_failed_69edce4d = 'Transcript separation failed';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr:35 }
  CozyText_HandoffKdfProbe_test_f5be38f8 = 'test';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:247 }
  CozyText_HandoffPipeContracts_PROBE_EXPIRED_EOF_ACCEPTED_678694a6 = 'PROBE_EXPIRED_EOF_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:371 }
  CozyText_HandoffPipeContracts_PROBE_FIELD_OVERFLOW_ACCEPTED_f12b9b94 = 'PROBE_FIELD_OVERFLOW_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:152 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_ARM_READER_f7cbb31a = 'PROBE_FRAGMENT_ARM_READER';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:169 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_BYTES_a16b0a97 = 'PROBE_FRAGMENT_BYTES';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:37 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_CANCEL_WAIT_f0fb35e9 = 'PROBE_FRAGMENT_CANCEL_WAIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:54 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_CLOSE_WAIT_5adcfd8f = 'PROBE_FRAGMENT_CLOSE_WAIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:74 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_CUT_af09d4ae = 'PROBE_FRAGMENT_CUT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:162 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_DEADLINE_RESTARTED_f75beb8e = 'PROBE_FRAGMENT_DEADLINE_RESTARTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:142 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_EVENTS_54984a84 = 'PROBE_FRAGMENT_EVENTS';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:45 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_FIRST_WRITE_2246c1ff = 'PROBE_FRAGMENT_FIRST_WRITE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:90 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_FRAME_SIZE_ca4edec6 = 'PROBE_FRAGMENT_FRAME_SIZE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:101 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_GUARD_CHANGED_b5c72177 = 'PROBE_FRAGMENT_GUARD_CHANGED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:172 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_HELLO_8a7446d3 = 'PROBE_FRAGMENT_HELLO';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:125 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_INPUT_a9089f07 = 'PROBE_FRAGMENT_INPUT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:165 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PARTIAL_OUTPUT_db845b2c = 'PROBE_FRAGMENT_PARTIAL_OUTPUT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:130 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PLAN_2a2e2fce = 'PROBE_FRAGMENT_PLAN';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:52 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PLAN_INCOMPLETE_1c6415cc = 'PROBE_FRAGMENT_PLAN_INCOMPLETE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:133 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PLAN_SIZE_8b10bbbb = 'PROBE_FRAGMENT_PLAN_SIZE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:187 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PROGRESS_4b68b201 = 'PROBE_FRAGMENT_PROGRESS';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:39 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_RANGE_2d36354a = 'PROBE_FRAGMENT_RANGE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:197 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_REMAINDER_2190e36f = 'PROBE_FRAGMENT_REMAINDER';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:49 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_START_GATE_e1d74120 = 'PROBE_FRAGMENT_START_GATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:145 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_THREAD_7af2793f = 'PROBE_FRAGMENT_THREAD';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:184 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITER_FAILED_f90a56f2 = 'PROBE_FRAGMENT_WRITER_FAILED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:185 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITER_HANDLE_22ea3b58 = 'PROBE_FRAGMENT_WRITER_HANDLE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:150 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITER_NOT_STARTED_c542a2bb = 'PROBE_FRAGMENT_WRITER_NOT_STARTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:41 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITE_2c156584 = 'PROBE_FRAGMENT_WRITE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:161 }
  CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRONG_OUTCOME_0175d4b6 = 'PROBE_FRAGMENT_WRONG_OUTCOME';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:360 }
  CozyText_HandoffPipeContracts_PROBE_HELLO_FAILURE_ACCEPTED_e63cd9d4 = 'PROBE_HELLO_FAILURE_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:367 }
  CozyText_HandoffPipeContracts_PROBE_NEGATIVE_READ_ACCEPTED_dcb294b6 = 'PROBE_NEGATIVE_READ_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:81 }
  CozyText_HandoffPipeContracts_PROBE_OWNED_HANDLE_CLOSE_7ff7b371 = 'PROBE_OWNED_HANDLE_CLOSE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:134 }
  CozyText_HandoffPipeContracts_PROBE_PIPE_CREATE_e80a470b = 'PROBE_PIPE_CREATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:336 }
  CozyText_HandoffPipeContracts_PROBE_PIPE_FAILURE_ACCEPTED_234352a8 = 'PROBE_PIPE_FAILURE_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:335 }
  CozyText_HandoffPipeContracts_PROBE_PIPE_ROUNDTRIP_49763021 = 'PROBE_PIPE_ROUNDTRIP';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc:375 }
  CozyText_HandoffPipeContracts_PROBE_PUBLIC_FRAME_OVERSIZE_ACCEPTED_245a3f79 = 'PROBE_PUBLIC_FRAME_OVERSIZE_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dpr:16 }
  CozyText_HandoffPipeProbe_FAIL_f2314237 = 'FAIL: ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dpr:13 }
  CozyText_HandoffPipeProbe_Fragment_writers_were_cancelled_joined_and_owned_52340e00 = 'Fragment writers were cancelled/joined and owned pipe/event/thread handles closed.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dpr:12 }
  CozyText_HandoffPipeProbe_PASS_f2f8c9a1 = 'PASS: ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dpr:16 }
  CozyText_HandoffPipeProbe_Text_553a537a = ': ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dpr:14 }
  CozyText_HandoffPipeProbe_This_does_not_test_child_processes_the_server_or_e8fa09c0 = 'This does not test child processes, the server, or Overlay graphics.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeProbe.dpr:12 }
  CozyText_HandoffPipeProbe_production_anonymous_pipe_range_fragment_deadlin_1f868d51 = ' production anonymous-pipe/range/fragment/deadline contracts.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:494 }
  CozyText_HandoffProcessContracts_Cozy_Handoff_Ownership_4784cef0 = 'Cozy-Handoff-Ownership-';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:137 }
  CozyText_HandoffProcessContracts_Cozy_restricted_overlay_native_compatibility_pro_2054f203 = 'Cozy restricted overlay native compatibility probe';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:263 }
  CozyText_HandoffProcessContracts_PROBE_ACL_INIT_9c520d75 = 'PROBE_ACL_INIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:267 }
  CozyText_HandoffProcessContracts_PROBE_ADMIN_ACE_f42d750b = 'PROBE_ADMIN_ACE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:259 }
  CozyText_HandoffProcessContracts_PROBE_ADMIN_SID_c697e89a = 'PROBE_ADMIN_SID';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:148 }
  CozyText_HandoffProcessContracts_PROBE_ARGUMENT_COUNT_9cb4e081 = 'PROBE_ARGUMENT_COUNT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:78 }
  CozyText_HandoffProcessContracts_PROBE_ARGUMENT_INVALID_f03f2651 = 'PROBE_ARGUMENT_INVALID';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:51 }
  CozyText_HandoffProcessContracts_PROBE_ATTRIBUTE_HANDLES_4ff9db6b = 'PROBE_ATTRIBUTE_HANDLES';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:47 }
  CozyText_HandoffProcessContracts_PROBE_ATTRIBUTE_INIT_5a574058 = 'PROBE_ATTRIBUTE_INIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:44 }
  CozyText_HandoffProcessContracts_PROBE_ATTRIBUTE_SIZE_35483083 = 'PROBE_ATTRIBUTE_SIZE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:357 }
  CozyText_HandoffProcessContracts_PROBE_CANCEL_RESET_3d75925a = 'PROBE_CANCEL_RESET';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:12 }
  CozyText_HandoffProcessContracts_PROBE_CHILD_DID_NOT_EXIT_e1945a63 = 'PROBE_CHILD_DID_NOT_EXIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:186 }
  CozyText_HandoffProcessContracts_PROBE_CHILD_HANDLE_TRANSFER_371d77cb = 'PROBE_CHILD_HANDLE_TRANSFER';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:152 }
  CozyText_HandoffProcessContracts_PROBE_CHILD_NOT_TERMINATED_31d5683c = 'PROBE_CHILD_NOT_TERMINATED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:150 }
  CozyText_HandoffProcessContracts_PROBE_CHILD_READY_f3ab716a = 'PROBE_CHILD_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:586 }
  CozyText_HandoffProcessContracts_PROBE_CHILD_START_5ae7ed87 = 'PROBE_CHILD_START';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:462 }
  CozyText_HandoffProcessContracts_PROBE_CONTEXT_PARENT_HANDLE_f16f9fe9 = 'PROBE_CONTEXT_PARENT_HANDLE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:465 }
  CozyText_HandoffProcessContracts_PROBE_CONTEXT_READY_HANDLE_71fd2bb8 = 'PROBE_CONTEXT_READY_HANDLE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:599 }
  CozyText_HandoffProcessContracts_PROBE_CONTROLLER_HANDLE_6210592a = 'PROBE_CONTROLLER_HANDLE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:600 }
  CozyText_HandoffProcessContracts_PROBE_CONTROL_PIPE_bce1a9c6 = 'PROBE_CONTROL_PIPE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:601 }
  CozyText_HandoffProcessContracts_PROBE_CONTROL_PRIVATE_58008935 = 'PROBE_CONTROL_PRIVATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:591 }
  CozyText_HandoffProcessContracts_PROBE_DEAD_CHILD_HELLO_ACCEPTED_aba0435c = 'PROBE_DEAD_CHILD_HELLO_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:166 }
  CozyText_HandoffProcessContracts_PROBE_DEAD_PARENT_ACCEPTED_75daf0ef = 'PROBE_DEAD_PARENT_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:487 }
  CozyText_HandoffProcessContracts_PROBE_DEAD_PARENT_CONFIRM_ACCEPTED_5348bc04 = 'PROBE_DEAD_PARENT_CONFIRM_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:481 }
  CozyText_HandoffProcessContracts_PROBE_DEAD_PARENT_READY_RESET_66815242 = 'PROBE_DEAD_PARENT_READY_RESET';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:269 }
  CozyText_HandoffProcessContracts_PROBE_DESCRIPTOR_DACL_fc651190 = 'PROBE_DESCRIPTOR_DACL';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:256 }
  CozyText_HandoffProcessContracts_PROBE_DESCRIPTOR_INIT_b2e4f4de = 'PROBE_DESCRIPTOR_INIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:362 }
  CozyText_HandoffProcessContracts_PROBE_EXPIRED_READY_ACCEPTED_694c24c7 = 'PROBE_EXPIRED_READY_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:512 }
  CozyText_HandoffProcessContracts_PROBE_FILE_TEST_CHANGED_PROCESS_STATE_f81ac955 = 'PROBE_FILE_TEST_CHANGED_PROCESS_STATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:221 }
  CozyText_HandoffProcessContracts_PROBE_FIXTURE_CREATE_9da80410 = 'PROBE_FIXTURE_CREATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:307 }
  CozyText_HandoffProcessContracts_PROBE_FIXTURE_DACL_RESTORE_747990cc = 'PROBE_FIXTURE_DACL_RESTORE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:272 }
  CozyText_HandoffProcessContracts_PROBE_FIXTURE_DACL_bff2f51e = 'PROBE_FIXTURE_DACL';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:223 }
  CozyText_HandoffProcessContracts_PROBE_FIXTURE_WRITE_5607daa3 = 'PROBE_FIXTURE_WRITE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:34 }
  CozyText_HandoffProcessContracts_PROBE_HANDLES_REQUIRED_93a74f53 = 'PROBE_HANDLES_REQUIRED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:39 }
  CozyText_HandoffProcessContracts_PROBE_HANDLE_INVALID_3e127347 = 'PROBE_HANDLE_INVALID';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:579 }
  CozyText_HandoffProcessContracts_PROBE_HELLO_PIPE_236c0da4 = 'PROBE_HELLO_PIPE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:580 }
  CozyText_HandoffProcessContracts_PROBE_HELLO_READ_PRIVATE_fe4f91dc = 'PROBE_HELLO_READ_PRIVATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:388 }
  CozyText_HandoffProcessContracts_PROBE_IDLE_PARENT_PUMP_NOT_ACCEPTED_b4891be2 = 'PROBE_IDLE_PARENT_PUMP_NOT_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:251 }
  CozyText_HandoffProcessContracts_PROBE_ORIGINAL_DACL_SIZE_b2220336 = 'PROBE_ORIGINAL_DACL_SIZE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:254 }
  CozyText_HandoffProcessContracts_PROBE_ORIGINAL_DACL_c2011c85 = 'PROBE_ORIGINAL_DACL';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:623 }
  CozyText_HandoffProcessContracts_PROBE_ORPHAN_REMAINS_dc4f615c = 'PROBE_ORPHAN_REMAINS';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:617 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_BODY_READY_e54ed6cc = 'PROBE_PARENT_BODY_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:197 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_NOT_TERMINATED_a20d81b9 = 'PROBE_PARENT_NOT_TERMINATED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:193 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_PARTIAL_READY_28cb1a40 = 'PROBE_PARENT_PARTIAL_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:178 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_PIPE_4aa15372 = 'PROBE_PARENT_PIPE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:406 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_PUMP_FAILURE_SWALLOWED_3fc41166 = 'PROBE_PARENT_PUMP_FAILURE_SWALLOWED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:441 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_PUMP_RESTARTED_DEADLINE_5223cb1a = 'PROBE_PARENT_PUMP_RESTARTED_DEADLINE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:398 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_RENEWAL_REJECTED_cb61e7f6 = 'PROBE_PARENT_RENEWAL_REJECTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:179 }
  CozyText_HandoffProcessContracts_PROBE_PARENT_WRITE_PRIVATE_df93bff8 = 'PROBE_PARENT_WRITE_PRIVATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:168 }
  CozyText_HandoffProcessContracts_PROBE_PARTIAL_BODY_MISSING_f60a24bc = 'PROBE_PARTIAL_BODY_MISSING';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:510 }
  CozyText_HandoffProcessContracts_PROBE_PIN_ALLOWS_REPLACE_5d0a5d6d = 'PROBE_PIN_ALLOWS_REPLACE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:507 }
  CozyText_HandoffProcessContracts_PROBE_PIN_ALLOWS_WRITE_16609791 = 'PROBE_PIN_ALLOWS_WRITE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:65 }
  CozyText_HandoffProcessContracts_PROBE_PROCESS_CREATE_a2e16ab8 = 'PROBE_PROCESS_CREATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:416 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_EVENT_c01f3b73 = 'PROBE_PUMP_CANCEL_EVENT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:423 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_READY_ACCEPTED_b239cc01 = 'PROBE_PUMP_CANCEL_READY_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:415 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_READY_ba1a2792 = 'PROBE_PUMP_CANCEL_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:424 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_RESET_87e65830 = 'PROBE_PUMP_CANCEL_RESET';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:425 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_DEADLINE_READY_RESET_eca01cf2 = 'PROBE_PUMP_DEADLINE_READY_RESET';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:390 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_FAILURE_RESET_cf426c27 = 'PROBE_PUMP_FAILURE_RESET';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:435 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_LATE_READY_cd5f9933 = 'PROBE_PUMP_LATE_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:376 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_READY_RESET_96b0d0dc = 'PROBE_PUMP_READY_RESET';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:383 }
  CozyText_HandoffProcessContracts_PROBE_PUMP_SET_READY_1505cbd0 = 'PROBE_PUMP_SET_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:350 }
  CozyText_HandoffProcessContracts_PROBE_RACE_CANCEL_7958a8f1 = 'PROBE_RACE_CANCEL';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:447 }
  CozyText_HandoffProcessContracts_PROBE_RACE_CHILD_EXIT_4cf03e12 = 'PROBE_RACE_CHILD_EXIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:347 }
  CozyText_HandoffProcessContracts_PROBE_RACE_CHILD_READY_517c8251 = 'PROBE_RACE_CHILD_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:344 }
  CozyText_HandoffProcessContracts_PROBE_RACE_EVENTS_38d0f68d = 'PROBE_RACE_EVENTS';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:446 }
  CozyText_HandoffProcessContracts_PROBE_RACE_RELEASE_0e99db10 = 'PROBE_RACE_RELEASE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:622 }
  CozyText_HandoffProcessContracts_PROBE_READER_FAILURE_REPORT_b1552566 = 'PROBE_READER_FAILURE_REPORT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:160 }
  CozyText_HandoffProcessContracts_PROBE_READER_GATE_ebf25a3a = 'PROBE_READER_GATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:615 }
  CozyText_HandoffProcessContracts_PROBE_READER_HANDLE_f06f5060 = 'PROBE_READER_HANDLE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:159 }
  CozyText_HandoffProcessContracts_PROBE_READER_READY_6683a3b6 = 'PROBE_READER_READY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:619 }
  CozyText_HandoffProcessContracts_PROBE_READER_RELEASE_18107680 = 'PROBE_READER_RELEASE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:616 }
  CozyText_HandoffProcessContracts_PROBE_READER_START_0e8e5e15 = 'PROBE_READER_START';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:374 }
  CozyText_HandoffProcessContracts_PROBE_READY_CALLED_PARENT_PUMP_d3916805 = 'PROBE_READY_CALLED_PARENT_PUMP';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:354 }
  CozyText_HandoffProcessContracts_PROBE_READY_CANCEL_ACCEPTED_6e84bb52 = 'PROBE_READY_CANCEL_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:453 }
  CozyText_HandoffProcessContracts_PROBE_READY_CHANGED_UNRELATED_EVENT_ba9bd581 = 'PROBE_READY_CHANGED_UNRELATED_EVENT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:451 }
  CozyText_HandoffProcessContracts_PROBE_READY_DEAD_CHILD_ACCEPTED_612ef97f = 'PROBE_READY_DEAD_CHILD_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:265 }
  CozyText_HandoffProcessContracts_PROBE_READ_ACE_ad03f429 = 'PROBE_READ_ACE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:537 }
  CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_CLEANUP_ACCEPTED_2f2ef5a1 = 'PROBE_REPLACEMENT_CLEANUP_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:529 }
  CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_IDENTITY_cb22c61e = 'PROBE_REPLACEMENT_IDENTITY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:541 }
  CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_OBSERVATION_cbb89e3c = 'PROBE_REPLACEMENT_OBSERVATION';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:543 }
  CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_REMOVED_6c2525fc = 'PROBE_REPLACEMENT_REMOVED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:519 }
  CozyText_HandoffProcessContracts_PROBE_REPLACE_AFTER_RELEASE_e22e68c5 = 'PROBE_REPLACE_AFTER_RELEASE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:134 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_ADMIN_WRITE_ALLOWED_de744350 = 'PROBE_RESTRICTED_ADMIN_WRITE_ALLOWED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:113 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_ARGUMENT_COUNT_c0d99d75 = 'PROBE_RESTRICTED_ARGUMENT_COUNT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:296 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_EXIT_CODE_25bc2020 = 'PROBE_RESTRICTED_CHILD_EXIT_CODE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:291 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_PREMATURE_EXIT_1b2d8744 = 'PROBE_RESTRICTED_CHILD_PREMATURE_EXIT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:289 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_REJECTED_5c6643a8 = 'PROBE_RESTRICTED_CHILD_REJECTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:294 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_REMAINS_21b9c0f6 = 'PROBE_RESTRICTED_CHILD_REMAINS';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:139 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CNG_SIGN_b6bf2e93 = 'PROBE_RESTRICTED_CNG_SIGN';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:279 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_EVENT_9276b5c9 = 'PROBE_RESTRICTED_EVENT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:127 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_FIXTURE_READ_7517469c = 'PROBE_RESTRICTED_FIXTURE_READ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:274 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_INPUT_1efb35ee = 'PROBE_RESTRICTED_INPUT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:275 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_INPUT_PRIVATE_4f1cafea = 'PROBE_RESTRICTED_INPUT_PRIVATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:119 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_PATH_SIZE_795ca715 = 'PROBE_RESTRICTED_PATH_SIZE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:143 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_RELEASE_4cdbf7f0 = 'PROBE_RESTRICTED_RELEASE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:292 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_RELEASE_EVENT_186c5c45 = 'PROBE_RESTRICTED_RELEASE_EVENT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:276 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_REPLY_6f58e255 = 'PROBE_RESTRICTED_REPLY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:277 }
  CozyText_HandoffProcessContracts_PROBE_RESTRICTED_REPLY_PRIVATE_e0985e34 = 'PROBE_RESTRICTED_REPLY_PRIVATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:602 }
  CozyText_HandoffProcessContracts_PROBE_RESULT_PIPE_dcc403f4 = 'PROBE_RESULT_PIPE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:603 }
  CozyText_HandoffProcessContracts_PROBE_RESULT_PRIVATE_36f1f9b1 = 'PROBE_RESULT_PRIVATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:532 }
  CozyText_HandoffProcessContracts_PROBE_STALE_PARENT_HANDLE_68df01f4 = 'PROBE_STALE_PARENT_HANDLE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:495 }
  CozyText_HandoffProcessContracts_PROBE_TEMP_DIRECTORY_6f5193f3 = 'PROBE_TEMP_DIRECTORY';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:492 }
  CozyText_HandoffProcessContracts_PROBE_TEMP_ID_bcaf1b9e = 'PROBE_TEMP_ID';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:491 }
  CozyText_HandoffProcessContracts_PROBE_TEMP_PATH_def6f461 = 'PROBE_TEMP_PATH';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:480 }
  CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_CLEANUP_REPORTED_9ce96262 = 'PROBE_UNCLAIMED_CLEANUP_REPORTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:469 }
  CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_CONFIRM_ACCEPTED_96947323 = 'PROBE_UNCLAIMED_CONFIRM_ACCEPTED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:477 }
  CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_PARENT_CLEANUP_a1da6294 = 'PROBE_UNCLAIMED_PARENT_CLEANUP';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:473 }
  CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_SELF_CLEANUP_5fe8252e = 'PROBE_UNCLAIMED_SELF_CLEANUP';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:608 }
  CozyText_HandoffProcessContracts_PROBE_UNRELATED_EVENT_718e2948 = 'PROBE_UNRELATED_EVENT';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:592 }
  CozyText_HandoffProcessContracts_PROBE_UNRELATED_EVENT_CHANGED_282883a5 = 'PROBE_UNRELATED_EVENT_CHANGED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:625 }
  CozyText_HandoffProcessContracts_PROBE_UNRELATED_HANDLE_CLOSED_d9d05279 = 'PROBE_UNRELATED_HANDLE_CLOSED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:624 }
  CozyText_HandoffProcessContracts_PROBE_UNRELATED_STATE_CHANGED_64547e53 = 'PROBE_UNRELATED_STATE_CHANGED';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:356 }
  CozyText_HandoffProcessContracts_PROBE_WAIT_CHANGED_CHILD_STATE_65adf972 = 'PROBE_WAIT_CHANGED_CHILD_STATE';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:262 }
  CozyText_HandoffProcessContracts_PROBE_WORLD_SID_976a7a39 = 'PROBE_WORLD_SID';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:36 }
  CozyText_HandoffProcessContracts_Text_7078d421 = '" ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:101 }
  CozyText_HandoffProcessContracts_handoff_probe_dying_child_755c5973 = '--handoff-probe-dying-child';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:103 }
  CozyText_HandoffProcessContracts_handoff_probe_orphan_reader_7455d879 = '--handoff-probe-orphan-reader';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:104 }
  CozyText_HandoffProcessContracts_handoff_probe_restricted_overlay_2043f006 = '--handoff-probe-restricted-overlay';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:102 }
  CozyText_HandoffProcessContracts_handoff_probe_writer_parent_1271ea3f = '--handoff-probe-writer-parent';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:496 }
  CozyText_HandoffProcessContracts_owned_fixture_91790b18 = 'owned.fixture';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc:497 }
  CozyText_HandoffProcessContracts_replacement_fixture_584c1be3 = 'replacement.fixture';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessProbe.dpr:19 }
  CozyText_HandoffProcessProbe_FAIL_59ea8206 = 'FAIL: ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessProbe.dpr:14 }
  CozyText_HandoffProcessProbe_PASS_a1181870 = 'PASS: ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessProbe.dpr:16 }
  CozyText_HandoffProcessProbe_Server_receipt_revocation_checks_run_separately__2c98cbcb = 'Server receipt/revocation checks run separately; this is not an A/B/O acceptance claim.';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessProbe.dpr:19 }
  CozyText_HandoffProcessProbe_Text_7567e595 = ': ';
  { Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessProbe.dpr:15 }
  CozyText_HandoffProcessProbe_actual_handoff_ownership_readiness_file_identity_352f6226 = ' actual handoff ownership, readiness, file identity and restricted-token contracts.';

implementation
end.
