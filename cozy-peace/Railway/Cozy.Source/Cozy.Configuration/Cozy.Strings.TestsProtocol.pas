unit Cozy.Strings.TestsProtocol;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:106 }
  CozyText_DeterministicStateProbe_DETERMINISTIC_PROBE_JOIN_TIMEOUT_c5bec2a3 = 'DETERMINISTIC_PROBE_JOIN_TIMEOUT';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:32 }
  CozyText_DeterministicStateProbe_DETERMINISTIC_PROBE_c8b6d9dc = 'DETERMINISTIC_PROBE: ';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:147 }
  CozyText_DeterministicStateProbe_JsonFixture_8aaf6bff = '{"status":"PASS","observedTransitionMasks":[';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:129 }
  CozyText_DeterministicStateProbe_OVERLAY_STATE_TRANSITION_INVALID_f8db1c6d = 'OVERLAY_STATE_TRANSITION_INVALID';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:154 }
  CozyText_DeterministicStateProbe_Text_327c0545 = ': ';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:84 }
  CozyText_DeterministicStateProbe_admission_barrier_timeout_3dae3194 = 'admission barrier timeout';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:90 }
  CozyText_DeterministicStateProbe_caller_not_held_at_barrier_ce447d25 = 'caller not held at barrier';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:93 }
  CozyText_DeterministicStateProbe_close_altered_admitted_count_932416f5 = 'close altered admitted count';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:91 }
  CozyText_DeterministicStateProbe_close_drained_an_active_caller_dff4ae91 = 'close drained an active caller';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:101 }
  CozyText_DeterministicStateProbe_closed_gate_reopened_0d56d33f = 'closed gate reopened';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:96 }
  CozyText_DeterministicStateProbe_completion_barrier_timeout_b5cdf838 = 'completion barrier timeout';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:82 }
  CozyText_DeterministicStateProbe_empty_close_must_drain_d40f117b = 'empty close must drain';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:99 }
  CozyText_DeterministicStateProbe_final_state_not_drained_21e88f69 = 'final state not drained';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:149 }
  CozyText_DeterministicStateProbe_gpuExecuted_false_scope_STATE_AND_THREAD_ADMISSI_2f75a035 = ',"gpuExecuted":false,"scope":"STATE_AND_THREAD_ADMISSION_ONLY"}';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:129 }
  CozyText_DeterministicStateProbe_incorrect_exception_code_a3b53c3b = 'incorrect exception code';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:100 }
  CozyText_DeterministicStateProbe_last_caller_drain_notification_differs_5a4f8bba = 'last caller drain notification differs';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:88 }
  CozyText_DeterministicStateProbe_late_caller_changed_active_count_8aa3188b = 'late caller changed active count';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:87 }
  CozyText_DeterministicStateProbe_late_caller_was_admitted_after_close_774042ed = 'late caller was admitted after close';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:92 }
  CozyText_DeterministicStateProbe_new_caller_entered_closing_gate_4cf88fae = 'new caller entered closing gate';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:133 }
  CozyText_DeterministicStateProbe_rejection_modified_state_d4c04fb7 = 'rejection modified state';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:148 }
  CozyText_DeterministicStateProbe_scheduleChecks_12043441 = ',"scheduleChecks":';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:148 }
  CozyText_DeterministicStateProbe_stateChecks_5661d1e6 = '],"stateChecks":';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:132 }
  CozyText_DeterministicStateProbe_transition_disagrees_with_independent_matrix_726f354c = 'transition disagrees with independent matrix';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:135 }
  CozyText_DeterministicStateProbe_transition_failed_to_change_state_2f931336 = 'transition failed to change state';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:64 }
  CozyText_DeterministicStateProbe_worker_release_barrier_timeout_10588f33 = 'worker release barrier timeout';
  { Cozy.Tests/Cozy.Protocol/Cozy.DeterministicStateProbe.dpr:60 }
  CozyText_DeterministicStateProbe_worker_start_barrier_timeout_15324ea8 = 'worker start barrier timeout';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:12 }
  CozyText_FloatJsonProbe_0123456789abcdef_3d00742b = '0123456789abcdef';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:67 }
  CozyText_FloatJsonProbe_FLOAT_JSON_CORPUS_ARGUMENT_e3f545aa = 'FLOAT_JSON_CORPUS_ARGUMENT';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:81 }
  CozyText_FloatJsonProbe_FLOAT_JSON_CORPUS_COUNT_fc10f6d7 = 'FLOAT_JSON_CORPUS_COUNT';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:71 }
  CozyText_FloatJsonProbe_FLOAT_JSON_CORPUS_LIMIT_4f08c1f2 = 'FLOAT_JSON_CORPUS_LIMIT';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:87 }
  CozyText_FloatJsonProbe_Text_0b9c64e2 = ': ';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:35 }
  CozyText_FloatJsonProbe_accepted_5e80b6c8 = 'accepted';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:53 }
  CozyText_FloatJsonProbe_bodyHex_98e57e8f = 'bodyHex';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:55 }
  CozyText_FloatJsonProbe_bodySha512_66d4ea96 = 'bodySha512';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:52 }
  CozyText_FloatJsonProbe_bootstrap_59db76cf = 'bootstrap';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:54 }
  CozyText_FloatJsonProbe_envelopeHex_8a7535a9 = 'envelopeHex';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:56 }
  CozyText_FloatJsonProbe_envelopeSha512_c3f3c89f = 'envelopeSha512';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:36 }
  CozyText_FloatJsonProbe_errorClass_59574224 = 'errorClass';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:29 }
  CozyText_FloatJsonProbe_index_80e01ebf = 'index';
  { Cozy.Tests/Cozy.Protocol/Cozy.FloatJsonProbe.dpr:49 }
  CozyText_FloatJsonProbe_numberBits_f0a2a5cd = 'numberBits';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:37 }
  CozyText_JsonEnvelopeProbe_BORROWED_BODY_CHANGED_3c0e20ed = 'BORROWED_BODY_CHANGED';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:44 }
  CozyText_JsonEnvelopeProbe_ENVELOPE_LIMIT_ACCEPTED_73eb1d54 = 'ENVELOPE_LIMIT_ACCEPTED';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:16 }
  CozyText_JsonEnvelopeProbe_INVALID_DOCUMENT_ACCEPTED_d122fbd3 = 'INVALID_DOCUMENT_ACCEPTED';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:59 }
  CozyText_JsonEnvelopeProbe_JsonFixture_c676471f = '{"fixture":"quote\" slash\\ line\r\n ';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:98 }
  CozyText_JsonEnvelopeProbe_PASS_generated_response_evidence_documents_exact_adb043b2 = 'PASS generated response/evidence documents: exact fields, types, wrong role and duplicate rejection';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:99 }
  CozyText_JsonEnvelopeProbe_PASS_real_Delphi_schema_encoder_40_command_shape_67ad084e = 'PASS real Delphi schema/encoder: 40 command shapes, legacy byte equality, exact byte limit, unknown field rejection, signed string preservation';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:65 }
  CozyText_JsonEnvelopeProbe_SIGNED_PAYLOAD_BYTES_CHANGED_15036dbc = 'SIGNED_PAYLOAD_BYTES_CHANGED';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:100 }
  CozyText_JsonEnvelopeProbe_Text_637c11a1 = ': ';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:49 }
  CozyText_JsonEnvelopeProbe_UNDECLARED_FIELD_ACCEPTED_4c04a0f9 = 'UNDECLARED_FIELD_ACCEPTED';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:36 }
  CozyText_JsonEnvelopeProbe_WIRE_CHANGED_b53a80a0 = 'WIRE_CHANGED';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:25 }
  CozyText_JsonEnvelopeProbe_body_67083f07 = 'body';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:61 }
  CozyText_JsonEnvelopeProbe_execute_090658e3 = 'execute';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:45 }
  CozyText_JsonEnvelopeProbe_must_reject_b2bb4fe8 = 'must-reject';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:72 }
  CozyText_JsonEnvelopeProbe_name_2c9aa2be = 'name';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:26 }
  CozyText_JsonEnvelopeProbe_operation_3bedefb6 = 'operation';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:58 }
  CozyText_JsonEnvelopeProbe_payloadJSON_58ec79d3 = 'payloadJSON';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:86 }
  CozyText_JsonEnvelopeProbe_role_244e5106 = 'role';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:31 }
  CozyText_JsonEnvelopeProbe_tlsPinVersion_6fde483b = 'tlsPinVersion';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:45 }
  CozyText_JsonEnvelopeProbe_unexpected_28c3335b = 'unexpected';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:73 }
  CozyText_JsonEnvelopeProbe_value_204ba8d9 = 'value';
  { Cozy.Tests/Cozy.Protocol/Cozy.JsonEnvelopeProbe.dpr:59 }
  CozyText_JsonEnvelopeProbe_zero_u0000_6f362ec8 = ' zero\u0000"}';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:59 }
  CozyText_ProtocolJsonDifferentialProbe_JsonFixture_23665675 = '{"accepted":false}';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:32 }
  CozyText_ProtocolJsonDifferentialProbe_JsonFixture_41ee0373 = '{"kind":"COZY_PROTOCOL_JSON_NATIVE_V1","platform":"WIN64"}';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:57 }
  CozyText_ProtocolJsonDifferentialProbe_JsonFixture_a69af3e4 = '{"accepted":true,"value":';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:39 }
  CozyText_ProtocolJsonDifferentialProbe_PROBE_FRAME_LIMIT_5e772fac = 'PROBE_FRAME_LIMIT';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:29 }
  CozyText_ProtocolJsonDifferentialProbe_PROBE_NO_ARGUMENTS_8e9ad70d = 'PROBE_NO_ARGUMENTS';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:16 }
  CozyText_ProtocolJsonDifferentialProbe_PROBE_READ_FAILED_81570d6a = 'PROBE_READ_FAILED';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:20 }
  CozyText_ProtocolJsonDifferentialProbe_PROBE_TRUNCATED_FRAME_3a209f87 = 'PROBE_TRUNCATED_FRAME';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:53 }
  CozyText_ProtocolJsonDifferentialProbe_PROTOCOL_SCHEMA_INVALID_a62adc41 = 'PROTOCOL_SCHEMA_INVALID';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:51 }
  CozyText_ProtocolJsonDifferentialProbe_name_abc4b2f7 = 'name';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolJsonDifferentialProbe.dpr:52 }
  CozyText_ProtocolJsonDifferentialProbe_value_00267832 = 'value';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:9 }
  CozyText_ProtocolSchemaProbe_Digest_05f9222b = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:10 }
  CozyText_ProtocolSchemaProbe_Digest_425fb305 = 'd0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:11 }
  CozyText_ProtocolSchemaProbe_Digest_699a6697 = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:13 }
  CozyText_ProtocolSchemaProbe_Digest_69a30067 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:12 }
  CozyText_ProtocolSchemaProbe_Digest_a766c823 = '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:80 }
  CozyText_ProtocolSchemaProbe_FAIL_5c954936 = 'FAIL: ';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:73 }
  CozyText_ProtocolSchemaProbe_Full_file_SHA_512_width_is_invalid_8ac64bd8 = 'Full-file SHA-512 width is invalid.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:28 }
  CozyText_ProtocolSchemaProbe_Malformed_or_legacy_measurement_digest_accepted_f6c81761 = 'Malformed or legacy measurement digest accepted.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:64 }
  CozyText_ProtocolSchemaProbe_Native_CNG_SHA_512_abc_vector_failed_4131a44d = 'Native CNG SHA-512 abc vector failed.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:63 }
  CozyText_ProtocolSchemaProbe_Native_CNG_SHA_512_empty_vector_failed_8dd03723 = 'Native CNG SHA-512 empty vector failed.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:76 }
  CozyText_ProtocolSchemaProbe_No_server_connection_or_application_workflow_was_dcb08730 = 'No server connection or application workflow was started.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:74 }
  CozyText_ProtocolSchemaProbe_PASS_native_CNG_vectors_v3_digest_validation_ide_cd224218 = 'PASS: native CNG vectors, v3 digest validation, identity SHA-256 compatibility.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:55 }
  CozyText_ProtocolSchemaProbe_PASS_policy_request_schema_boundaries_43_accepte_f7f5c13a = 'PASS: policy request schema boundaries; 43 accepted, 75 rejected.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:54 }
  CozyText_ProtocolSchemaProbe_Policy_fixture_coverage_changed_9ccc6914 = 'Policy fixture coverage changed.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:48 }
  CozyText_ProtocolSchemaProbe_Policy_wire_boundary_mismatch_23f08e2e = 'Policy wire boundary mismatch: ';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:56 }
  CozyText_ProtocolSchemaProbe_Shape_validation_is_separate_from_server_signatu_320a8579 = 'Shape validation is separate from server signature, session, license and policy authorization.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:65 }
  CozyText_ProtocolSchemaProbe_Stable_identity_SHA_256_compatibility_failed_fb9b415b = 'Stable identity SHA-256 compatibility failed.';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:80 }
  CozyText_ProtocolSchemaProbe_Text_eb6e295e = ': ';
  { Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr:64 }
  CozyText_ProtocolSchemaProbe_abc_47ac2fc6 = 'abc';

implementation
end.
