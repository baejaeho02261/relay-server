unit Cozy.Strings.Crypto;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:183 }
  CozyText_Hashes_0123456789abcdef_49c83f57 = '0123456789abcdef';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:655 }
  CozyText_Hashes_BLAKE3_XOF_offset_overflow_d151735a = 'BLAKE3 XOF offset overflow';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:366 }
  CozyText_Hashes_BLAKE3_hash_input_is_nil_98bc7188 = 'BLAKE3 hash input is nil.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:693 }
  CozyText_Hashes_BLAKE3_hex_output_too_large_7ad5cccc = 'BLAKE3 hex output too large';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:438 }
  CozyText_Hashes_BLAKE3_input_exceeds_2_64_1_bytes_78f05c30 = 'BLAKE3 input exceeds 2^64-1 bytes.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:369 }
  CozyText_Hashes_BLAKE3_input_length_overflow_76e85319 = 'BLAKE3 input length overflow.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:310 }
  CozyText_Hashes_BLAKE3_key_must_be_32_bytes_bc7b4518 = 'BLAKE3 key must be 32 bytes';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:353 }
  CozyText_Hashes_BLAKE3_operation_already_active_e8fdb6d0 = 'BLAKE3 operation already active.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:352 }
  CozyText_Hashes_BLAKE3_owner_thread_required_aaadae16 = 'BLAKE3 owner thread required.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:362 }
  CozyText_Hashes_BLAKE3_stream_failed_8b61c9d6 = 'BLAKE3 stream failed.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:416 }
  CozyText_Hashes_BLAKE3_tree_capacity_exceeded_b10afae1 = 'BLAKE3 tree capacity exceeded.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:617 }
  CozyText_Hashes_BLAKE3_worker_incomplete_179efd16 = 'BLAKE3 worker incomplete.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:364 }
  CozyText_Hashes_BLAKE3_workers_must_be_1_4_05cbc465 = 'BLAKE3 workers must be 1..4.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:162 }
  CozyText_Hashes_Hash_operation_cancelled_184f5b9d = 'Hash operation cancelled.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:817 }
  CozyText_Hashes_Integrity_hash_input_is_nil_b7f4a41f = 'Integrity hash input is nil.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:820 }
  CozyText_Hashes_Integrity_hash_input_length_overflow_c80d860e = 'Integrity hash input length overflow.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:727 }
  CozyText_Hashes_Integrity_hash_operation_already_active_3a869710 = 'Integrity hash operation already active.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:726 }
  CozyText_Hashes_Integrity_hash_owner_thread_required_3d5e626a = 'Integrity hash owner thread required.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:737 }
  CozyText_Hashes_Integrity_hash_stream_requires_reset_0ca1f3cf = 'Integrity hash stream requires reset.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:408 }
  CozyText_Hashes_Invalid_BLAKE3_tree_state_09870f1c = 'Invalid BLAKE3 tree state.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.pas:654 }
  CozyText_Hashes_Negative_BLAKE3_output_length_ec1c9635 = 'Negative BLAKE3 output length';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.SHA512.pas:121 }
  CozyText_Hashes_SHA512_0123456789abcdef_bd95c923 = '0123456789abcdef';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.SHA512.pas:95 }
  CozyText_Hashes_SHA512_SHA512_input_length_overflow_138f0d73 = 'SHA512 input length overflow';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.SelfTest.pas:79 }
  CozyText_Hashes_SelfTest_BLAKE3_2019_12_27_16_29_52_test_vectors_context_c78916f2 = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.SelfTest.pas:78 }
  CozyText_Hashes_SelfTest_whats_the_Elvish_word_for_friend_eb04f1bf = 'whats the Elvish word for friend';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:249 }
  CozyText_Hashes_Workers_BLAKE3_worker_failed_bf245f4e = 'BLAKE3 worker failed.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:262 }
  CozyText_Hashes_Workers_BLAKE3_worker_handle_close_failed_207993b0 = 'BLAKE3 worker handle close failed.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:283 }
  CozyText_Hashes_Workers_Cannot_reset_probe_while_cleanup_is_pending_62aeacc7 = 'Cannot reset probe while cleanup is pending.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:248 }
  CozyText_Hashes_Workers_Hash_operation_cancelled_e99dfbd6 = 'Hash operation cancelled.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:191 }
  CozyText_Hashes_Workers_Hash_worker_executor_is_not_reentrant_ba08b5b8 = 'Hash worker executor is not reentrant.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:165 }
  CozyText_Hashes_Workers_Hash_worker_handle_cleanup_pending_854d2d7d = 'Hash worker handle cleanup pending.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:84 }
  CozyText_Hashes_Workers_Injected_hash_worker_failure_a2942a85 = 'Injected hash worker failure.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:189 }
  CozyText_Hashes_Workers_Invalid_BLAKE3_worker_batch_8bd9d13f = 'Invalid BLAKE3 worker batch.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:278 }
  CozyText_Hashes_Workers_Invalid_hash_worker_fault_position_fb8cac9f = 'Invalid hash worker fault position.';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.Workers.pas:324 }
  CozyText_Hashes_Workers_kernel32_dll_adca97e9 = 'kernel32.dll';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.XXH3.pas:251 }
  CozyText_Hashes_XXH3_0123456789abcdef_1affd556 = '0123456789abcdef';
  { Cozy.Source/Cozy.Crypto/Cozy.Hashes.XXH3.pas:231 }
  CozyText_Hashes_XXH3_XXH3_input_length_overflow_f56c4374 = 'XXH3 input length overflow';

implementation
end.
