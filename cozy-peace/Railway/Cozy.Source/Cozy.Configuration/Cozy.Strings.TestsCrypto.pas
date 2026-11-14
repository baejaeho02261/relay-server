unit Cozy.Strings.TestsCrypto;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:202 }
  CozyText_Blake3ParallelProbe_BLAKE3_2019_12_27_16_29_52_test_vectors_context_f665d433 = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:256 }
  CozyText_Blake3ParallelProbe_BLAKE3_failed_Reset_lost_key_derive_mode_72665f2c = 'BLAKE3 failed Reset lost key/derive mode';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:225 }
  CozyText_Blake3ParallelProbe_Continued_update_mismatch_bfbe8e2e = 'Continued update mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:246 }
  CozyText_Blake3ParallelProbe_Executor_failure_accepted_0f2438ff = 'Executor failure accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:218 }
  CozyText_Blake3ParallelProbe_Expected_real_parallel_work_ae0923ea = 'Expected real parallel work';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:182 }
  CozyText_Blake3ParallelProbe_Failed_integrated_Finish_accepted_543a6b96 = 'Failed integrated Finish accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:188 }
  CozyText_Blake3ParallelProbe_Failed_integrated_Reset_did_not_clear_size_a20a6092 = 'Failed integrated Reset did not clear size';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:193 }
  CozyText_Blake3ParallelProbe_Failed_integrated_Reset_did_not_restore_all_dige_1acf20f3 = 'Failed integrated Reset did not restore all digests';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:185 }
  CozyText_Blake3ParallelProbe_Failed_integrated_Update_accepted_dc244884 = 'Failed integrated Update accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:249 }
  CozyText_Blake3ParallelProbe_Failed_stream_remained_usable_032d265d = 'Failed stream remained usable';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:236 }
  CozyText_Blake3ParallelProbe_Independent_digest_stream_mismatch_a822c968 = 'Independent digest stream mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:48 }
  CozyText_Blake3ParallelProbe_Injected_joined_failure_c9788303 = 'Injected joined failure';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:179 }
  CozyText_Blake3ParallelProbe_Integrated_executor_failure_accepted_24fc74b3 = 'Integrated executor failure accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:220 }
  CozyText_Blake3ParallelProbe_Mismatch_mode_d_prefix_d_size_d_workers_d_e0329370 = 'Mismatch mode=%d prefix=%d size=%d workers=%d';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:270 }
  CozyText_Blake3ParallelProbe_PASS_cases_8bb86ecb = 'PASS cases=';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:223 }
  CozyText_Blake3ParallelProbe_Parallel_finalization_mutated_state_729e4248 = 'Parallel finalization mutated state';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:148 }
  CozyText_Blake3ParallelProbe_Random_integrated_Finish_mutated_state_e407d10c = 'Random integrated Finish mutated state';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:153 }
  CozyText_Blake3ParallelProbe_Random_integrated_split_result_mismatch_ff5dba1b = 'Random integrated split result mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:124 }
  CozyText_Blake3ParallelProbe_Random_split_Finish_mutated_state_5832d717 = 'Random split Finish mutated state';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:129 }
  CozyText_Blake3ParallelProbe_Random_split_continue_after_Finish_mismatch_3cbd02fc = 'Random split continue-after-Finish mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:121 }
  CozyText_Blake3ParallelProbe_Random_split_mismatch_mode_d_trial_d_offset_d_wo_f8c69c11 = 'Random split mismatch mode=%d trial=%d offset=%d workers=%d';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:213 }
  CozyText_Blake3ParallelProbe_Snapshot_mutated_state_2201e806 = 'Snapshot mutated state';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:272 }
  CozyText_Blake3ParallelProbe_Text_aa226d92 = ': ';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:32 }
  CozyText_Blake3ParallelProbe_Thread_start_failed_4137b1a8 = 'Thread start failed';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:267 }
  CozyText_Blake3ParallelProbe_VECTOR_2347dc6b = 'VECTOR ';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:40 }
  CozyText_Blake3ParallelProbe_Worker_failed_ce84ed60 = 'Worker failed';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:270 }
  CozyText_Blake3ParallelProbe_batches_f77b783b = ' batches=';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:270 }
  CozyText_Blake3ParallelProbe_portableThreadStarts_8931cb63 = ' portableThreadStarts=';
  { Cozy.Tests/Cozy.Crypto/Cozy.Blake3ParallelProbe.dpr:201 }
  CozyText_Blake3ParallelProbe_whats_the_Elvish_word_for_friend_987eb351 = 'whats the Elvish word for friend';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:53 }
  CozyText_HashContracts_Derive_helper_mismatch_d4989547 = 'Derive helper mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:39 }
  CozyText_HashContracts_Hex_allocation_integer_overflow_accepted_1b50b6cf = 'Hex allocation integer overflow accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:44 }
  CozyText_HashContracts_Keyed_convenience_output_length_07c951ec = 'Keyed convenience output length';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:46 }
  CozyText_HashContracts_Keyed_helper_mismatch_9290411b = 'Keyed helper mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:33 }
  CozyText_HashContracts_Negative_XOF_length_accepted_caa66429 = 'Negative XOF length accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:25 }
  CozyText_HashContracts_Non_32_byte_key_accepted_6878c049 = 'Non-32-byte key accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:56 }
  CozyText_HashContracts_PASS_invalid_key_sizes_XOF_lengths_overflow_seek_af66901e = 'PASS: invalid key sizes, XOF lengths/overflow/seek, continued updates and keyed/derive helper contracts';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:57 }
  CozyText_HashContracts_Text_7069facb = ': ';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:36 }
  CozyText_HashContracts_XOF_position_overflow_accepted_ad7fe84f = 'XOF position overflow accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:41 }
  CozyText_HashContracts_XOF_seek_mismatch_54718f14 = 'XOF seek mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashContracts.dpr:30 }
  CozyText_HashContracts_Zero_length_XOF_failed_2b32dae6 = 'Zero length XOF failed';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:118 }
  CozyText_HashLifecycleProbe_A_borrowed_job_returned_before_completion_9703caa0 = 'A borrowed job returned before completion';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:221 }
  CozyText_HashLifecycleProbe_BLAKE3_leaf_cancellation_e0a5b75d = 'BLAKE3 leaf cancellation';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:219 }
  CozyText_HashLifecycleProbe_BLAKE3_leaf_cancellation_was_ignored_3c68f076 = 'BLAKE3 leaf cancellation was ignored';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:119 }
  CozyText_HashLifecycleProbe_Borrowed_context_used_after_its_lifetime_92fbf9e0 = 'Borrowed context used after its lifetime';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:224 }
  CozyText_HashLifecycleProbe_Cancelled_BLAKE3_digest_remained_readable_3b2b9eb8 = 'Cancelled BLAKE3 digest remained readable';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:195 }
  CozyText_HashLifecycleProbe_Cancelled_integrated_digest_accepted_Update_6ac53968 = 'Cancelled integrated digest accepted Update';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:192 }
  CozyText_HashLifecycleProbe_Cancelled_integrated_digest_remained_readable_dbed404d = 'Cancelled integrated digest remained readable';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:120 }
  CozyText_HashLifecycleProbe_Create_failure_dropped_work_e156a907 = 'Create failure dropped work';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:256 }
  CozyText_HashLifecycleProbe_Digest_fault_7fef52f9 = 'Digest fault';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:271 }
  CozyText_HashLifecycleProbe_Digest_fault_recovered_a39724c6 = 'Digest fault recovered';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:255 }
  CozyText_HashLifecycleProbe_Digest_fault_returned_wrong_success_failure_3ac64b6c = 'Digest fault returned wrong success/failure';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:70 }
  CozyText_HashLifecycleProbe_FAIL_d6c7a88e = 'FAIL: ';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:261 }
  CozyText_HashLifecycleProbe_Faulted_digest_remained_readable_1f645184 = 'Faulted digest remained readable';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:334 }
  CozyText_HashLifecycleProbe_Foreign_owner_accessed_a_shared_stream_3f515c62 = 'Foreign owner accessed a shared stream';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:337 }
  CozyText_HashLifecycleProbe_Foreign_owner_modified_BLAKE3_state_29f4dbda = 'Foreign owner modified BLAKE3 state';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:336 }
  CozyText_HashLifecycleProbe_Foreign_owner_modified_integrated_state_dd783d86 = 'Foreign owner modified integrated state';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:189 }
  CozyText_HashLifecycleProbe_Integrated_cancellation_c8129e42 = 'Integrated cancellation';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:188 }
  CozyText_HashLifecycleProbe_Integrated_cancellation_was_ignored_50927984 = 'Integrated cancellation was ignored';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:220 }
  CozyText_HashLifecycleProbe_Leaf_cancellation_was_not_exercised_a3fed2e5 = 'Leaf cancellation was not exercised';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:155 }
  CozyText_HashLifecycleProbe_Nested_executor_ran_borrowed_work_12903e37 = 'Nested executor ran borrowed work';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:153 }
  CozyText_HashLifecycleProbe_Nested_executor_rejection_e4c90c7e = 'Nested executor rejection';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:135 }
  CozyText_HashLifecycleProbe_Nested_executor_was_admitted_e312e289 = 'Nested executor was admitted';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:331 }
  CozyText_HashLifecycleProbe_Ownership_probe_join_failed_f4be1009 = 'Ownership probe join failed';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:328 }
  CozyText_HashLifecycleProbe_Ownership_probe_thread_could_not_start_09eda10e = 'Ownership probe thread could not start';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:368 }
  CozyText_HashLifecycleProbe_PASS_hash_lifecycle_cases_22108fd9 = 'PASS hash lifecycle cases=';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:121 }
  CozyText_HashLifecycleProbe_Precancelled_batch_started_work_bc131cb6 = 'Precancelled batch started work';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:309 }
  CozyText_HashLifecycleProbe_Reentrant_wrapper_access_was_not_rejected_2b7c099e = 'Reentrant wrapper access was not rejected';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:352 }
  CozyText_HashLifecycleProbe_Rejected_reentrancy_modified_BLAKE3_state_ec4635e6 = 'Rejected reentrancy modified BLAKE3 state';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:347 }
  CozyText_HashLifecycleProbe_Rejected_reentrancy_modified_wrapper_state_6e02c40c = 'Rejected reentrancy modified wrapper state';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:205 }
  CozyText_HashLifecycleProbe_Reset_after_cancellation_d7d1c81e = 'Reset after cancellation';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:204 }
  CozyText_HashLifecycleProbe_Reset_after_cancellation_did_not_recover_exact_d_2e071062 = 'Reset after cancellation did not recover exact digests';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:373 }
  CozyText_HashLifecycleProbe_Text_412c2a9c = ': ';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:270 }
  CozyText_HashLifecycleProbe_Thread_fault_fallback_reset_changed_exact_digest_921f6e78 = 'Thread fault fallback/reset changed exact digest';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:333 }
  CozyText_HashLifecycleProbe_Unexpected_foreign_owner_exception_e2441699 = 'Unexpected foreign-owner exception';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:154 }
  CozyText_HashLifecycleProbe_Worker_callback_reentry_was_not_rejected_8fbbad3a = 'Worker callback reentry was not rejected';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:117 }
  CozyText_HashLifecycleProbe_Worker_fault_ec280d28 = 'Worker fault';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:116 }
  CozyText_HashLifecycleProbe_Worker_fault_returned_wrong_success_failure_30d2de34 = 'Worker fault returned wrong success/failure';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:73 }
  CozyText_HashLifecycleProbe_borrowed_context_returned_before_join_0813eac0 = ': borrowed context returned before join';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:369 }
  CozyText_HashLifecycleProbe_cancellation_exact_reset_owner_reentrancy_create_0008f9e0 = ': cancellation, exact reset, owner/reentrancy, create/work/close faults, joined borrowed lifetimes';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:75 }
  CozyText_HashLifecycleProbe_pending_close_remained_418dcc38 = ': pending close remained';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:74 }
  CozyText_HashLifecycleProbe_thread_handle_not_closed_3b22372e = ': thread handle not closed';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashLifecycleProbe.dpr:70 }
  CozyText_HashLifecycleProbe_worker_remains_active_55c6470f = ': worker remains active';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:38 }
  CozyText_HashProbe_BLAKE3_2019_12_27_16_29_52_test_vectors_context_1bea33fc = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:66 }
  CozyText_HashProbe_BLAKE3_byte_array_API_mismatch_bbab11a7 = 'BLAKE3 byte-array API mismatch';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:59 }
  CozyText_HashProbe_Finalization_changed_final_state_de603090 = 'Finalization changed final state';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:54 }
  CozyText_HashProbe_Finalization_changed_the_streaming_state_bb006373 = 'Finalization changed the streaming state';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:36 }
  CozyText_HashProbe_Invalid_XOF_size_9eb99360 = 'Invalid XOF size';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:42 }
  CozyText_HashProbe_Invalid_mode_d3e23cc9 = 'Invalid mode';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:32 }
  CozyText_HashProbe_Invalid_update_size_9e4419d4 = 'Invalid update size';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:64 }
  CozyText_HashProbe_Streaming_differs_from_byte_array_API_0dc6bdaf = 'Streaming differs from byte-array API';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:75 }
  CozyText_HashProbe_Text_4d0878e4 = ': ';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:30 }
  CozyText_HashProbe_Usage_Cozy_HashProbe_file_update_size_hash_keyed_7030f71c = 'Usage: Cozy.HashProbe <file> <update-size> [hash|keyed|derive] [xof-bytes] [seek]';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:41 }
  CozyText_HashProbe_derive_afff3795 = 'derive';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:33 }
  CozyText_HashProbe_hash_dd1ef3c4 = 'hash';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:40 }
  CozyText_HashProbe_keyed_741b0ec6 = 'keyed';
  { Cozy.Tests/Cozy.Crypto/Cozy.HashProbe.dpr:37 }
  CozyText_HashProbe_whats_the_Elvish_word_for_friend_5905c7e3 = 'whats the Elvish word for friend';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:21 }
  CozyText_IntegrityHashProbe_BLAKE3_e9d7fc94 = ': BLAKE3';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:121 }
  CozyText_IntegrityHashProbe_Continue_after_finish_f00c9891 = 'Continue after finish';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:63 }
  CozyText_IntegrityHashProbe_Digest_5446e383 = '2882ebca04ec915ce95c42288f28186e';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:54 }
  CozyText_IntegrityHashProbe_Digest_546b7f99 = 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:58 }
  CozyText_IntegrityHashProbe_Digest_57a54ee6 = '06b05ab6733a618578af5f94892f3950';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:59 }
  CozyText_IntegrityHashProbe_Digest_6333269d = '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:62 }
  CozyText_IntegrityHashProbe_Digest_6b6ac4a2 = '1f0cb287c12671e2f498170ff2762886686ceb88b7d63f944708d3060752376ff38e4a88ab7ceb0bb437083e7f1d051049b8d94356e72e4d59adcc102f585ac0';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:57 }
  CozyText_IntegrityHashProbe_Digest_787909f9 = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:53 }
  CozyText_IntegrityHashProbe_Digest_8074d43c = '99aa06d3014798d86001c324468d497f';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:52 }
  CozyText_IntegrityHashProbe_Digest_951b1188 = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:64 }
  CozyText_IntegrityHashProbe_Digest_e0f5bad5 = 'd00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:99 }
  CozyText_IntegrityHashProbe_Empty_update_after_finish_4afa90e8 = 'Empty update after finish';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:141 }
  CozyText_IntegrityHashProbe_Invalid_chunk_size_559e3dc2 = 'Invalid chunk size';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:31 }
  CozyText_IntegrityHashProbe_Known_answer_BLAKE3_81721ad9 = 'Known-answer BLAKE3';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:29 }
  CozyText_IntegrityHashProbe_Known_answer_SHA_512_314975eb = 'Known-answer SHA-512';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:30 }
  CozyText_IntegrityHashProbe_Known_answer_XXH3_128_cc7ce9e4 = 'Known-answer XXH3-128';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:32 }
  CozyText_IntegrityHashProbe_Known_answer_size_a28c60ea = 'Known-answer size';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:104 }
  CozyText_IntegrityHashProbe_Nonempty_nil_input_accepted_8c415523 = 'Nonempty nil input accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:128 }
  CozyText_IntegrityHashProbe_PASS_common_hash_known_answers_380_chunk_partiti_639a7e34 = 'PASS: common hash known answers, 380 chunk partitions, repeated finish, continue/reset, nil/overflow rejection';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:119 }
  CozyText_IntegrityHashProbe_Partial_count_ca1781d6 = 'Partial count';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:96 }
  CozyText_IntegrityHashProbe_Partition_result_23a66450 = 'Partition result';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:92 }
  CozyText_IntegrityHashProbe_Prefix_snapshot_7ef21ed9 = 'Prefix snapshot';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:105 }
  CozyText_IntegrityHashProbe_Rejected_nil_preserves_stream_9d58cfb1 = 'Rejected nil preserves stream';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:111 }
  CozyText_IntegrityHashProbe_Rejected_overflow_preserves_stream_67f2dd5b = 'Rejected overflow preserves stream';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:97 }
  CozyText_IntegrityHashProbe_Repeated_final_snapshot_27168962 = 'Repeated final snapshot';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:93 }
  CozyText_IntegrityHashProbe_Repeated_prefix_9056ac4e = 'Repeated prefix';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:115 }
  CozyText_IntegrityHashProbe_Reset_returns_empty_digest_54de1931 = 'Reset returns empty digest';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:124 }
  CozyText_IntegrityHashProbe_Reuse_after_reset_48cda711 = 'Reuse after reset';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:19 }
  CozyText_IntegrityHashProbe_SHA_512_f60c756c = ': SHA-512';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:169 }
  CozyText_IntegrityHashProbe_Text_b70d3142 = ': ';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:139 }
  CozyText_IntegrityHashProbe_Usage_Cozy_IntegrityHashProbe_file_chunk_size_52210b73 = 'Usage: Cozy.IntegrityHashProbe [<file> <chunk-size>]';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:110 }
  CozyText_IntegrityHashProbe_Wrapping_address_range_accepted_e226d121 = 'Wrapping address range accepted';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:20 }
  CozyText_IntegrityHashProbe_XXH3_128_62f672f7 = ': XXH3-128';
  { Cozy.Tests/Cozy.Crypto/Cozy.IntegrityHashProbe.dpr:22 }
  CozyText_IntegrityHashProbe_byte_count_524ed3a3 = ': byte count';

implementation
end.
