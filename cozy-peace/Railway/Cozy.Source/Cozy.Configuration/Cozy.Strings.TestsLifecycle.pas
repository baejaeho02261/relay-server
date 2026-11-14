unit Cozy.Strings.TestsLifecycle;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:39 }
  CozyText_LifecycleContractsProbe_ACKNOWLEDGED_e3fbc2ce = 'ACKNOWLEDGED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:25 }
  CozyText_LifecycleContractsProbe_BACKWARD_PARENT_ORDER_4340cc6d = 'BACKWARD_PARENT_ORDER';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:26 }
  CozyText_LifecycleContractsProbe_BACKWARD_SELF_ORDER_4f7f93e2 = 'BACKWARD_SELF_ORDER';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:93 }
  CozyText_LifecycleContractsProbe_CHALLENGE_FAILURE_BLOCKED_CLEANUP_9cc13046 = 'CHALLENGE_FAILURE_BLOCKED_CLEANUP';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:111 }
  CozyText_LifecycleContractsProbe_CONTENDED_NOTE_NOT_DROPPED_2d71fc84 = 'CONTENDED_NOTE_NOT_DROPPED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:46 }
  CozyText_LifecycleContractsProbe_CONTRADICTORY_EXIT_SUCCESS_cb47320f = 'CONTRADICTORY_EXIT_SUCCESS';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:47 }
  CozyText_LifecycleContractsProbe_CONTRADICTORY_FILE_SUCCESS_a0cc61f4 = 'CONTRADICTORY_FILE_SUCCESS';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:76 }
  CozyText_LifecycleContractsProbe_DIAGNOSTIC_FAILURE_DELAY_df96caa7 = 'DIAGNOSTIC_FAILURE_DELAY';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:20 }
  CozyText_LifecycleContractsProbe_DUPLICATE_EVENT_c6240cd8 = 'DUPLICATE_EVENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:45 }
  CozyText_LifecycleContractsProbe_EXPECTED_OBSERVATION_COUNT_5367b05c = 'EXPECTED_OBSERVATION_COUNT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:79 }
  CozyText_LifecycleContractsProbe_EXPECTED_PREPARE_AND_REPORT_145d2ebb = 'EXPECTED_PREPARE_AND_REPORT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:72 }
  CozyText_LifecycleContractsProbe_EXPIRED_DEADLINE_SENT_d9403ab3 = 'EXPIRED_DEADLINE_SENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:47 }
  CozyText_LifecycleContractsProbe_FAILED_5444d33f = 'FAILED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:38 }
  CozyText_LifecycleContractsProbe_FILE_CLEANUP_20747a42 = 'FILE_CLEANUP';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:78 }
  CozyText_LifecycleContractsProbe_FILE_NOT_REMOVED_5f295a97 = 'FILE_NOT_REMOVED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:40 }
  CozyText_LifecycleContractsProbe_INVALID_NOTE_SERIALIZED_108040df = 'INVALID_NOTE_SERIALIZED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:23 }
  CozyText_LifecycleContractsProbe_LATE_EVENT_302b313e = 'LATE_EVENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:88 }
  CozyText_LifecycleContractsProbe_LATE_GRANT_INSTALLED_00ca5234 = 'LATE_GRANT_INSTALLED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:86 }
  CozyText_LifecycleContractsProbe_LATE_REPLY_PROBE_NOT_ENTERED_d9ebcc31 = 'LATE_REPLY_PROBE_NOT_ENTERED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:81 }
  CozyText_LifecycleContractsProbe_LATE_REPORT_RETRIED_80f437f5 = 'LATE_REPORT_RETRIED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:122 }
  CozyText_LifecycleContractsProbe_LIFECYCLE_CONTRACTS_FAIL_cd009e02 = 'LIFECYCLE_CONTRACTS_FAIL ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:121 }
  CozyText_LifecycleContractsProbe_LIFECYCLE_CONTRACTS_PASS_2d323cde = 'LIFECYCLE_CONTRACTS_PASS ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:107 }
  CozyText_LifecycleContractsProbe_LOCK_PROBE_START_6db69d99 = 'LOCK_PROBE_START';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:58 }
  CozyText_LifecycleContractsProbe_LOST_RESPONSE_a7b1bdee = 'LOST_RESPONSE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:109 }
  CozyText_LifecycleContractsProbe_NOTE_BLOCKED_ON_DIAGNOSTIC_LOCK_384c4136 = 'NOTE_BLOCKED_ON_DIAGNOSTIC_LOCK';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:37 }
  CozyText_LifecycleContractsProbe_OBSERVED_e4c9911b = 'OBSERVED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:21 }
  CozyText_LifecycleContractsProbe_ORDERED_PARENT_REMOVAL_b9351219 = 'ORDERED_PARENT_REMOVAL';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:18 }
  CozyText_LifecycleContractsProbe_PARENT_EXIT_132dbddc = 'PARENT_EXIT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:37 }
  CozyText_LifecycleContractsProbe_PROCESS_EXIT_f1acf170 = 'PROCESS_EXIT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:77 }
  CozyText_LifecycleContractsProbe_REAL_FILE_CLEANUP_BLOCKED_38b8a288 = 'REAL_FILE_CLEANUP_BLOCKED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:38 }
  CozyText_LifecycleContractsProbe_REMOVED_612f68ca = 'REMOVED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:74 }
  CozyText_LifecycleContractsProbe_REQUESTED_26d05d11 = 'REQUESTED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:15 }
  CozyText_LifecycleContractsProbe_SELF_EXIT_330e3c69 = 'SELF_EXIT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:39 }
  CozyText_LifecycleContractsProbe_SERVER_CONFIRMED_61a0699c = 'SERVER_CONFIRMED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:74 }
  CozyText_LifecycleContractsProbe_SHUTDOWN_BEGIN_06d2c0c3 = 'SHUTDOWN_BEGIN';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:31 }
  CozyText_LifecycleContractsProbe_SIMULATED_TRANSPORT_FAILURE_25509264 = 'SIMULATED_TRANSPORT_FAILURE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:46 }
  CozyText_LifecycleContractsProbe_TIMEOUT_0def29f1 = 'TIMEOUT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:28 }
  CozyText_LifecycleContractsProbe_TRANSFER_BEFORE_SHUTDOWN_86e221bd = 'TRANSFER_BEFORE_SHUTDOWN';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:17 }
  CozyText_LifecycleContractsProbe_UNOBSERVED_PARENT_REMOVAL_d1e25c21 = 'UNOBSERVED_PARENT_REMOVAL';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:16 }
  CozyText_LifecycleContractsProbe_WRONG_PARENT_d2899e46 = 'WRONG_PARENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:58 }
  CozyText_LifecycleContractsProbe_action_87a70e17 = 'action';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:63 }
  CozyText_LifecycleContractsProbe_expiresAt_d25c6756 = 'expiresAt';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:64 }
  CozyText_LifecycleContractsProbe_flowId_53c02827 = 'flowId';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:58 }
  CozyText_LifecycleContractsProbe_lifecycleReport_460903a8 = 'lifecycleReport';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:63 }
  CozyText_LifecycleContractsProbe_nonce_056552dd = 'nonce';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:62 }
  CozyText_LifecycleContractsProbe_permitId_cfbb73e2 = 'permitId';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:71 }
  CozyText_LifecycleContractsProbe_probe_token_e7b3a54a = 'probe-token';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:65 }
  CozyText_LifecycleContractsProbe_reporterRole_69effeed = 'reporterRole';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:64 }
  CozyText_LifecycleContractsProbe_serverTime_0844c317 = 'serverTime';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:46 }
  CozyText_LifecycleContractsProbe_status_2623dc33 = 'status';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:65 }
  CozyText_LifecycleContractsProbe_targetRole_062de784 = 'targetRole';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:66 }
  CozyText_LifecycleContractsProbe_targetSessionId_85715bab = 'targetSessionId';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifecycleContractsProbe.dpr:62 }
  CozyText_LifecycleContractsProbe_version_410bb1aa = 'version';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:36 }
  CozyText_LifetimeProbe_Lifetime_36c9400c = 'Lifetime: ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:81 }
  CozyText_LifetimeProbe_PASS_actual_atomic_gate_admission_close_race_ord_5d735e7a = 'PASS: actual atomic gate, admission/close race ordering, concurrent drain and repeated close.';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:88 }
  CozyText_LifetimeProbe_Text_b74d555d = ': ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:65 }
  CozyText_LifetimeProbe_admission_rejected_while_destructor_drains_84dc35ec = 'admission rejected while destructor drains';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:44 }
  CozyText_LifetimeProbe_close_waits_for_admitted_calls_e30f657a = 'close waits for admitted calls';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:45 }
  CozyText_LifetimeProbe_closed_gate_refuses_new_admission_ce0dd9c5 = 'closed gate refuses new admission';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:48 }
  CozyText_LifetimeProbe_closer_cannot_steal_the_last_caller_signal_befor_aff8bc87 = 'closer cannot steal the last-caller signal before it is sent';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:64 }
  CozyText_LifetimeProbe_concurrent_joins_cannot_finish_while_caller_rema_f29c3f6c = 'concurrent joins cannot finish while caller remains';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:46 }
  CozyText_LifetimeProbe_first_caller_does_not_signal_drain_5d9b7b1c = 'first caller does not signal drain';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:47 }
  CozyText_LifetimeProbe_last_caller_owns_drain_signal_7c8bfc5d = 'last caller owns drain signal';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:69 }
  CozyText_LifetimeProbe_last_leave_wakes_both_concurrent_joins_cf0c9cc7 = 'last leave wakes both concurrent joins';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:62 }
  CozyText_LifetimeProbe_other_thread_closes_admission_679690a1 = 'other thread closes admission';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:71 }
  CozyText_LifetimeProbe_repeated_close_is_idempotent_0bdcab46 = 'repeated close is idempotent';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:74 }
  CozyText_LifetimeProbe_throwing_admission_rejects_terminal_object_035c3e6f = 'throwing admission rejects terminal object';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:43 }
  CozyText_LifetimeProbe_two_admissions_d3e7c631 = 'two admissions';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.LifetimeProbe.dpr:51 }
  CozyText_LifetimeProbe_unbalanced_leave_rejected_82e55baf = 'unbalanced leave rejected';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:40 }
  CozyText_MeasurementLifetimeProbe_ADMISSION_TIMEOUT_5419e9cc = 'ADMISSION_TIMEOUT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:82 }
  CozyText_MeasurementLifetimeProbe_BOUNDED_READ_STATUS_3f1df03f = 'BOUNDED_READ_STATUS';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:153 }
  CozyText_MeasurementLifetimeProbe_BUNDLE_CANCEL_AFTER_DIGEST_NOT_REPORTED_ea53eec2 = 'BUNDLE_CANCEL_AFTER_DIGEST_NOT_REPORTED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:100 }
  CozyText_MeasurementLifetimeProbe_CALLER_FILE_POSITION_CHANGED_af074c42 = 'CALLER_FILE_POSITION_CHANGED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:48 }
  CozyText_MeasurementLifetimeProbe_CLOSING_DID_NOT_CANCEL_MEASUREMENT_7da491b6 = 'CLOSING_DID_NOT_CANCEL_MEASUREMENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:33 }
  CozyText_MeasurementLifetimeProbe_CODE_SIZE_19bf9afa = 'CODE_SIZE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:44 }
  CozyText_MeasurementLifetimeProbe_DESTROY_RELEASED_ACTIVE_OWNER_482a9df2 = 'DESTROY_RELEASED_ACTIVE_OWNER';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:177 }
  CozyText_MeasurementLifetimeProbe_DRAIN_SHUTDOWN_JOIN_FAILED_e22ef50c = 'DRAIN_SHUTDOWN_JOIN_FAILED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:164 }
  CozyText_MeasurementLifetimeProbe_DRAIN_SHUTDOWN_SOURCE_87582578 = 'DRAIN_SHUTDOWN_SOURCE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:125 }
  CozyText_MeasurementLifetimeProbe_DRAIN_START_FAILURE_LEAKED_OWNER_f62cb4d6 = 'DRAIN_START_FAILURE_LEAKED_OWNER';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:124 }
  CozyText_MeasurementLifetimeProbe_DRAIN_START_FAILURE_NOT_EXERCISED_bba669a9 = 'DRAIN_START_FAILURE_NOT_EXERCISED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:171 }
  CozyText_MeasurementLifetimeProbe_DRAIN_TAIL_COUNTER_NOT_ZERO_a5dcc709 = 'DRAIN_TAIL_COUNTER_NOT_ZERO';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:170 }
  CozyText_MeasurementLifetimeProbe_DRAIN_TAIL_NOT_ENTERED_11b1f8ad = 'DRAIN_TAIL_NOT_ENTERED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:46 }
  CozyText_MeasurementLifetimeProbe_DRAIN_TIMEOUT_2aa67254 = 'DRAIN_TIMEOUT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:103 }
  CozyText_MeasurementLifetimeProbe_EOF_PUBLISHED_BYTES_d8450217 = 'EOF_PUBLISHED_BYTES';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:154 }
  CozyText_MeasurementLifetimeProbe_FAILED_BUNDLE_TRANSFERRED_OUTPUT_6e34ffbb = 'FAILED_BUNDLE_TRANSFERRED_OUTPUT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:83 }
  CozyText_MeasurementLifetimeProbe_FAILED_READ_PUBLISHED_BYTES_6cec40a7 = 'FAILED_READ_PUBLISHED_BYTES';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:34 }
  CozyText_MeasurementLifetimeProbe_FILE_SIZE_db76ab99 = 'FILE_SIZE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:99 }
  CozyText_MeasurementLifetimeProbe_FULL_READ_CONTENT_336bd675 = 'FULL_READ_CONTENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:206 }
  CozyText_MeasurementLifetimeProbe_GameModuleGenerationFixture_53a22244 = 'GameModuleGenerationFixture';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:69 }
  CozyText_MeasurementLifetimeProbe_INTERNAL_CODE_CANCELLATION_1f1a9458 = 'INTERNAL_CODE_CANCELLATION';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:118 }
  CozyText_MeasurementLifetimeProbe_INVALID_SOURCE_HANDLE_ACCEPTED_964ad399 = 'INVALID_SOURCE_HANDLE_ACCEPTED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:182 }
  CozyText_MeasurementLifetimeProbe_MEASUREMENT_ADMISSION_AFTER_SHUTDOWN_148b76e1 = 'MEASUREMENT_ADMISSION_AFTER_SHUTDOWN';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:222 }
  CozyText_MeasurementLifetimeProbe_MEASUREMENT_PROBE_ARGUMENTS_0c31794a = 'MEASUREMENT_PROBE_ARGUMENTS';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:199 }
  CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_ALREADY_LOADED_9f0a63fe = 'MODULE_GENERATION_FIXTURE_ALREADY_LOADED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:204 }
  CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_LOAD_7c7bcde3 = 'MODULE_GENERATION_FIXTURE_LOAD';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:197 }
  CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_MISSING_567b0507 = 'MODULE_GENERATION_FIXTURE_MISSING';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:212 }
  CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_STILL_LOADED_abe785a5 = 'MODULE_GENERATION_FIXTURE_STILL_LOADED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:209 }
  CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_FIXTURE_UNLOAD_bf4c98b4 = 'MODULE_GENERATION_FIXTURE_UNLOAD';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:202 }
  CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_NOT_TRACKED_250469bb = 'MODULE_GENERATION_NOT_TRACKED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:198 }
  CozyText_MeasurementLifetimeProbe_MODULE_GENERATION_UNAVAILABLE_2879aef6 = 'MODULE_GENERATION_UNAVAILABLE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:208 }
  CozyText_MeasurementLifetimeProbe_MODULE_LOAD_NOT_OBSERVED_3529a93f = 'MODULE_LOAD_NOT_OBSERVED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:211 }
  CozyText_MeasurementLifetimeProbe_MODULE_UNLOAD_NOT_OBSERVED_c28271e1 = 'MODULE_UNLOAD_NOT_OBSERVED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:113 }
  CozyText_MeasurementLifetimeProbe_NIL_READ_BUFFER_ACCEPTED_965efc69 = 'NIL_READ_BUFFER_ACCEPTED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:140 }
  CozyText_MeasurementLifetimeProbe_OPEN_BUNDLE_SELF_ded0d650 = 'OPEN_BUNDLE_SELF';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:91 }
  CozyText_MeasurementLifetimeProbe_OPEN_READ_FIXTURE_0591c05b = 'OPEN_READ_FIXTURE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:18 }
  CozyText_MeasurementLifetimeProbe_OPEN_SELF_eddb837d = 'OPEN_SELF';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:115 }
  CozyText_MeasurementLifetimeProbe_OVERSIZED_READ_ACCEPTED_63fd31e8 = 'OVERSIZED_READ_ACCEPTED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:214 }
  CozyText_MeasurementLifetimeProbe_PASS_actual_loader_load_unload_reload_generation_6ab1285c = 'PASS actual loader load/unload/reload generation; final module membership unchanged';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:226 }
  CozyText_MeasurementLifetimeProbe_PASS_actual_retained_file_code_close_races_bound_ed5fdf8d = 'PASS actual retained file/code close races, bounded offsets, unchanged file position, cancellation and failed bundle ownership';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:95 }
  CozyText_MeasurementLifetimeProbe_POSITIONAL_READ_CONTENT_a563316f = 'POSITIONAL_READ_CONTENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:94 }
  CozyText_MeasurementLifetimeProbe_POSITIONAL_READ_HIGH_cf77515e = 'POSITIONAL_READ_HIGH';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:96 }
  CozyText_MeasurementLifetimeProbe_POSITIONAL_READ_REVERSE_5dc6bc59 = 'POSITIONAL_READ_REVERSE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:97 }
  CozyText_MeasurementLifetimeProbe_POSITIONAL_REVERSE_CONTENT_4a86c43d = 'POSITIONAL_REVERSE_CONTENT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:102 }
  CozyText_MeasurementLifetimeProbe_READ_EOF_608478f7 = 'READ_EOF';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:120 }
  CozyText_MeasurementLifetimeProbe_READ_OWNER_REMAINED_dd27c819 = 'READ_OWNER_REMAINED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:183 }
  CozyText_MeasurementLifetimeProbe_REJECTED_SHUTDOWN_READ_LEAKED_532713fc = 'REJECTED_SHUTDOWN_READ_LEAKED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:26 }
  CozyText_MeasurementLifetimeProbe_RESUME_TIMEOUT_0fcc24aa = 'RESUME_TIMEOUT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:92 }
  CozyText_MeasurementLifetimeProbe_SET_CALLER_OFFSET_11e3a5b7 = 'SET_CALLER_OFFSET';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:175 }
  CozyText_MeasurementLifetimeProbe_SHUTDOWN_ACCEPTED_COUNTER_BEFORE_THREAD_EXIT_22a20265 = 'SHUTDOWN_ACCEPTED_COUNTER_BEFORE_THREAD_EXIT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:198 }
  CozyText_MeasurementLifetimeProbe_TRACKED_6a82df8a = 'TRACKED';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:228 }
  CozyText_MeasurementLifetimeProbe_Text_f08fecb2 = ': ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:206 }
  CozyText_MeasurementLifetimeProbe_WRONG_MODULE_GENERATION_FIXTURE_887f440f = 'WRONG_MODULE_GENERATION_FIXTURE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.MeasurementLifetimeProbe.dpr:219 }
  CozyText_MeasurementLifetimeProbe_loader_fixture_478e61ef = '--loader-fixture';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:91 }
  CozyText_ThreadInventoryProbe_COMPLETE_5a37cb37 = 'COMPLETE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:98 }
  CozyText_ThreadInventoryProbe_OBSERVED_thread_start_inventory_bd6af40f = 'OBSERVED thread start inventory: ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:91 }
  CozyText_ThreadInventoryProbe_PARTIAL_1a72a6a0 = 'PARTIAL';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:100 }
  CozyText_ThreadInventoryProbe_PARTIAL_actual_Windows_thread_start_observation__11f2bfe3 = 'PARTIAL actual Windows thread start observation: bounded incomplete scan';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:143 }
  CozyText_ThreadInventoryProbe_PASS_own_process_thread_inventory_contracts_d644cd39 = 'PASS own-process thread inventory contracts: ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:49 }
  CozyText_ThreadInventoryProbe_SIMULATED_QUERY_EXCEPTION_ccac38f9 = 'SIMULATED_QUERY_EXCEPTION';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:99 }
  CozyText_ThreadInventoryProbe_SKIP_actual_Windows_thread_start_observation_nat_fd7ea1e5 = 'SKIP actual Windows thread start observation: native API unavailable';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:19 }
  CozyText_ThreadInventoryProbe_THREAD_INVENTORY_CONTRACT_1d3d8f19 = 'THREAD_INVENTORY_CONTRACT';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:144 }
  CozyText_ThreadInventoryProbe_Text_191fb4dc = ': ';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:91 }
  CozyText_ThreadInventoryProbe_UNAVAILABLE_9b4ecf6c = 'UNAVAILABLE';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:92 }
  CozyText_ThreadInventoryProbe_enumerated_b71d38c0 = 'enumerated';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:92 }
  CozyText_ThreadInventoryProbe_knownImage_a57d471b = 'knownImage';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:90 }
  CozyText_ThreadInventoryProbe_status_61f9c79e = 'status';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:93 }
  CozyText_ThreadInventoryProbe_unknownStart_bf26e165 = 'unknownStart';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:93 }
  CozyText_ThreadInventoryProbe_unreadable_aee2e4c9 = 'unreadable';
  { Cozy.Tests/Cozy.Lifecycle/Cozy.ThreadInventoryProbe.dpr:89 }
  CozyText_ThreadInventoryProbe_version_45042994 = 'version';

implementation
end.
