unit Cozy.Strings.TestsFaultInjection;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.FaultInjection/Cozy.ClientFaultTest.dpr:12 }
  CozyText_ClientFaultTest_GAME_PRODUCT_FAULT_TEST_V1_a047a37f = 'GAME-PRODUCT-FAULT-TEST-V1';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LauncherFaultTest.dpr:12 }
  CozyText_LauncherFaultTest_GAME_PRODUCT_FAULT_TEST_V1_5227c4bd = 'GAME-PRODUCT-FAULT-TEST-V1';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:28 }
  CozyText_LicenseOwnershipProbe_ACD_e67ecad6 = 'ACD';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:20 }
  CozyText_LicenseOwnershipProbe_ALIAS_RETAINED_REVOKED_SECRET_9503dd55 = 'ALIAS_RETAINED_REVOKED_SECRET';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:45 }
  CozyText_LicenseOwnershipProbe_AUTH_STARTED_AFTER_STOP_a370fe3c = 'AUTH_STARTED_AFTER_STOP';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:33 }
  CozyText_LicenseOwnershipProbe_CANCEL_RETAINED_INPUT_4bce0729 = 'CANCEL_RETAINED_INPUT';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:26 }
  CozyText_LicenseOwnershipProbe_CD_b352f4e4 = 'CD';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:130 }
  CozyText_LicenseOwnershipProbe_CONSOLE_OWNERSHIP_FAIL_2475874b = 'CONSOLE_OWNERSHIP_FAIL ';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:129 }
  CozyText_LicenseOwnershipProbe_CONSOLE_OWNERSHIP_PASS_c5618465 = 'CONSOLE_OWNERSHIP_PASS ';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:67 }
  CozyText_LicenseOwnershipProbe_DUPLICATE_RESET_PROGRESS_4746b3ca = 'DUPLICATE_RESET_PROGRESS';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:28 }
  CozyText_LicenseOwnershipProbe_INPUT_COPY_OR_BACKSPACE_FAILED_c6986150 = 'INPUT_COPY_OR_BACKSPACE_FAILED';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:47 }
  CozyText_LicenseOwnershipProbe_LATE_REJECTION_REOPENED_INPUT_a268d8b2 = 'LATE_REJECTION_REOPENED_INPUT';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:42 }
  CozyText_LicenseOwnershipProbe_MAILBOX_DID_NOT_TRANSFER_OWNER_5ad4858e = 'MAILBOX_DID_NOT_TRANSFER_OWNER';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:31 }
  CozyText_LicenseOwnershipProbe_OVERFLOW_MUTATED_INPUT_b651efdc = 'OVERFLOW_MUTATED_INPUT';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:64 }
  CozyText_LicenseOwnershipProbe_PROGRESS_COMPLETED_BEFORE_TRANSFER_49e616c0 = 'PROGRESS_COMPLETED_BEFORE_TRANSFER';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:60 }
  CozyText_LicenseOwnershipProbe_PROGRESS_ENQUEUE_MISSING_e377e121 = 'PROGRESS_ENQUEUE_MISSING';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:76 }
  CozyText_LicenseOwnershipProbe_PROGRESS_NEW_ATTEMPT_NOT_RESET_23ce7302 = 'PROGRESS_NEW_ATTEMPT_NOT_RESET';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:62 }
  CozyText_LicenseOwnershipProbe_PROGRESS_REGRESSED_973f3640 = 'PROGRESS_REGRESSED';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:100 }
  CozyText_LicenseOwnershipProbe_RACE_OWNERSHIP_LOST_bffdceab = 'RACE_OWNERSHIP_LOST';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:102 }
  CozyText_LicenseOwnershipProbe_RACE_REPLY_TIMEOUT_1dbba71c = 'RACE_REPLY_TIMEOUT';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:109 }
  CozyText_LicenseOwnershipProbe_RACE_START_TIMEOUT_9f48cb7b = 'RACE_START_TIMEOUT';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:112 }
  CozyText_LicenseOwnershipProbe_RACE_STOP_TIMEOUT_20017762 = 'RACE_STOP_TIMEOUT';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:92 }
  CozyText_LicenseOwnershipProbe_RACE_SUBMIT_FAILED_69e94a95 = 'RACE_SUBMIT_FAILED';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:113 }
  CozyText_LicenseOwnershipProbe_RACE_WORKER_FAILED_b9180206 = 'RACE_WORKER_FAILED';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:117 }
  CozyText_LicenseOwnershipProbe_REAUTH_AFTER_TERMINAL_6d6d27ca = 'REAUTH_AFTER_TERMINAL';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:50 }
  CozyText_LicenseOwnershipProbe_REJECTED_INPUT_OWNER_LOST_478ea3d0 = 'REJECTED_INPUT_OWNER_LOST';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:115 }
  CozyText_LicenseOwnershipProbe_REJECTION_REOPENED_STOPPED_MAILBOX_2ee8c0a7 = 'REJECTION_REOPENED_STOPPED_MAILBOX';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:17 }
  CozyText_LicenseOwnershipProbe_RELEASE_REVOKED_OTHER_OWNER_83f5e27d = 'RELEASE_REVOKED_OTHER_OWNER';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:73 }
  CozyText_LicenseOwnershipProbe_RETRY_CLOSED_AFTER_REJECTION_65cc0796 = 'RETRY_CLOSED_AFTER_REJECTION';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:66 }
  CozyText_LicenseOwnershipProbe_RETRY_DUPLICATE_ACCEPTED_fd0f1b12 = 'RETRY_DUPLICATE_ACCEPTED';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:59 }
  CozyText_LicenseOwnershipProbe_RETRY_FIRST_OWNER_eba92d0f = 'RETRY_FIRST_OWNER';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:75 }
  CozyText_LicenseOwnershipProbe_RETRY_SECOND_OWNER_939f7bf3 = 'RETRY_SECOND_OWNER';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:70 }
  CozyText_LicenseOwnershipProbe_RETRY_TAKE_STATE_ef862e20 = 'RETRY_TAKE_STATE';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:79 }
  CozyText_LicenseOwnershipProbe_RETRY_TRANSFER_NOT_STICKY_7556a176 = 'RETRY_TRANSFER_NOT_STICKY';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:21 }
  CozyText_LicenseOwnershipProbe_REVOKED_SECRET_READABLE_4ced787e = 'REVOKED_SECRET_READABLE';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:49 }
  CozyText_LicenseOwnershipProbe_SUBMIT_AFTER_STOP_fdfa691c = 'SUBMIT_AFTER_STOP';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:118 }
  CozyText_LicenseOwnershipProbe_TERMINAL_QUEUE_NOT_EMPTY_9289aef1 = 'TERMINAL_QUEUE_NOT_EMPTY';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:114 }
  CozyText_LicenseOwnershipProbe_TRANSFER_OWNERSHIP_LOST_79454293 = 'TRANSFER_OWNERSHIP_LOST';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:65 }
  CozyText_LicenseOwnershipProbe_duplicate_key_f47a7406 = 'duplicate-key';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:58 }
  CozyText_LicenseOwnershipProbe_first_key_fd9373d5 = 'first-key';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:116 }
  CozyText_LicenseOwnershipProbe_late_key_bb25f43b = 'late-key';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:91 }
  CozyText_LicenseOwnershipProbe_race_key_70805df7 = 'race-key';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:48 }
  CozyText_LicenseOwnershipProbe_second_key_d96e1814 = 'second-key';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:13 }
  CozyText_LicenseOwnershipProbe_test_capability_eb02aa4e = 'test-capability';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.LicenseOwnershipProbe.dpr:41 }
  CozyText_LicenseOwnershipProbe_test_key_df35a21e = 'test-key';
  { Cozy.Tests/Cozy.FaultInjection/Cozy.OverlayFaultTest.dpr:12 }
  CozyText_OverlayFaultTest_GAME_PRODUCT_FAULT_TEST_V1_8df84c58 = 'GAME-PRODUCT-FAULT-TEST-V1';

implementation
end.
