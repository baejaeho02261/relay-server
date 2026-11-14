{ Generated from contracts/runtime/peace.lifecycle-events-v1.json; checked by server contract test. }
const
  LifecycleContract = 'COZY-LIFECYCLE-EVENTS-V1';
  LifecycleSchemaSha512 = '27b6feba5ba4ebc6ec5385ef5ac4a18dc28bbd72a353acf280cafe47cb51102ed51aef7acc419ba1f7e54c7723ea8907c4afea72e717242eb93c4bc26e16655d';
  LifecycleMaximumEvents = 8;
  LifecycleRoleNames: array[TLifecycleRole] of string = ('A','B','O');
  LifecycleEventNames: array[TLifecycleEvent] of string = ('SHUTDOWN_BEGIN','CLOSE_RESPONSE','PROCESS_EXIT','FILE_CLEANUP','UI_HIDDEN','LEASE_EXPIRED','DOWNLOAD_DEADLINE','RENEWAL_FAILED','UI_RUNTIME_FAILURE');
  LifecycleStatusNames: array[TLifecycleStatus] of string = ('REQUESTED','ACKNOWLEDGED','FAILED','OBSERVED','TIMEOUT','UNKNOWN','REMOVED','NOT_ATTEMPTED','SCHEDULED');
  LifecycleEventStatuses: array[TLifecycleEvent] of TLifecycleStatuses = (
    [lsRequested],
    [lsAcknowledged,lsFailed],
    [lsObserved,lsTimeout,lsUnknown],
    [lsRemoved,lsFailed,lsNotAttempted,lsScheduled,lsTimeout,lsUnknown],
    [lsObserved],
    [lsObserved],
    [lsObserved],
    [lsTimeout,lsFailed],
    [lsFailed]);
