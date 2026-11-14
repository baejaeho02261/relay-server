program Cozy_OverlayRenewalScheduleProbe;
{$APPTYPE CONSOLE}
{$RANGECHECKS ON}
{$OVERFLOWCHECKS ON}
uses
{ Cozy central text imports. }
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',

  System.SysUtils,
  Cozy.Overlay.State in '..\..\Cozy.Source\Cozy.Overlay\Cozy.Overlay.State.pas';
var Checks: Integer;
procedure Check(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(CozyText_OverlayRenewalScheduleProbe_FAIL_7000878b + Name);
  Inc(Checks);
  Writeln(CozyText_OverlayRenewalScheduleProbe_PASS_7a5abcc9 + Name);
end;
procedure ExpectExpired;
var Rejected: Boolean;
begin
  Rejected := False;
  try
    OverlayLeaseNeedsMaintenance(1000, 1000, 4000, True);
  except
    on E: Exception do Rejected := E.Message = CozyText_OverlayRenewalScheduleProbe_OVERLAY_LEASE_EXPIRED_739dd6c8;
  end;
  Check(Rejected, CozyText_OverlayRenewalScheduleProbe_maintenance_cannot_resurrect_expiry_c478eead);
end;
begin
  try
    Checks := 0;
    Check(OverlaySnapshotDue(100, 0, False), CozyText_OverlayRenewalScheduleProbe_initial_snapshot_mandatory_8da0a40a);
    Check(not OverlaySnapshotDue(100000, 10000, False), CozyText_OverlayRenewalScheduleProbe_confirm_transfer_before_full_rescan_2be3436b);
    Check(not OverlaySnapshotDue(62999, 48000, True), CozyText_OverlayRenewalScheduleProbe_not_due_before_15s_completion_ceiling_6d96427f);
    Check(OverlaySnapshotDue(63000, 48000, True), CozyText_OverlayRenewalScheduleProbe_complete_snapshot_due_at_15s_ceiling_7de91528);
    Check(OverlaySnapshotDue(47000, 48000, True), CozyText_OverlayRenewalScheduleProbe_backward_tick_schedules_fresh_measurement_withou_af2b71ab);
    Check(OverlayNextRenewal(54000, 80000, 53359) = 54000, CozyText_OverlayRenewalScheduleProbe_old_full_cost_estimate_renewed_immediately_d41d525a);
    Check(OverlayNextRenewal(54000, 80000, 5000) = 64000, CozyText_OverlayRenewalScheduleProbe_cheap_renewal_estimate_allows_first_frame_73702377);
    Check(not OverlayLeaseNeedsMaintenance(123, 0, 0, True), CozyText_OverlayRenewalScheduleProbe_initial_zero_grant_is_not_authorization_4be74644);
    Check(OverlayLeaseNeedsMaintenance(1000, 40000, 3000, True), CozyText_OverlayRenewalScheduleProbe_renew_before_periodic_scan_0e15ad5d);
    Check(not OverlayLeaseNeedsMaintenance(10000, 31000, 4000, False), CozyText_OverlayRenewalScheduleProbe_no_unnecessary_batch_renewal_c2efe1d3);
    Check(OverlayLeaseNeedsMaintenance(11000, 31000, 4000, False), CozyText_OverlayRenewalScheduleProbe_bounded_margin_between_batches_9b2763e5);
    Check(OverlaySnapshotDue(50000, 48000, True, 100000, 40000), CozyText_OverlayRenewalScheduleProbe_short_snapshot_bound_schedules_before_ceiling_40305007);
    Check(not OverlaySnapshotDue(50000, 48000, True, 160000, 40000), CozyText_OverlayRenewalScheduleProbe_ample_snapshot_window_does_not_force_scan_efa72230);
    Check(not OverlayLeaseNeedsMaintenance(11000, 31000, 4000, False, 31000), CozyText_OverlayRenewalScheduleProbe_do_not_repeat_proofs_at_unchanged_snapshot_ceili_a56db3d0);
    Check(OverlayLeaseNeedsMaintenance(11000, 31000, 4000, True, 31000), CozyText_OverlayRenewalScheduleProbe_explicit_pre_scan_force_is_still_checked_20b66f35);
    Check(OverlayLeaseNeedsMaintenance(11000, 31000, 4000, False, 120000), CozyText_OverlayRenewalScheduleProbe_new_own_proof_useful_below_snapshot_ceiling_91db6b41);
    Check(OverlayTransientRetryAllowed(1000, 22000, 3000, False, CozyText_OverlayRenewalScheduleProbe_CONNECT_TIMEOUT_3d7cdbe0), CozyText_OverlayRenewalScheduleProbe_one_transient_retry_within_old_grant_f4cafa2c);
    Check(not OverlayTransientRetryAllowed(1000, 22000, 3000, True, CozyText_OverlayRenewalScheduleProbe_CONNECT_TIMEOUT_3d7cdbe0), CozyText_OverlayRenewalScheduleProbe_second_retry_refused_75b315ee);
    Check(not OverlayTransientRetryAllowed(1000, 13000, 3000, False, CozyText_OverlayRenewalScheduleProbe_CONNECT_TIMEOUT_3d7cdbe0), CozyText_OverlayRenewalScheduleProbe_retry_reserve_boundary_refused_d4355358);
    Check(not OverlayTransientRetryAllowed(1000, 1000, 3000, False, CozyText_OverlayRenewalScheduleProbe_CONNECT_TIMEOUT_3d7cdbe0), CozyText_OverlayRenewalScheduleProbe_expired_retry_refused_bbeb5d5c);
    Check(not OverlayTransientRetryAllowed(1000, 50000, 3000, False, CozyText_OverlayRenewalScheduleProbe_CONNECT_CANCELLED_3e2b73af), CozyText_OverlayRenewalScheduleProbe_cancellation_never_retried_c611d391);
    Check(not OverlayTransientRetryAllowed(1000, 50000, 3000, False, CozyText_OverlayRenewalScheduleProbe_CONNECT_AUTHENTICATION_FAILED_d5a78617), CozyText_OverlayRenewalScheduleProbe_authentication_rejection_never_retried_38b15c17);
    Check(not OverlayTransientRetryAllowed(1000, 50000, 3000, False, CozyText_OverlayRenewalScheduleProbe_INTEGRITY_REJECTED_648afd6a), CozyText_OverlayRenewalScheduleProbe_integrity_rejection_never_retried_8144a605);
    Check(not OverlayTransientRetryAllowed(1000, 50000, 3000, False, CozyText_OverlayRenewalScheduleProbe_CONNECT_UNAVAILABLE_a8d3bf4d), CozyText_OverlayRenewalScheduleProbe_ambiguous_TLS_handshake_failure_never_retried_524d9b36);
    Check(not OverlayTransientRetryAllowed(1000, 50000, 3000, False, CozyText_OverlayRenewalScheduleProbe_CONNECT_RECEIVE_FAILED_e7a134e3), CozyText_OverlayRenewalScheduleProbe_ambiguous_TLS_record_failure_never_retried_6853e1fe);
    Check(not OverlayTransientRetryAllowed(1000, 120000, High(UInt64), False, CozyText_OverlayRenewalScheduleProbe_CONNECT_TIMEOUT_3d7cdbe0), CozyText_OverlayRenewalScheduleProbe_large_estimate_cannot_overflow_retry_admission_94dcfa31);
    ExpectExpired;
    Writeln(CozyText_OverlayRenewalScheduleProbe_SCHEDULING_PROBE_PASS_df352c54, Checks);
    Writeln(CozyText_OverlayRenewalScheduleProbe_Scheduling_only_not_an_overlay_rendering_server__f6dfc869);
  except
    on E: Exception do
    begin
      Writeln(E.ClassName + CozyText_OverlayRenewalScheduleProbe_Text_f3fc9c97 + E.Message);
      ExitCode := 1;
    end;
  end;
end.
