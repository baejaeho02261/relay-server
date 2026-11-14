program Cozy_LicenseStateProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
{$R+}
{$Q+}
{$IFNDEF GAME_LICENSE_CONTRACT_TESTS}
  {$IFDEF FPC}
    {$FATAL Compile with GAME_LICENSE_CONTRACT_TESTS}
  {$ELSE}
    {$MESSAGE FATAL 'Compile with GAME_LICENSE_CONTRACT_TESTS'}
  {$ENDIF}
{$ENDIF}

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',

  {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF}, Cozy.Api.Types;

{ Executes the production TLicenseState methods with a deterministic clock.
  Only the platform clock binding is replaced by the test build define.
  No application process, server, handoff or license is created by this probe. }

var
  Cases: Integer;

procedure Check(Value: Boolean; const MessageText: string);
begin
  if not Value then raise Exception.Create(MessageText);
end;

function ActiveState: TLicenseState;
begin
  Result := Default(TLicenseState);
  Result.LicenseID := CozyText_LicenseStateProbe_DL_00112233445566778899AABB_6aaaaec1;
  Result.DeviceID := CozyText_LicenseStateProbe_probe_device_540c20cd;
  Result.Status := CozyText_LicenseStateProbe_USED_403576ef;
  Result.ServerTime := 1000000;
  Result.LeaseExpiresAt := 1120000;
  Result.ExpiresAt := 4600000;
  Result.VerifiedAtTick := 10000;
  Result.LeaseDeadlineTick := 130000;
end;

procedure Expect(const Name: string; const State: TLicenseState; Tick: UInt64;
  Active: Boolean; LeaseSeconds: Integer; LicenseSeconds: Int64);
begin
  LicenseStateProbeSetTick(Tick);
  Check(State.IsActive = Active, Name + CozyText_LicenseStateProbe_IsActive_5bc67a7a);
  Check(LicenseStateProbeTickReads = 1, Name + CozyText_LicenseStateProbe_IsActive_clock_sample_4fff7a08);
  LicenseStateProbeSetTick(Tick);
  Check(State.RemainingLeaseSeconds = LeaseSeconds, Name + CozyText_LicenseStateProbe_lease_seconds_713e9b5e);
  Check(LicenseStateProbeTickReads = 1, Name + CozyText_LicenseStateProbe_lease_clock_sample_d4706ba4);
  LicenseStateProbeSetTick(Tick);
  Check(State.RemainingLicenseSeconds = LicenseSeconds, Name + CozyText_LicenseStateProbe_license_seconds_c5bc49da);
  Check(LicenseStateProbeTickReads = 1, Name + CozyText_LicenseStateProbe_license_clock_sample_7b1ce052);
  Inc(Cases);
  Writeln(CozyText_LicenseStateProbe_PASS_bb0cffc5, Name);
end;

procedure Reject(const Name: string; const State: TLicenseState; Tick: UInt64);
begin
  Expect(Name, State, Tick, False, 0, 0);
end;

procedure Run;
var
  State: TLicenseState;
begin
  State := ActiveState;
  Expect(CozyText_LicenseStateProbe_Full_authorized_lease_c1bf70bb, State, 10000, True, 120, 3600);
  Expect(CozyText_LicenseStateProbe_One_millisecond_elapsed_6ec6b9e7, State, 10001, True, 120, 3600);
  Expect(CozyText_LicenseStateProbe_Exact_second_elapsed_b6c1c18a, State, 11000, True, 119, 3599);
  Expect(CozyText_LicenseStateProbe_Last_authorized_millisecond_37f45ca4, State, 129999, True, 1, 3481);
  Reject(CozyText_LicenseStateProbe_Exact_lease_expiry_88f7515e, State, 130000);
  Reject(CozyText_LicenseStateProbe_Past_lease_expiry_6eb5201f, State, 130001);
  Reject(CozyText_LicenseStateProbe_Monotonic_clock_rollback_5662ad99, State, 9999);
  State.LeaseDeadlineTick := 20000;
  Expect(CozyText_LicenseStateProbe_Network_latency_shortens_lease_c15783bb, State, 10000, True, 10, 3600);
  State := ActiveState;
  State.ExpiresAt := 0;
  Expect(CozyText_LicenseStateProbe_Perpetual_license_still_requires_a_live_lease_f82d7881, State, 10000, True, 120, -1);
  Reject(CozyText_LicenseStateProbe_Perpetual_license_with_expired_lease_fb2acb97, State, 130000);
  State := ActiveState;
  State.LeaseExpiresAt := State.ServerTime + 1;
  State.ExpiresAt := State.LeaseExpiresAt;
  State.LeaseDeadlineTick := State.VerifiedAtTick + 1;
  Expect(CozyText_LicenseStateProbe_One_millisecond_grant_rounds_up_021863af, State, 10000, True, 1, 1);
  Reject(CozyText_LicenseStateProbe_One_millisecond_grant_expired_e2facdad, State, 10001);

  State := Default(TLicenseState);
  Reject(CozyText_LicenseStateProbe_Uninitialized_record_bd699ba5, State, 10000);
  State := ActiveState; State.Status := CozyText_LicenseStateProbe_ACTIVE_098f897d;
  Reject(CozyText_LicenseStateProbe_Unapproved_status_c1f28190, State, 10000);
  State := ActiveState; State.LicenseID := '';
  Reject(CozyText_LicenseStateProbe_Missing_license_identity_d4f70be5, State, 10000);
  State := ActiveState; State.DeviceID := '';
  Reject(CozyText_LicenseStateProbe_Missing_device_identity_b9cdabb3, State, 10000);
  State := ActiveState; State.VerifiedAtTick := 0;
  Reject(CozyText_LicenseStateProbe_Missing_verification_clock_c4dae2af, State, 10000);
  State := ActiveState; State.VerifiedAtTick := 10001;
  Reject(CozyText_LicenseStateProbe_Future_verification_clock_bad77461, State, 10000);
  State := ActiveState; State.LeaseDeadlineTick := 0;
  Reject(CozyText_LicenseStateProbe_Missing_lease_deadline_bb8d6854, State, 10000);
  State := ActiveState; State.LeaseDeadlineTick := 10000;
  Reject(CozyText_LicenseStateProbe_Empty_local_lease_637024ee, State, 10000);
  State := ActiveState; State.LeaseDeadlineTick := 9999;
  Reject(CozyText_LicenseStateProbe_Reversed_local_lease_d7841c5a, State, 10000);
  State := ActiveState; State.LeaseDeadlineTick := 130001;
  Reject(CozyText_LicenseStateProbe_Local_deadline_exceeds_server_grant_7e2107bc, State, 10000);
  State := ActiveState; State.LeaseExpiresAt := 1120001;
  Reject(CozyText_LicenseStateProbe_Server_lease_exceeds_protocol_bound_2b61717e, State, 10000);
  State := ActiveState; State.LeaseExpiresAt := State.ServerTime;
  Reject(CozyText_LicenseStateProbe_Empty_server_lease_8c3ec735, State, 10000);
  State := ActiveState; State.LeaseExpiresAt := State.ServerTime - 1;
  Reject(CozyText_LicenseStateProbe_Reversed_server_lease_45623f23, State, 10000);
  State := ActiveState; State.ServerTime := 0;
  Reject(CozyText_LicenseStateProbe_Zero_server_time_84e347d0, State, 10000);
  State := ActiveState; State.ServerTime := Low(Int64);
  Reject(CozyText_LicenseStateProbe_Minimum_signed_server_time_3b2b1329, State, 10000);
  State := ActiveState; State.LeaseExpiresAt := Low(Int64);
  Reject(CozyText_LicenseStateProbe_Minimum_signed_lease_expiry_2018db01, State, 10000);
  State := ActiveState; State.ExpiresAt := Low(Int64);
  Reject(CozyText_LicenseStateProbe_Minimum_signed_license_expiry_3a025fb7, State, 10000);
  State := ActiveState; State.ExpiresAt := -1;
  Reject(CozyText_LicenseStateProbe_Negative_finite_expiry_9d34c098, State, 10000);
  State := ActiveState; State.ExpiresAt := State.ServerTime;
  Reject(CozyText_LicenseStateProbe_Already_expired_license_d2570549, State, 10000);
  State := ActiveState; State.ExpiresAt := State.LeaseExpiresAt - 1;
  Reject(CozyText_LicenseStateProbe_Lease_extends_beyond_license_1b54a719, State, 10000);

  State := ActiveState; State.LeaseDeadlineTick := High(UInt64);
  Reject(CozyText_LicenseStateProbe_Maximum_unsigned_deadline_cannot_round_into_vali_a66449ba, State, 10000);
  State := ActiveState;
  State.LeaseDeadlineTick := State.VerifiedAtTick + UInt64(High(Integer)) * 1000 + 1;
  Reject(CozyText_LicenseStateProbe_Lease_cannot_overflow_Integer_seconds_9f4b4ab0, State, 10000);
  State := ActiveState;
  State.VerifiedAtTick := 1;
  State.LeaseDeadlineTick := UInt64(High(Int64)) + 2000;
  Reject(CozyText_LicenseStateProbe_Elapsed_time_cannot_wrap_signed_Int64_86451a9c, State, UInt64(High(Int64)) + 1000);
  State := ActiveState;
  State.VerifiedAtTick := High(UInt64) - 120000;
  State.LeaseDeadlineTick := High(UInt64);
  Expect(CozyText_LicenseStateProbe_Valid_clock_near_UInt64_maximum_9cba250b, State, High(UInt64) - 1, True, 1, 3481);
  Reject(CozyText_LicenseStateProbe_Maximum_unsigned_clock_at_expiry_7d978e25, State, High(UInt64));
  State := ActiveState;
  State.ServerTime := High(Int64) - 120000;
  State.LeaseExpiresAt := High(Int64);
  State.ExpiresAt := High(Int64);
  Expect(CozyText_LicenseStateProbe_Valid_timestamps_near_Int64_maximum_537dbe82, State, 10000, True, 120, 120);
  Expect(CozyText_LicenseStateProbe_Final_millisecond_near_Int64_maximum_38b06ba8, State, 129999, True, 1, 1);
  State := ActiveState; State.ExpiresAt := High(Int64);
  Expect(CozyText_LicenseStateProbe_Finite_license_rounding_cannot_overflow_Int64_1cc2bbb6, State, 10000,
    True, 120, 9223372036853776);
end;

begin
  try
    Run;
    Writeln(CozyText_LicenseStateProbe_PASS_5d779032, Cases, CozyText_LicenseStateProbe_production_license_state_boundary_cases_d074791b);
    Writeln(CozyText_LicenseStateProbe_Platform_clock_injection_only_not_a_Windows_serv_04b7f1cc);
  except
    on E: Exception do
    begin
      Writeln(CozyText_LicenseStateProbe_FAIL_fc41398e, E.ClassName, CozyText_LicenseStateProbe_Text_1cd35884, E.Message);
      ExitCode := 1;
    end;
  end;
end.
