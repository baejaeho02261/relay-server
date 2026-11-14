program Cozy_OverlayDownloadDeadlineProbe;
{$APPTYPE CONSOLE}
{$RANGECHECKS ON}
{$OVERFLOWCHECKS ON}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_HANDOFF_CONTRACT_TESTS))}
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$ENDIF}
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$ENDIF}
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  System.SysUtils,
  Cozy.Overlay.Client;
var Checks: Integer;
procedure Check(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(CozyText_OverlayDownloadDeadlineProbe_FAIL_fa0e2f90 + Name);
  Inc(Checks);
end;
procedure RejectDeadline(StartedTick, NowTick: UInt64; ExpiresAt, NowUTC: Int64;
  Expected: TOverlayDownloadFailureKind);
var Rejected: Boolean;
begin
  Rejected := False;
  try
    EOverlayDownloadFailure.RequestDeadline(StartedTick, NowTick, ExpiresAt, NowUTC);
  except
    on E: EOverlayDownloadFailure do
    begin
      Rejected := E.Kind = Expected;
      if E.Kind = odfTimeout then
        Check(E.Message = CozyText_OverlayDownloadDeadlineProbe_OVERLAY_DOWNLOAD_TIMEOUT_77863866,
          CozyText_OverlayDownloadDeadlineProbe_timeout_exposes_only_its_fixed_diagnostic_code_d8be3df4)
      else
        Check(E.Message = CozyText_OverlayDownloadDeadlineProbe_OVERLAY_DOWNLOAD_TICKET_EXPIRED_65af6405,
          CozyText_OverlayDownloadDeadlineProbe_ticket_expiry_exposes_only_its_fixed_diagnostic__30836032);
    end;
  end;
  Check(Rejected, CozyText_OverlayDownloadDeadlineProbe_deadline_rejected_with_the_expected_closed_failu_787d1b3a);
end;
begin
  try
    Checks := 0;
    Check(EOverlayDownloadFailure.RequestDeadline(1000, 1000, 1410000, 1000000) = 301000,
      CozyText_OverlayDownloadDeadlineProbe_initial_request_keeps_the_original_300_second_do_d6f01969);
    Check(EOverlayDownloadFailure.RequestDeadline(1000, 300999, 1410000, 1299999) = 301000,
      CozyText_OverlayDownloadDeadlineProbe_last_millisecond_does_not_grant_a_fresh_request__e6150c82);
    Check(EOverlayDownloadFailure.RequestDeadline(1000, 41000, 1040007, 1040000) = 41007,
      CozyText_OverlayDownloadDeadlineProbe_earlier_signed_ticket_expiry_caps_the_in_flight__f2941f48);
    Check(EOverlayDownloadFailure.RequestDeadline(1000, 101000, 999999999, 1000000) = 301000,
      CozyText_OverlayDownloadDeadlineProbe_a_changed_or_later_ticket_cannot_extend_the_loca_1f826f73);
    RejectDeadline(1000, 301000, 1410000, 1300000, odfTimeout);
    RejectDeadline(1000, 999, 1410000, 1000000, odfTimeout);
    RejectDeadline(1000, 2000, 1000000, 1000000, odfTicketExpired);
    RejectDeadline(1000, 2000, 999999, 1000000, odfTicketExpired);
    RejectDeadline(1000, 2000, High(Int64), -1, odfTicketExpired);
    RejectDeadline(High(UInt64)-100, High(UInt64)-99, High(Int64), 1, odfTimeout);
    Writeln(CozyText_OverlayDownloadDeadlineProbe_OVERLAY_DOWNLOAD_DEADLINE_PASS_07f38fdf, Checks);
    Writeln(CozyText_OverlayDownloadDeadlineProbe_Deadline_arithmetic_only_no_network_authorizatio_93baacd2);
  except
    on E: Exception do
    begin
      Writeln(E.ClassName + CozyText_OverlayDownloadDeadlineProbe_Text_7c986bf4 + E.Message);
      ExitCode := 1;
    end;
  end;
end.
