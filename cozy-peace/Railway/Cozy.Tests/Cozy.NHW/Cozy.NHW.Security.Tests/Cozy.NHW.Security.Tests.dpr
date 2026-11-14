program CozyNHW_Security_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Requires Windows 64-bit Delphi.'}
{$ENDIF}

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Security.Snapshot in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Security.Snapshot.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Process in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Process.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas',
  Cozy.NHW.Security in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Security.pas';

procedure Require(Condition: Boolean; const Description: string);
begin
  if not Condition then
    raise Exception.Create(Description);
end;

var
  Monitor: TSecurityMonitor;
  Observed: TList<TObservedTokenHandle>;
  OwnerTimes: TCreationTimeMap;
  Item: TObservedTokenHandle;
  Events: TDetectionKinds;
  TestPID: Cardinal;
  SelfToken: THandle;
  BeforeToken, AfterToken: TTokenSecuritySnapshot;
begin
  ResolveWinPointers;
  ResolveNativeAPIs;
  SelfToken := 0;
  BeforeToken := Default(TTokenSecuritySnapshot);
  AfterToken := Default(TTokenSecuritySnapshot);
  Monitor := TSecurityMonitor.Create;
  Observed := TList<TObservedTokenHandle>.Create;
  OwnerTimes := TCreationTimeMap.Create;
  try
    TestPID := 414141;
    OwnerTimes.Add(TestPID, 7654321);
    Item := Default(TObservedTokenHandle);
    Item.OwnerPID := TestPID;
    Item.TokenObject := $123456;
    Item.GrantedAccess := TOKEN_QUERY_RIGHT;
    Observed.Add(Item);

    Events := [];
    Monitor.ExamineTokenHandles(Observed, True, 9999,
      OwnerTimes, True, Events);
    Require(Events = [], 'Baseline must not raise token event');

    Events := [];
    Monitor.ExamineTokenHandles(Observed, True, 9999,
      OwnerTimes, False, Events);
    Require(Events = [], 'Steady handle must not raise event');

    Item.GrantedAccess := TOKEN_QUERY_RIGHT or TOKEN_DUPLICATE_RIGHT;
    Observed[0] := Item;
    Events := [];
    Monitor.ExamineTokenHandles(Observed, True, 9999,
      OwnerTimes, False, Events);
    Require((dkTokenRights in Events) and not (dkTokenObject in Events),
      'New token-modification right should be isolated');

    Observed.Clear;
    Events := [];
    Monitor.ExamineTokenHandles(Observed, False, 9999,
      OwnerTimes, False, Events);
    Require(Events = [], 'Unavailable snapshot must not mark missing');
    Monitor.ExamineTokenHandles(Observed, True, 9999,
      OwnerTimes, False, Events);
    Monitor.ExamineTokenHandles(Observed, True, 9999,
      OwnerTimes, False, Events);

    Item.GrantedAccess := TOKEN_QUERY_RIGHT;
    Observed.Add(Item);
    Events := [];
    Monitor.ExamineTokenHandles(Observed, True, 9999,
      OwnerTimes, False, Events);
    Require(Events = [],
      'Query-only handle return is not a token mutation');

    Item.TokenObject := $987654;
    Item.GrantedAccess := TOKEN_DUPLICATE_RIGHT; Observed[0] := Item; Events := [];
    Monitor.ExamineTokenHandles(Observed, True, 9999, OwnerTimes, True, Events);
    Require((dkTokenObject in Events) and (dkTokenRights in Events),
      'Bootstrap must retain external token modification evidence');

    { Read-only live Windows smoke: this never enables a privilege, replaces
      a token, or spends a license. Failure is not reported as an attack. }
    SelfToken := OpenNativeProcessToken(THandle(NativeInt(-1)), TOKEN_QUERY_RIGHT);
    Require(SelfToken <> 0, 'Current token query unavailable');
    Require(TryTokenSecuritySnapshot(SelfToken, BeforeToken), 'Current token baseline unavailable');
    Require((BeforeToken.ValidFields and
      (TOKEN_FIELD_STATISTICS or TOKEN_FIELD_PRIVILEGES or TOKEN_FIELD_INTEGRITY or TOKEN_FIELD_ELEVATION)) =
      (TOKEN_FIELD_STATISTICS or TOKEN_FIELD_PRIVILEGES or TOKEN_FIELD_INTEGRITY or TOKEN_FIELD_ELEVATION),
      'Required token baseline fields unavailable');
    Require(TryTokenSecuritySnapshot(SelfToken, AfterToken), 'Current token recheck unavailable');
    Require(TokenSecurityDelta(BeforeToken, AfterToken) = 0,
      'Unmodified token must not be detected as escalation');
    Writeln('Security tests PASS (synthetic rights and read-only current token)');
  finally
    CloseNativeProcess(SelfToken);
    FillChar(BeforeToken, SizeOf(BeforeToken), 0);
    FillChar(AfterToken, SizeOf(AfterToken), 0);
    OwnerTimes.Free;
    Observed.Free;
    Monitor.Free;
  end;
end.
