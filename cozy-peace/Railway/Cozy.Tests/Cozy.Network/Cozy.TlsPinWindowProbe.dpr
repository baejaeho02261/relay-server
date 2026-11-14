program Cozy_TlsPinWindowProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
 System.SysUtils, System.JSON, System.DateUtils, System.Diagnostics, System.Classes,
  Cozy.Tls.PinWindow in '..\..\Cozy.Source\Cozy.Network\Cozy.Tls.PinWindow.pas',
  Cozy.ShutdownBudget in '..\..\Cozy.Source\Cozy.Lifecycle\Cozy.ShutdownBudget.pas';
var Checks: Integer;
procedure Check(Value: Boolean; const Code: string);
begin if not Value then raise Exception.Create(Code); Inc(Checks); end;
procedure Rejected(const Action: TProc; const Prefix: string = CozyText_TlsPinWindowProbe_TLS_PIN_85a6fa3f);
var Failed: Boolean;
begin
  Failed := False;
  try Action(); except on E: EInvalidOpException do
    begin if Pos(Prefix,E.Message) <> 1 then raise; Failed := True; end; end;
  Check(Failed,CozyText_TlsPinWindowProbe_EXPECTED_REJECTION_cbb8662c);
end;
function Plan(Generation: Integer; const OldPin, NewPin: string;
  Issued, StartAt, EndAt: Int64): string;
var O: TJSONObject;
begin
  O := TJSONObject.Create;
  try
    O.AddPair(CozyText_TlsPinWindowProbe_version_c2d0bab1,TJSONNumber.Create(1)); O.AddPair(CozyText_TlsPinWindowProbe_generation_dcd87e65,TJSONNumber.Create(Generation));
    O.AddPair(CozyText_TlsPinWindowProbe_host_d270c27a,CozyText_TlsPinWindowProbe_127_0_0_1_de1c3de7); O.AddPair(CozyText_TlsPinWindowProbe_port_a72973fa,TJSONNumber.Create(29131));
    O.AddPair(CozyText_TlsPinWindowProbe_serverKeyId_68b10d74,StringOfChar('a',64)); O.AddPair(CozyText_TlsPinWindowProbe_tlsServerName_3c673a0b,CozyText_TlsPinWindowProbe_pin_fixture_invalid_d5b74d42);
    O.AddPair(CozyText_TlsPinWindowProbe_currentPin_f5648371,OldPin); O.AddPair(CozyText_TlsPinWindowProbe_nextPin_21ee9bac,NewPin);
    O.AddPair(CozyText_TlsPinWindowProbe_issuedAt_389a23f9,TJSONNumber.Create(Issued)); O.AddPair(CozyText_TlsPinWindowProbe_notBefore_5ff1eb7a,TJSONNumber.Create(StartAt));
    O.AddPair(CozyText_TlsPinWindowProbe_oldNotAfter_0f5b56a4,TJSONNumber.Create(EndAt)); Result := O.ToJSON;
  finally O.Free; end;
end;
function State(const P: string; Floor: Int64; const Retired: string = ''): string;
var O: TJSONObject;
begin
  O := TJSONObject.Create;
  try O.AddPair(CozyText_TlsPinWindowProbe_contract_d10f91e5,TlsPinWindowContract); O.AddPair(CozyText_TlsPinWindowProbe_plan_3902df9d,P);
    O.AddPair(CozyText_TlsPinWindowProbe_floor_6c80812c,TJSONNumber.Create(Floor)); O.AddPair(CozyText_TlsPinWindowProbe_retiredPins_4c688279,Retired); Result := O.ToJSON;
  finally O.Free; end;
end;
function Window(const Root, Trusted: string): ITlsPinWindow;
begin Result := NewTlsPinWindow(CozyText_TlsPinWindowProbe_127_0_0_1_de1c3de7,29131,StringOfChar('a',64),CozyText_TlsPinWindowProbe_pin_fixture_invalid_d5b74d42,Root,Trusted); end;
function TrustedFloor(const Text: string): Int64;
var O: TJSONObject;
begin
  O := TJSONObject.ParseJSONValue(Text) as TJSONObject;
  try
    if (O = nil) or not TryStrToInt64(O.GetValue(CozyText_TlsPinWindowProbe_floor_6c80812c).Value,Result) then
      raise Exception.Create(CozyText_TlsPinWindowProbe_TRUSTED_FLOOR_REQUIRED_97f726f7);
  finally O.Free; end;
end;
procedure GuardedPlanTests;
var
  W, Shared: ITlsPinWindow;
  A,B,C,Text,Future,First,Second: string;
  NowMs: Int64;
  D: TDateTime;
  GuardCalls: Integer;
  Clock: TStopwatch;
begin
  D:=Now; NowMs:=DateTimeToUnix(D,False)*1000+MilliSecondOf(D);
  A:=StringOfChar('b',64); B:=StringOfChar('c',64); C:=StringOfChar('d',64);
  Text:=Plan(1,A,B,NowMs,NowMs+60000,NowMs+120000);
  Future:=Plan(1,A,C,NowMs+300000,NowMs+360000,NowMs+420000);
  W:=Window(A,''); Shared:=W; W.LearnAuthenticated(Text,A);
  GuardCalls:=0;
  Rejected(procedure begin
    W.LearnAuthenticated(Future,A,procedure begin Inc(GuardCalls); end);
  end);
  Check(GuardCalls=0,CozyText_TlsPinWindowProbe_CONFLICT_REJECTED_BEFORE_GUARD_08d07ddf);
  Shared.SelectPins(First,Second);
  Check((First=A) and (Second=''),CozyText_TlsPinWindowProbe_INVALID_FUTURE_PLAN_CANNOT_RETIRE_SHARED_PIN_875de000);
  Check(TrustedFloor(Shared.ExportTrusted)<NowMs+60000,CozyText_TlsPinWindowProbe_INVALID_FUTURE_PLAN_CANNOT_ADVANCE_SERVER_FLOOR_4c95ac4f);
  W:=Window(A,''); Shared:=W;
  Rejected(procedure begin
    W.LearnAuthenticated(Future,A,procedure begin
      Inc(GuardCalls); raise EInvalidOpException.Create(CozyText_TlsPinWindowProbe_TLS_PIN_GUARD_CANCELLED_67b28350);
    end);
  end);
  Check((GuardCalls=1) and (Shared.ExportTrusted=''),CozyText_TlsPinWindowProbe_CANCEL_GUARD_PRESERVES_EMPTY_SHARED_STATE_f33d0e03);
  W.LearnAuthenticated(Text,A);
  Shared.SelectPins(First,Second);
  Check((First=A) and (Second=''),CozyText_TlsPinWindowProbe_CANCELLED_FUTURE_PLAN_CANNOT_POISON_LATER_VALID__d457ca0d);
  W:=Window(A,''); Shared:=W; Clock:=TStopwatch.StartNew;
  while Clock.ElapsedMilliseconds<1 do TThread.Sleep(1);
  Rejected(procedure begin
    W.LearnAuthenticated(Future,A,procedure begin
      if Clock.ElapsedMilliseconds>=1 then
        raise EInvalidOpException.Create(CozyText_TlsPinWindowProbe_TLS_PIN_GUARD_DEADLINE_5969b380);
    end);
  end);
  Check(Shared.ExportTrusted='',CozyText_TlsPinWindowProbe_ELAPSED_DEADLINE_CANNOT_PUBLISH_PLAN_244a341b);
  W.LearnAuthenticated(Future,A,procedure begin Inc(GuardCalls); end);
  Check(GuardCalls=2,CozyText_TlsPinWindowProbe_ACCEPTED_PLAN_GUARD_EXECUTED_ffa7891c);
  Check(TrustedFloor(Shared.ExportTrusted)>=NowMs+300000,CozyText_TlsPinWindowProbe_ACCEPTED_SERVER_FLOOR_COMMITTED_61a317ed);
  W.LearnAuthenticated(Future,A,procedure begin Inc(GuardCalls); end);
  Check(GuardCalls=3,CozyText_TlsPinWindowProbe_IDEMPOTENT_PLAN_STILL_CHECKS_CALLER_GUARD_250a6978);
  Shared:=nil; W:=nil;
end;
procedure Execute;
var NowMs: Int64; D: TDateTime; A,B,C,X,Text,Saved,First,Second: string;
  W,CopyW: ITlsPinWindow; Budget: TShutdownBudget;
begin
  GuardedPlanTests;
  D := Now; NowMs := DateTimeToUnix(D,False)*1000+MilliSecondOf(D);
  A := StringOfChar('b',64); B := StringOfChar('c',64); C := StringOfChar('d',64); X := StringOfChar('e',64);
  Text := Plan(1,A,B,NowMs,NowMs+60000,NowMs+120000);
  W := Window(A,''); W.SelectPins(First,Second); Check((First=A) and (Second=''),CozyText_TlsPinWindowProbe_ROOT_ONLY_95a35e1d);
  Rejected(procedure begin W.CheckPresented(X); end);
  W.LearnAuthenticated(Text,A); W.SelectPins(First,Second); Check((First=A) and (Second=''),CozyText_TlsPinWindowProbe_BEFORE_WINDOW_17ff5e72);
  Rejected(procedure begin W.CheckPresented(B); end);
  Rejected(procedure begin W.LearnAuthenticated(Plan(1,A,B,NowMs,NowMs+60000,NowMs+180000),A); end);
  Rejected(procedure begin W.LearnAuthenticated(Plan(2,A,C,NowMs,NowMs+60000,NowMs+180000),A); end);
  Saved := W.ExportTrusted; CopyW := Window(A,Saved); CopyW.SelectPins(First,Second); Check((First=A) and (Second=''),CozyText_TlsPinWindowProbe_HANDOFF_COPY_6d5a5a76);
  W := Window(A,State(Text,NowMs+60000)); W.SelectPins(First,Second); Check((First=A) and (Second=B),CozyText_TlsPinWindowProbe_OVERLAP_917d7c0b);
  W.CheckPresented(A); Inc(Checks); W.CheckPresented(B); Inc(Checks);
  W := Window(A,State(Text,NowMs+120000)); W.SelectPins(First,Second); Check((First=B) and (Second=''),CozyText_TlsPinWindowProbe_OLD_RETIRED_fcb0b973);
  Rejected(procedure begin W.CheckPresented(A); end); W.CheckPresented(B); Inc(Checks);
  W.LearnAuthenticated(Text,B); W.SelectPins(First,Second); Check((First=B) and (Second=''),CozyText_TlsPinWindowProbe_SAME_PLAN_CANNOT_REOPEN_c4238de6);
  W.LearnAuthenticated(Plan(2,B,C,NowMs+120000,NowMs+180000,NowMs+240000),B);
  W.SelectPins(First,Second); Check((First=B) and (Second=''),CozyText_TlsPinWindowProbe_NEXT_GENERATION_670d8cf5);
  Saved := W.ExportTrusted; Check(Pos(A,Saved)>0,CozyText_TlsPinWindowProbe_RETIRED_HISTORY_PRESERVED_2eb42a63);
  CopyW := Window(A,Saved); CopyW.SelectPins(First,Second); Check((First=B) and (Second=''),CozyText_TlsPinWindowProbe_OLD_ROOT_VALID_HANDOFF_e55b1595);
  Rejected(procedure begin W.LearnAuthenticated(Text,B); end);
  W := Window(A,State(Plan(2,B,C,NowMs+120000,NowMs+180000,NowMs+240000),NowMs+240000,A+'|'));
  Rejected(procedure begin W.LearnAuthenticated(Plan(3,C,A,NowMs+240000,NowMs+300000,NowMs+360000),C); end);
  Rejected(procedure begin CopyW:=Window(X,Saved); end);
  Rejected(procedure begin CopyW:=Window(A,State(Text,NowMs,A+'|')); end);
  Rejected(procedure begin CopyW:=Window(A,State(Text,NowMs-1)); end);
  Rejected(procedure begin CopyW:=Window(A,State(Plan(0,A,B,NowMs,NowMs+60000,NowMs+120000),NowMs)); end);
  Rejected(procedure begin CopyW:=Window(A,State(Plan(1,A,A,NowMs,NowMs+60000,NowMs+120000),NowMs)); end);
  Rejected(procedure begin CopyW:=Window(A,State(Plan(1,A,B,NowMs,NowMs-1,NowMs+120000),NowMs)); end);
  Rejected(procedure begin CopyW:=Window(A,State(Plan(1,A,B,NowMs,NowMs+60000,NowMs+60001),NowMs)); end);
  Budget.BeginAt(10000); Check(Budget.Deadline=15000,CozyText_TlsPinWindowProbe_TOTAL_DEADLINE_8a85b758); Check(Budget.JoinDeadline=14000,CozyText_TlsPinWindowProbe_CLOSE_RESERVE_ffa9e97a);
  Check(Budget.Remaining(10000)=5000,CozyText_TlsPinWindowProbe_START_REMAINING_aac150b4); Check(Budget.Remaining(15000)=0,CozyText_TlsPinWindowProbe_EXACT_DEADLINE_ce89ccc0); Check(Budget.Remaining(9999)=0,CozyText_TlsPinWindowProbe_BACKWARD_TICK_eeac5786);
  Budget.JoinedAt(13999); Check(not Budget.JoinMissed,CozyText_TlsPinWindowProbe_JOIN_WITHIN_1dfb32c7); Budget.ClosedAt(14999); Check(not Budget.CloseMissed,CozyText_TlsPinWindowProbe_CLOSE_WITHIN_935a7c28); Check(Budget.CloseElapsed=1000,CozyText_TlsPinWindowProbe_CLOSE_ELAPSED_b7c18542);
  Budget.BeginAt(10000); Budget.JoinedAt(14000); Check(Budget.JoinMissed,CozyText_TlsPinWindowProbe_EXACT_JOIN_DEADLINE_09b11ac4); Check(Budget.Remaining(14000)=1000,CozyText_TlsPinWindowProbe_RESERVED_CLOSE_REMAINS_1fc3f0f8);
  Budget.ClosedAt(15000); Check(Budget.CloseMissed,CozyText_TlsPinWindowProbe_EXACT_CLOSE_DEADLINE_6271d639);
  Budget.BeginAt(10000); Budget.JoinedAt(16000); Check(Budget.JoinMissed and (Budget.Remaining(16000)=0),CozyText_TlsPinWindowProbe_SAFE_DRAIN_OVERRUN_8eed7484);
  Rejected(procedure begin Budget.BeginAt(High(UInt64)); end,CozyText_TlsPinWindowProbe_SHUTDOWN_78145d4a);
  Rejected(procedure begin Budget.BeginAt(1,0); end,CozyText_TlsPinWindowProbe_SHUTDOWN_78145d4a);
  Rejected(procedure begin Budget.BeginAt(1,5000,5001); end,CozyText_TlsPinWindowProbe_SHUTDOWN_78145d4a);
  W := nil; CopyW := nil;
end;
begin
  try Execute; WriteLn(CozyText_TlsPinWindowProbe_JsonFixture_d906d563,Checks,CozyText_TlsPinWindowProbe_status_PASS_tlsHandshakeExecuted_false_gpuExecut_f9499dc9);
  except on E: Exception do begin WriteLn(E.ClassName,CozyText_TlsPinWindowProbe_Text_fac21826,E.Message); ExitCode:=1; end; end;
end.
