unit Cozy.Tls.PinWindow;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Network,
 System.SysUtils;
const TlsPinWindowContract = CozyText_Tls_PinWindow_GAME_TLS_PIN_WINDOW_V1_7e9afbc4;
type
  { Shared across transport clones; only authenticated Handoff serializes it.
    Public pin state stays in RAM. It is not a persistent rollback checkpoint. }
  ITlsPinWindow = interface
    ['{E44CB3DB-4387-4970-B89A-B0D9C20F1EDC}']
    procedure SelectPins(out Primary, Secondary: string);
    procedure CheckPresented(const Pin: string);
    { Guard runs under the shared window lock immediately before publication.
      It must only validate caller state; it must not reenter this window. }
    procedure LearnAuthenticated(const PlanJSON, PresentedPin: string;
      const BeforeCommit: TProc = nil);
    function ExportTrusted: string;
  end;
function NewTlsPinWindow(const Host: string; Port: Word;
  const KeyId, ServerName, RootPin, TrustedState: string): ITlsPinWindow;
implementation
uses System.JSON, System.Diagnostics, System.DateUtils, Cozy.ProtocolJson;
const MaxStateBytes = 6144; MaxHistory = 64; MaxOverlap = Int64(86400000);
      MaxLead = Int64(604800000); MaxTime = Int64(8640000000000000);
type
  TPinPlan = record
    Generation: Integer;
    CurrentPin, NextPin: string;
    IssuedAt, NotBefore, OldNotAfter: Int64;
  end;
  TTlsPinWindow = class(TInterfacedObject, ITlsPinWindow)
  private
    FLock: TObject;
    FClock: TStopwatch;
    FBaseWall, FLastWall: Int64;
    FHost, FKeyId, FServerName, FRootPin: string;
    FPort: Word;
    FPlan: TPinPlan;
    FPlanJSON, FRetired: string;
    function TimeNow: Int64;
    function ParsePlan(const Text: string): TPinPlan;
    procedure PinsLocked(out Primary, Secondary: string);
    procedure PresentedLocked(const Pin: string);
    procedure ImportTrusted(const Text: string);
  public
    constructor Create(const Host: string; Port: Word;
      const KeyId, ServerName, RootPin, TrustedState: string);
    destructor Destroy; override;
    procedure SelectPins(out Primary, Secondary: string);
    procedure CheckPresented(const Pin: string);
    { Guard runs under the shared window lock immediately before publication.
      It must only validate caller state; it must not reenter this window. }
    procedure LearnAuthenticated(const PlanJSON, PresentedPin: string;
      const BeforeCommit: TProc = nil);
    function ExportTrusted: string;
  end;
procedure Bad(const Code: string = CozyText_Tls_PinWindow_TLS_PIN_PLAN_INVALID_f1f2dcc1);
begin raise EInvalidOpException.Create(Code); end;
function PinValid(const Text: string): Boolean;
var C: Char;
begin
  Result := Length(Text) = 64;
  if not Result then Exit;
  for C in Text do if not CharInSet(C, ['0'..'9','a'..'f']) then Exit(False);
end;
function Str(Obj: TJSONObject; const Name: string): string;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name); if not (V is TJSONString) then Bad;
  Result := V.Value;
end;
function Num(Obj: TJSONObject; const Name: string): Int64;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name);
  if not (V is TJSONNumber) then Bad;
  if not TryStrToInt64(V.Value, Result) then Bad;
  if (Result < 0) or (Result > MaxTime) or (IntToStr(Result) <> V.Value) then Bad;
end;
function WallNow: Int64;
var D: TDateTime;
begin
  D := Now;
  Result := DateTimeToUnix(D, False) * 1000 + MilliSecondOf(D);
end;
constructor TTlsPinWindow.Create(const Host: string; Port: Word;
  const KeyId, ServerName, RootPin, TrustedState: string);
begin
  inherited Create;
  FLock := TObject.Create;
  FHost := Host; FPort := Port; FKeyId := KeyId;
  FServerName := ServerName; FRootPin := RootPin;
  if not PinValid(RootPin) then Bad;
  FClock := TStopwatch.StartNew; FBaseWall := WallNow; FLastWall := FBaseWall;
  if TrustedState <> '' then ImportTrusted(TrustedState);
end;
destructor TTlsPinWindow.Destroy;
begin FLock.Free; inherited; end;
function TTlsPinWindow.TimeNow: Int64;
var Wall, Elapsed: Int64;
begin
  Elapsed := FClock.ElapsedMilliseconds;
  if (Elapsed < 0) or (Elapsed > MaxTime - FBaseWall) then Bad;
  Result := FBaseWall + Elapsed;
  Wall := WallNow;
  if Wall > Result then Result := Wall;
  if FLastWall > Result then Result := FLastWall;
  FBaseWall := Result - Elapsed;
  FLastWall := Result;
  { Backward wall-clock adjustment cannot reopen a retired pin in this state. }
end;
function TTlsPinWindow.ParsePlan(const Text: string): TPinPlan;
var Obj: TJSONObject; G: Int64;
begin
  Obj := ParseProtocolObject(Text, 2048);
  try
    if (Obj.Count <> 11) or (Num(Obj,CozyText_Tls_PinWindow_version_6f902017) <> 1) then Bad;
    if (Str(Obj,CozyText_Tls_PinWindow_host_976ccbf3) <> FHost) or (Num(Obj,CozyText_Tls_PinWindow_port_c52491ee) <> FPort) or
       (Str(Obj,CozyText_Tls_PinWindow_serverKeyId_c8f1e9fb) <> FKeyId) or (Str(Obj,CozyText_Tls_PinWindow_tlsServerName_b7fd4d27) <> FServerName) then
      Bad(CozyText_Tls_PinWindow_TLS_PIN_ENDPOINT_CHANGED_a5177191);
    G := Num(Obj,CozyText_Tls_PinWindow_generation_f47154a7); if (G < 1) or (G > MaxHistory) then Bad;
    Result.Generation := Integer(G);
    Result.CurrentPin := Str(Obj,CozyText_Tls_PinWindow_currentPin_3b8bb112); Result.NextPin := Str(Obj,CozyText_Tls_PinWindow_nextPin_76888740);
    if not PinValid(Result.CurrentPin) or not PinValid(Result.NextPin) or
       (Result.CurrentPin = Result.NextPin) then Bad;
    Result.IssuedAt := Num(Obj,CozyText_Tls_PinWindow_issuedAt_b190554e); Result.NotBefore := Num(Obj,CozyText_Tls_PinWindow_notBefore_126137f9);
    Result.OldNotAfter := Num(Obj,CozyText_Tls_PinWindow_oldNotAfter_78ca6c19);
    if (Result.IssuedAt < 1) or (Result.NotBefore < Result.IssuedAt) or
       (Result.NotBefore - Result.IssuedAt > MaxLead) or
       (Result.OldNotAfter - Result.NotBefore < 60000) or
       (Result.OldNotAfter - Result.NotBefore > MaxOverlap) then Bad;
  finally Obj.Free; end;
end;
procedure TTlsPinWindow.PinsLocked(out Primary, Secondary: string);
var At: Int64;
begin
  Secondary := '';
  if FPlan.Generation = 0 then begin Primary := FRootPin; Exit; end;
  At := TimeNow;
  if At < FPlan.OldNotAfter then Primary := FPlan.CurrentPin
  else Primary := FPlan.NextPin;
  if (At >= FPlan.NotBefore) and (At < FPlan.OldNotAfter) then Secondary := FPlan.NextPin;
end;
procedure TTlsPinWindow.PresentedLocked(const Pin: string);
var A, B: string;
begin
  PinsLocked(A,B);
  if (Pin = '') or ((Pin <> A) and ((B = '') or (Pin <> B))) then
    Bad(CozyText_Tls_PinWindow_TLS_PIN_CERTIFICATE_OUTSIDE_WINDOW_9e323ea1);
end;
procedure TTlsPinWindow.SelectPins(out Primary, Secondary: string);
begin TMonitor.Enter(FLock); try PinsLocked(Primary,Secondary); finally TMonitor.Exit(FLock); end; end;
procedure TTlsPinWindow.CheckPresented(const Pin: string);
begin TMonitor.Enter(FLock); try PresentedLocked(Pin); finally TMonitor.Exit(FLock); end; end;
procedure TTlsPinWindow.LearnAuthenticated(const PlanJSON, PresentedPin: string;
  const BeforeCommit: TProc);
var
  P: TPinPlan;
  At, CommitAt, NextBase, NextLast, Elapsed: Int64;
  Retired: string;
  SamePlan: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    PresentedLocked(PresentedPin); { Recheck the handshake pin AFTER tag verification. }
    P := ParsePlan(PlanJSON); At := TimeNow;
    { Server time is prospective until the complete plan and caller deadline
      have passed. A rejected future plan must not retire an existing pin. }
    if P.IssuedAt > At then At := P.IssuedAt;
    if not (((PresentedPin = P.CurrentPin) and (At < P.OldNotAfter)) or
            ((PresentedPin = P.NextPin) and (At >= P.NotBefore))) then
      Bad(CozyText_Tls_PinWindow_TLS_PIN_CERTIFICATE_OUTSIDE_WINDOW_9e323ea1);
    Retired := FRetired; SamePlan := False;
    if FPlan.Generation = 0 then
    begin
      if (FRootPin <> P.CurrentPin) and (FRootPin <> P.NextPin) then Bad(CozyText_Tls_PinWindow_TLS_PIN_TRUST_CHAIN_INVALID_1dc8f8fe);
    end
    else if P.Generation = FPlan.Generation then
    begin
      if (P.CurrentPin <> FPlan.CurrentPin) or (P.NextPin <> FPlan.NextPin) or
         (P.IssuedAt <> FPlan.IssuedAt) or (P.NotBefore <> FPlan.NotBefore) or
         (P.OldNotAfter <> FPlan.OldNotAfter) then Bad(CozyText_Tls_PinWindow_TLS_PIN_GENERATION_CONFLICT_0b2f3854);
      SamePlan := True;
      { The same plan is idempotent, but its caller still must pass the guard. }
    end
    else
    begin
      if (P.Generation <> FPlan.Generation + 1) or (At < FPlan.OldNotAfter) or
         (P.CurrentPin <> FPlan.NextPin) then Bad(CozyText_Tls_PinWindow_TLS_PIN_ROLLBACK_FORBIDDEN_13a86568);
      if Length(Retired) div 65 >= MaxHistory then Bad(CozyText_Tls_PinWindow_TLS_PIN_HISTORY_CAPACITY_c5a89c70);
      Retired := Retired + FPlan.CurrentPin + '|';
    end;
    if (Pos('|' + P.NextPin + '|','|' + Retired) > 0) or
       (Pos('|' + P.CurrentPin + '|','|' + Retired) > 0) then Bad(CozyText_Tls_PinWindow_TLS_PIN_ROLLBACK_FORBIDDEN_13a86568);
    { Recheck the elapsed window after parsing/history validation. Local clock
      advancement is monotonic, while the response's floor remains staged. }
    PresentedLocked(PresentedPin);
    CommitAt := TimeNow;
    if P.IssuedAt > CommitAt then CommitAt := P.IssuedAt;
    if not (((PresentedPin = P.CurrentPin) and (CommitAt < P.OldNotAfter)) or
            ((PresentedPin = P.NextPin) and (CommitAt >= P.NotBefore))) then
      Bad(CozyText_Tls_PinWindow_TLS_PIN_CERTIFICATE_OUTSIDE_WINDOW_9e323ea1);
    Elapsed := FClock.ElapsedMilliseconds;
    NextBase := FBaseWall; NextLast := FLastWall;
    if CommitAt > NextLast then
    begin
      NextBase := CommitAt - Elapsed;
      NextLast := CommitAt;
    end;
    { The owner holds its cancellation/admission lock while this guard checks
      its absolute deadline. No fallible work follows this publication point;
      never roll back a concurrent clone's shared state. }
    if Assigned(BeforeCommit) then BeforeCommit();
    FBaseWall := NextBase; FLastWall := NextLast;
    if not SamePlan then
    begin FPlan := P; FPlanJSON := PlanJSON; FRetired := Retired; end;
  finally TMonitor.Exit(FLock); end;
end;
procedure TTlsPinWindow.ImportTrusted(const Text: string);
var Obj: TJSONObject; Floor: Int64; I: Integer; Token, Seen: string;
begin
  Obj := ParseProtocolObject(Text,MaxStateBytes);
  try
    if (Obj.Count <> 4) or (Str(Obj,CozyText_Tls_PinWindow_contract_f569c72b) <> TlsPinWindowContract) then Bad;
    FPlanJSON := Str(Obj,CozyText_Tls_PinWindow_plan_8fd236a9); FPlan := ParsePlan(FPlanJSON);
    Floor := Num(Obj,CozyText_Tls_PinWindow_floor_b84cf89c); if Floor < FPlan.IssuedAt then Bad;
    FRetired := Str(Obj,CozyText_Tls_PinWindow_retiredPins_2836045f);
    if (Length(FRetired) mod 65 <> 0) or (Length(FRetired) div 65 > MaxHistory) then Bad;
    Seen := '|'; I := 1;
    while I <= Length(FRetired) do
    begin
      Token := Copy(FRetired,I,64);
      if not PinValid(Token) or (FRetired[I+64] <> '|') or
         (Token = FPlan.CurrentPin) or (Token = FPlan.NextPin) or
         (Pos('|' + Token + '|',Seen) > 0) then Bad;
      Seen := Seen + Token + '|'; Inc(I,65);
    end;
    if (FRootPin <> FPlan.CurrentPin) and (FRootPin <> FPlan.NextPin) and
       (Pos('|' + FRootPin + '|','|' + FRetired) = 0) then
      Bad(CozyText_Tls_PinWindow_TLS_PIN_TRUST_CHAIN_INVALID_1dc8f8fe);
    if Length(FRetired) div 65 >= FPlan.Generation then Bad;
    if Floor > FLastWall then FLastWall := Floor;
    if Floor > FBaseWall then FBaseWall := Floor;
  finally Obj.Free; end;
end;
function TTlsPinWindow.ExportTrusted: string;
var Obj: TJSONObject;
begin
  Result := ''; TMonitor.Enter(FLock);
  try
    if FPlan.Generation = 0 then Exit;
    Obj := TJSONObject.Create;
    try
      Obj.AddPair(CozyText_Tls_PinWindow_contract_f569c72b,TlsPinWindowContract);
      Obj.AddPair(CozyText_Tls_PinWindow_plan_8fd236a9,FPlanJSON);
      Obj.AddPair(CozyText_Tls_PinWindow_floor_b84cf89c,TJSONNumber.Create(TimeNow));
      Obj.AddPair(CozyText_Tls_PinWindow_retiredPins_2836045f,FRetired);
      Result := Obj.ToJSON;
      if TEncoding.UTF8.GetByteCount(Result) > MaxStateBytes then Bad(CozyText_Tls_PinWindow_TLS_PIN_HISTORY_CAPACITY_c5a89c70);
    finally Obj.Free; end;
  finally TMonitor.Exit(FLock); end;
end;
function NewTlsPinWindow(const Host: string; Port: Word;
  const KeyId, ServerName, RootPin, TrustedState: string): ITlsPinWindow;
begin Result := TTlsPinWindow.Create(Host,Port,KeyId,ServerName,RootPin,TrustedState); end;
end.
