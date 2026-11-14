unit Cozy.NHW.DriverIdentity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TDriverIdentityMonitor = class
  private
    FPrimed: Boolean;
    FBaseline: TArray<string>;
    FPending: TArray<string>;
    FConfirmations: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const NativeModules, PSAPIModules: TKernelModuleInfos;
      NativeValid, PSAPIValid: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function DriverIdentityCandidate(MismatchCount: Integer;
  Confirmations: Byte): Boolean;

implementation

uses System.SysUtils;

const
  IDENTITY_CONFIRMATIONS = 3;
  IDENTITY_REPORT_MS = 60000;

function ResolvableDriverPath(const Path: string): Boolean;
begin
  Result := (Length(Path) >= 3) and (Path[2] = ':') and
    ((Path[3] = '\') or (Path[3] = '/'));
end;

procedure SortStrings(var Values: TArray<string>);
var I, J: Integer; V: string;
begin
  for I := 1 to High(Values) do
  begin
    V := Values[I];
    J := I;
    while (J > 0) and (CompareText(Values[J-1], V) > 0) do
    begin
      Values[J] := Values[J-1];
      Dec(J);
    end;
    Values[J] := V;
  end;
end;

function SameStrings(const A, B: TArray<string>): Boolean;
var I: Integer;
begin
  Result := Length(A) = Length(B);
  if not Result then Exit;
  for I := 0 to High(A) do
    if not SameText(A[I], B[I]) then Exit(False);
end;

function BuildIdentityMismatch(const NativeModules,
  PSAPIModules: TKernelModuleInfos): TArray<string>;
var I, J, N: Integer; A, B: string;
begin
  SetLength(Result, Length(NativeModules));
  I := 0; J := 0; N := 0;
  while (I < Length(NativeModules)) and (J < Length(PSAPIModules)) do
  begin
    if NativeModules[I].Base < PSAPIModules[J].Base then
    begin Inc(I); Continue; end;
    if NativeModules[I].Base > PSAPIModules[J].Base then
    begin Inc(J); Continue; end;
    A := NativeModules[I].Path;
    B := PSAPIModules[J].Path;
    // Device namespace paths are not canonicalized to drive letters here.
    // Skip them instead of treating equivalent namespace spellings as tamper.
    if ResolvableDriverPath(A) and ResolvableDriverPath(B) and
       (not SameText(A, B)) then
    begin
      Result[N] := IntToHex(UInt64(NativeModules[I].Base), 16) + '|' +
        LowerCase(A) + '|' + LowerCase(B);
      Inc(N);
    end;
    Inc(I); Inc(J);
  end;
  SetLength(Result, N);
  SortStrings(Result);
end;

function DriverIdentityCandidate(MismatchCount: Integer;
  Confirmations: Byte): Boolean;
begin
  Result := (MismatchCount > 0) and
    (Confirmations >= IDENTITY_CONFIRMATIONS);
end;

constructor TDriverIdentityMonitor.Create;
begin inherited Create; Reset; end;

procedure TDriverIdentityMonitor.ClearCandidate;
begin
  FPending := nil;
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TDriverIdentityMonitor.Reset;
begin
  FPrimed := False;
  FBaseline := nil;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TDriverIdentityMonitor.Examine(const NativeModules,
  PSAPIModules: TKernelModuleInfos; NativeValid, PSAPIValid: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var Mismatch: TArray<string>; CanReport: Boolean;
begin
  if not NativeValid or not PSAPIValid then
  begin
    ClearCandidate;
    Exit;
  end;
  Mismatch := BuildIdentityMismatch(NativeModules, PSAPIModules);
  if not FPrimed then
  begin
    // Stable path spelling differences that exist before monitoring begins are
    // baseline platform behavior, not an attack attribution.
    FPrimed := True;
    FBaseline := Copy(Mismatch, 0, Length(Mismatch));
    ClearCandidate;
    Exit;
  end;
  if (Length(Mismatch) = 0) or SameStrings(FBaseline, Mismatch) then
  begin
    ClearCandidate;
    Exit;
  end;
  if not SameStrings(FPending, Mismatch) then
  begin
    FPending := Copy(Mismatch, 0, Length(Mismatch));
    FConfirmations := 1;
    FLastConfirmTick := Tick;
    Exit;
  end;
  if Tick > FLastConfirmTick then
  begin
    if FConfirmations < IDENTITY_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not DriverIdentityCandidate(Length(Mismatch), FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= IDENTITY_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkDriverIdentity);
    FLastReport := Tick;
  end;
end;

end.
