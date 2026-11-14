unit Cozy.NHW.DriverCrossView;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TDriverCrossViewMonitor = class
  private
    FPrimed: Boolean;
    FBaseline: TKernelBaseList;
    FPending: TKernelBaseList;
    FConfirmations: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const NativeModules: TKernelModuleInfos;
      NativeValid: Boolean; const PSAPIBases: TKernelBaseList;
      PSAPIValid: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
  end;

function DriverCrossViewCandidate(MismatchCount: Integer;
  Confirmations: Byte): Boolean;

implementation

const
  CROSSVIEW_CONFIRMATIONS = 3;
  CROSSVIEW_REPORT_MS = 60000;

function SameBases(const A, B: TKernelBaseList): Boolean;
var I: Integer;
begin
  Result := Length(A) = Length(B);
  if not Result then Exit;
  for I := 0 to High(A) do if A[I] <> B[I] then Exit(False);
end;

function BuildMismatch(const NativeModules: TKernelModuleInfos;
  const PSAPI: TKernelBaseList): TKernelBaseList;
var I, J, N: Integer;
begin
  SetLength(Result, Length(NativeModules) + Length(PSAPI));
  I := 0; J := 0; N := 0;
  while (I < Length(NativeModules)) or (J < Length(PSAPI)) do
  begin
    if I >= Length(NativeModules) then
    begin Result[N] := PSAPI[J]; Inc(J); end
    else if J >= Length(PSAPI) then
    begin Result[N] := NativeModules[I].Base; Inc(I); end
    else if NativeModules[I].Base = PSAPI[J] then
    begin Inc(I); Inc(J); Continue; end
    else if NativeModules[I].Base < PSAPI[J] then
    begin Result[N] := NativeModules[I].Base; Inc(I); end
    else
    begin Result[N] := PSAPI[J]; Inc(J); end;
    Inc(N);
  end;
  SetLength(Result, N);
end;

function DriverCrossViewCandidate(MismatchCount: Integer;
  Confirmations: Byte): Boolean;
begin
  Result := (MismatchCount > 0) and (Confirmations >= CROSSVIEW_CONFIRMATIONS);
end;

constructor TDriverCrossViewMonitor.Create;
begin inherited Create; Reset; end;

procedure TDriverCrossViewMonitor.ClearCandidate;
begin
  FPending := nil;
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TDriverCrossViewMonitor.Reset;
begin
  FPrimed := False;
  FLastReport := 0;
  FBaseline := nil;
  ClearCandidate;
end;

procedure TDriverCrossViewMonitor.Examine(const NativeModules: TKernelModuleInfos;
  NativeValid: Boolean; const PSAPIBases: TKernelBaseList;
  PSAPIValid: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var Mismatch: TKernelBaseList; CanReport: Boolean;
begin
  if not NativeValid or not PSAPIValid then
  begin
    ClearCandidate;
    Exit;
  end;
  Mismatch := BuildMismatch(NativeModules, PSAPIBases);
  if not FPrimed then
  begin
    // Stable cross-view differences present before the program starts are
    // baseline platform behavior, not an attack attribution.
    FPrimed := True;
    FBaseline := Copy(Mismatch, 0, Length(Mismatch));
    ClearCandidate;
    Exit;
  end;
  if Length(Mismatch) = 0 then
  begin
    ClearCandidate;
    Exit;
  end;
  if SameBases(FBaseline, Mismatch) then
  begin
    ClearCandidate;
    Exit;
  end;
  if not SameBases(FPending, Mismatch) then
  begin
    FPending := Copy(Mismatch, 0, Length(Mismatch));
    FConfirmations := 1;
    FLastConfirmTick := Tick;
    Exit;
  end;
  if Tick > FLastConfirmTick then
  begin
    if FConfirmations < CROSSVIEW_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not DriverCrossViewCandidate(Length(Mismatch), FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= CROSSVIEW_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkDriverCrossView);
    FLastReport := Tick;
  end;
end;

end.
