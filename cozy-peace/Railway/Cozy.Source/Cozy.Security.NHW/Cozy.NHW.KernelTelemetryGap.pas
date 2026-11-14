unit Cozy.NHW.KernelTelemetryGap;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Logging;

const
  KTG_NATIVE_MODULE = $01;
  KTG_PSAPI_MODULE  = $02;
  KTG_BOOT_TRUST    = $04;
  KTG_CODE_INTEGRITY = $08;
  KTG_CI_EVENT_LOG  = $10;

type
  TKernelTelemetryGapMonitor = class
  private
    FStableMask: Byte;
    FValidStreak: array[0..4] of Byte;
    FPendingMask: Byte;
    FConfirmations: Byte;
    FLastTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
    procedure UpdateStableMask(CurrentMask: Byte);
  public
    constructor Create;
    procedure Reset;
    procedure Examine(NativeModulesValid, PSAPIValid, BootValid, CIValid,
      CIEventLogValid: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
  end;

function KernelTelemetryGapCandidate(GapMask: Byte;
  Confirmations: Byte): Boolean;

implementation

const
  KTG_SAMPLE_MS = 10000;
  KTG_STABLE_CONFIRMATIONS = 3;
  KTG_GAP_CONFIRMATIONS = 3;
  KTG_REPORT_MS = 60000;

function BitCount8(V: Byte): Integer;
begin
  Result := 0;
  while V <> 0 do
  begin
    Inc(Result);
    V := V and (V - 1);
  end;
end;

function KernelTelemetryGapCandidate(GapMask: Byte;
  Confirmations: Byte): Boolean;
begin
  Result := (Confirmations >= KTG_GAP_CONFIRMATIONS) and
    ((((GapMask and KTG_NATIVE_MODULE) <> 0) and
      ((GapMask and KTG_CODE_INTEGRITY) <> 0)) or
     (BitCount8(GapMask) >= 4));
end;

constructor TKernelTelemetryGapMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TKernelTelemetryGapMonitor.ClearCandidate;
begin
  FPendingMask := 0;
  FConfirmations := 0;
end;

procedure TKernelTelemetryGapMonitor.Reset;
begin
  FStableMask := 0;
  FillChar(FValidStreak, SizeOf(FValidStreak), 0);
  FLastTick := 0;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TKernelTelemetryGapMonitor.UpdateStableMask(CurrentMask: Byte);
var I: Integer; Bit: Byte;
begin
  for I := 0 to 4 do
  begin
    Bit := Byte(1 shl I);
    if (CurrentMask and Bit) <> 0 then
    begin
      if FValidStreak[I] < KTG_STABLE_CONFIRMATIONS then Inc(FValidStreak[I]);
      if FValidStreak[I] >= KTG_STABLE_CONFIRMATIONS then
        FStableMask := FStableMask or Bit;
    end
    else if (FStableMask and Bit) = 0 then
      FValidStreak[I] := 0;
  end;
end;

procedure TKernelTelemetryGapMonitor.Examine(NativeModulesValid, PSAPIValid,
  BootValid, CIValid, CIEventLogValid: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var CurrentMask, GapMask: Byte; CanReport: Boolean;
begin
  if FLastTick <> 0 then
  begin
    if Tick < FLastTick then
    begin
      Reset;
      FLastTick := Tick;
      Exit;
    end;
    if Tick - FLastTick < KTG_SAMPLE_MS then Exit;
  end;
  FLastTick := Tick;
  CurrentMask := 0;
  if NativeModulesValid then CurrentMask := CurrentMask or KTG_NATIVE_MODULE;
  if PSAPIValid then CurrentMask := CurrentMask or KTG_PSAPI_MODULE;
  if BootValid then CurrentMask := CurrentMask or KTG_BOOT_TRUST;
  if CIValid then CurrentMask := CurrentMask or KTG_CODE_INTEGRITY;
  if CIEventLogValid then CurrentMask := CurrentMask or KTG_CI_EVENT_LOG;
  UpdateStableMask(CurrentMask);
  GapMask := FStableMask and not CurrentMask;
  if GapMask = 0 then
  begin
    ClearCandidate;
    Exit;
  end;
  if FPendingMask <> GapMask then
  begin
    FPendingMask := GapMask;
    FConfirmations := 1;
    Exit;
  end;
  if FConfirmations < KTG_GAP_CONFIRMATIONS then Inc(FConfirmations);
  if not KernelTelemetryGapCandidate(GapMask, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= KTG_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkKernelTelemetryGap);
    FLastReport := Tick;
  end;
end;

end.
