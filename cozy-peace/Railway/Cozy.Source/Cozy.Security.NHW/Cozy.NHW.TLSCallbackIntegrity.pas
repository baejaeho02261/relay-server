unit Cozy.NHW.TLSCallbackIntegrity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TTLSCaptureStatus = (tcsUnavailable, tcsComplete, tcsReadFailed,
    tcsInvalidRange, tcsUnterminatedWithinLimit, tcsChangedDuringRead);

  TTLSCallbackSnapshot = record
    Valid: Boolean;
    Count: Cardinal;
    PrivateExecutable: Cardinal;
    Digest: UInt64;
    Status: TTLSCaptureStatus; // reason only; never a detection by itself
  end;

  TTLSCallbackMonitor = class
  private
    FPrimed: Boolean;
    FBaselineDigest: UInt64;
    FLastDigest: UInt64;
    FPendingPrivate: Cardinal;
    FPendingTick: UInt64;
    FLastTick: UInt64;
    FLastEvidence: UInt64;
    FLastReport: UInt64;
    FConfirmations: Integer;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, ExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CaptureTLSCallbacks(out Snapshot: TTLSCallbackSnapshot): Boolean;
function TLSCallbackAnomaly(BaselineHash, CurrentHash: UInt64;
  PrivateCallbacks: Cardinal; Confirmations: Integer;
  IndependentlyCorroborated: Boolean): Boolean;

{$IFDEF NHW_NATIVE5F_TESTS}
function TestTLSHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.PEView, Cozy.NHW.NativeSafety;

const
  TLS_SCAN_MS = 8000;
  TLS_CORRELATION_MS = 30000;
  TLS_REPORT_COOLDOWN_MS = 60000;
  MAX_TLS_CALLBACKS = 64;

type
  TTLSDirectory64 = packed record
    StartRawVA: UInt64;
    EndRawVA: UInt64;
    AddressOfIndex: UInt64;
    AddressOfCallbacks: UInt64;
    ZeroFill: Cardinal;
    Characteristics: Cardinal;
  end;

{$IFDEF NHW_NATIVE5F_TESTS}
type
  TTLSViewHook = function(out View: TPEView): Boolean;
  TTLSReadHook = function(Address: NativeUInt; var Dest;
    Bytes: NativeUInt): Boolean;
  TTLSDescribeHook = function(Address: NativeUInt;
    out Kind: TCodeLocation; out RegionBase: NativeUInt): Boolean;
  TTLSCaptureHook = function(out Snapshot: TTLSCallbackSnapshot): Boolean;
var
  TLSViewHook: TTLSViewHook = nil;
  TLSReadHook: TTLSReadHook = nil;
  TLSDescribeHook: TTLSDescribeHook = nil;
  TLSCaptureHook: TTLSCaptureHook = nil;
{$ENDIF}

function TLSView(out View: TPEView): Boolean;
begin
  View := Default(TPEView);
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(TLSViewHook) then Exit(TLSViewHook(View));
{$ENDIF}
  Result := LoadPEView(NativeUInt(HInstance), View);
end;

function TLSRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) then Exit;
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(TLSReadHook) then Exit(TLSReadHook(Address, Dest, Bytes));
{$ENDIF}
  Result := LocalRead(Address, Dest, Bytes);
end;

function TLSDescribe(Address: NativeUInt; out Kind: TCodeLocation;
  out RegionBase: NativeUInt): Boolean;
begin
  Kind := clUnknown;
  RegionBase := 0;
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(TLSDescribeHook) then
    Exit(TLSDescribeHook(Address, Kind, RegionBase));
{$ENDIF}
  Result := DescribeCodeAddress(Address, Kind, RegionBase);
end;

function SameTLSDirectory(const A, B: TTLSDirectory64): Boolean;
begin
  Result := (A.StartRawVA = B.StartRawVA) and (A.EndRawVA = B.EndRawVA) and
    (A.AddressOfIndex = B.AddressOfIndex) and
    (A.AddressOfCallbacks = B.AddressOfCallbacks) and
    (A.ZeroFill = B.ZeroFill) and (A.Characteristics = B.Characteristics);
end;

function SameTLSView(const A, B: TPEView): Boolean;
begin
  Result := (A.Base = B.Base) and (A.ImageSize = B.ImageSize) and
    (A.Directory[9].RVA = B.Directory[9].RVA) and
    (A.Directory[9].Size = B.Directory[9].Size);
end;

function CaptureTLSCallbacks(out Snapshot: TTLSCallbackSnapshot): Boolean;
var
  View, VerifyView: TPEView;
  Candidate: TTLSCallbackSnapshot;
  Dir, CallbackSlot, RegionBase: NativeUInt;
  Bytes, SlotsRead: Cardinal;
  TLS, VerifyTLS: TTLSDirectory64;
  Callbacks: array[0..MAX_TLS_CALLBACKS] of UInt64;
  CallbackVA: UInt64;
  Kind: TCodeLocation;
  Terminated: Boolean;
  Status: TTLSCaptureStatus;
  function ReadTLSDirectory: Boolean;
  begin
    Result := False;
    if (View.Directory[9].RVA = 0) or
      not PEDataAddress(View, 9, SizeOf(TTLSDirectory64), Dir, Bytes) then
    begin Status := tcsInvalidRange; Exit; end;
    if not TLSRead(Dir, TLS, SizeOf(TLS)) then Exit;
    Result := True;
  end;

  function CollectCallbackSlots: Boolean;
  var
    I: Cardinal;
  begin
    Result := False;
    SlotsRead := 0;
    if TLS.AddressOfCallbacks <> 0 then
    begin
      Terminated := False;
      // Permit 64 nonzero callbacks AND their terminating slot. The 65th
      // nonzero value is an incomplete/over-limit snapshot, not an attack.
      for I := 0 to MAX_TLS_CALLBACKS do
      begin
        if not NHWTryAddAddress(NativeUInt(TLS.AddressOfCallbacks),
          NativeUInt(I) * SizeOf(UInt64), CallbackSlot) or
          not NHWAddressSpan(CallbackSlot, SizeOf(UInt64)) then
        begin Status := tcsInvalidRange; Exit; end;
        if not TLSRead(CallbackSlot, CallbackVA, SizeOf(CallbackVA)) then Exit;
        Callbacks[I] := CallbackVA;
        Inc(SlotsRead);
        if CallbackVA = 0 then
        begin Terminated := True; Break; end;
        if I = MAX_TLS_CALLBACKS then
        begin Status := tcsUnterminatedWithinLimit; Exit; end;
        if not TLSDescribe(NativeUInt(CallbackVA), Kind, RegionBase) then Exit;
        Inc(Candidate.Count);
        Candidate.Digest := PEHash(Candidate.Digest, CallbackVA);
        if Kind = clPrivate then Inc(Candidate.PrivateExecutable);
      end;
      if not Terminated then
      begin Status := tcsUnterminatedWithinLimit; Exit; end;
    end;
    Result := True;
  end;

  function VerifyCallbackCollection: Boolean;
  var
    I: Cardinal;
  begin
    Result := False;
    // Re-read the entire observed array INCLUDING the null terminator.
    // This catches a change visible between the two reads, not an ABA race.
    if not TLSRead(Dir, VerifyTLS, SizeOf(VerifyTLS)) then Exit;
    if not SameTLSDirectory(TLS, VerifyTLS) then
    begin Status := tcsChangedDuringRead; Exit; end;
    if SlotsRead <> 0 then
      for I := 0 to SlotsRead - 1 do
      begin
        if not NHWTryAddAddress(NativeUInt(TLS.AddressOfCallbacks),
          NativeUInt(I) * SizeOf(UInt64), CallbackSlot) then
        begin Status := tcsInvalidRange; Exit; end;
        if not TLSRead(CallbackSlot, CallbackVA, SizeOf(CallbackVA)) then Exit;
        if CallbackVA <> Callbacks[I] then
        begin Status := tcsChangedDuringRead; Exit; end;
      end;
    if not TLSRead(Dir, VerifyTLS, SizeOf(VerifyTLS)) or
      not TLSView(VerifyView) then Exit;
    if not SameTLSDirectory(TLS, VerifyTLS) or
      not SameTLSView(View, VerifyView) then
    begin Status := tcsChangedDuringRead; Exit; end;
    Result := True;
  end;

begin
  Snapshot := Default(TTLSCallbackSnapshot);
  Candidate := Default(TTLSCallbackSnapshot);
  Result := False;
  Status := tcsReadFailed;
  FillChar(Callbacks, SizeOf(Callbacks), 0);
  TLS := Default(TTLSDirectory64);
  VerifyTLS := Default(TTLSDirectory64);
  CallbackVA := 0;
  try
    if not TLSView(View) then Exit;
    Candidate.Digest := UInt64($CBF29CE484222325);
    if (View.Directory[9].RVA = 0) and (View.Directory[9].Size = 0) then
    begin
      if not TLSView(VerifyView) then Exit;
      if not SameTLSView(View, VerifyView) then
      begin Status := tcsChangedDuringRead; Exit; end;
      Candidate.Valid := True;
      Candidate.Status := tcsComplete;
      Snapshot := Candidate;
      Exit(True);
    end;
    if not ReadTLSDirectory then Exit;
    if not CollectCallbackSlots then Exit;
    if not VerifyCallbackCollection then Exit;
    Candidate.Valid := True;
    Candidate.Status := tcsComplete;
    Snapshot := Candidate;
    Result := True;
  finally
    if not Result then
    begin
      Snapshot := Default(TTLSCallbackSnapshot);
      Snapshot.Status := Status;
    end;
  end;
end;

function ReadTLSCallbacks(out Snapshot: TTLSCallbackSnapshot): Boolean;
begin
  Snapshot := Default(TTLSCallbackSnapshot);
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(TLSCaptureHook) then Exit(TLSCaptureHook(Snapshot));
{$ENDIF}
  Result := CaptureTLSCallbacks(Snapshot);
end;

function TLSCallbackAnomaly(BaselineHash, CurrentHash: UInt64;
  PrivateCallbacks: Cardinal; Confirmations: Integer;
  IndependentlyCorroborated: Boolean): Boolean;
begin
  Result := (BaselineHash <> CurrentHash) and
    (PrivateCallbacks > 0) and (Confirmations >= 2) and
    IndependentlyCorroborated;
end;

constructor TTLSCallbackMonitor.Create;
begin inherited Create; Reset; end;

procedure TTLSCallbackMonitor.ClearCandidate;
begin
  FLastDigest := 0;
  FPendingPrivate := 0;
  FPendingTick := 0;
  FConfirmations := 0;
end;

procedure TTLSCallbackMonitor.Reset;
begin
  FPrimed := False;
  FBaselineDigest := 0;
  FLastTick := 0;
  FLastEvidence := 0;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TTLSCallbackMonitor.Examine(Baseline,
  ExternalAccess: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var Snap: TTLSCallbackSnapshot;
begin
  if (FLastTick <> 0) and (Tick < FLastTick) then
  begin
    ClearCandidate;
    FLastEvidence := 0;
    FLastReport := 0;
  end;
  if Baseline or ((FConfirmations <> 0) and
    NHWExpired(FPendingTick, Tick, TLS_CORRELATION_MS)) then ClearCandidate;
  if ExternalAccess or ((Detected * [dkTLSDirectory, dkTLSPointer,
    dkPECodeIntegrity, dkPrivateThread]) <> []) then FLastEvidence := Tick;
  if (FLastTick <> 0) and (Tick >= FLastTick) and
    (Tick - FLastTick < TLS_SCAN_MS) then Exit;
  FLastTick := Tick;
  try
    if not ReadTLSCallbacks(Snap) or not Snap.Valid or
      (Snap.Status <> tcsComplete) or (Snap.Count > MAX_TLS_CALLBACKS) or
      (Snap.PrivateExecutable > Snap.Count) then
    begin ClearCandidate; Exit; end;
  except
    ClearCandidate;
    raise;
  end;
  if not FPrimed or Baseline then
  begin
    FPrimed := True;
    FBaselineDigest := Snap.Digest;
    ClearCandidate;
    Exit;
  end;
  if Snap.Digest = FBaselineDigest then
  begin ClearCandidate; Exit; end;
  if (FConfirmations > 0) and (Snap.Digest = FLastDigest) and
    (Snap.PrivateExecutable = FPendingPrivate) then
  begin
    if FConfirmations < 2 then Inc(FConfirmations);
  end
  else
  begin
    FLastDigest := Snap.Digest;
    FPendingPrivate := Snap.PrivateExecutable;
    FPendingTick := Tick;
    FConfirmations := 1;
  end;
  if TLSCallbackAnomaly(FBaselineDigest, Snap.Digest,
    Snap.PrivateExecutable, FConfirmations,
    (FLastEvidence <> 0) and (Tick >= FLastEvidence) and
    (Tick - FLastEvidence <= TLS_CORRELATION_MS)) and
    ((FLastReport = 0) or ((Tick >= FLastReport) and
    (Tick - FLastReport >= TLS_REPORT_COOLDOWN_MS))) then
  begin
    Include(Detected, dkTLSCallbackIntegrity);
    FLastReport := Tick;
  end;
end;

{$IFDEF NHW_NATIVE5F_TESTS}
{$I Cozy.NHW.Native5F.TLS.inc}
{$ENDIF}

end.
