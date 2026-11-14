unit Cozy.NHW.Registry;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.RegistryNative;

type
  // Pure comparison model. One failed query is UNKNOWN, never a change.
  TRegistryEvidence = record
    ValuesKnown: Boolean;
    ValuesHash: UInt64;
    KeysKnown: Boolean;
    KeysHash: UInt64;
    DaclKnown: Boolean;
    DaclHash: UInt64;
  end;

  TRegistryEvidenceState = record
  private
    FValuesKnown: Boolean;
    FValuesHash: UInt64;
    FKeysKnown: Boolean;
    FKeysHash: UInt64;
    FDaclKnown: Boolean;
    FDaclHash: UInt64;
  public
    procedure Reset;
    procedure Observe(const E: TRegistryEvidence; Baseline: Boolean;
      var Detected: TDetectionKinds);
  end;

  TRegistryWatch = class
  private
    FNativePath: string;
    FPolicyScope: Boolean;
    FKey: THandle;
    FEvent: THandle;
    FIo: TRegIoStatusBlock;
    FArmed: Boolean;
    FPrimeRemaining: Integer;
    FValuesPrime, FKeysPrime, FDaclPrime, FPrimeAttempts: Integer;
    FLastCheck: UInt64;
    FRetryAfter: UInt64;
    FState: TRegistryEvidenceState;
    procedure ResetPrime;
    procedure ApplyEvidence(const E: TRegistryEvidence; Baseline: Boolean;
      var Detected: TDetectionKinds);
    procedure CloseHandles;
    function OpenIfNeeded(Tick: UInt64): Boolean;
    procedure Arm;
    procedure Capture(Baseline: Boolean; var Detected: TDetectionKinds);
  public
    constructor Create(const Path: string; PolicyScope: Boolean);
    destructor Destroy; override;
    procedure Reset;
    procedure DeferRetry(Tick: UInt64);
    procedure Poll(Tick: UInt64; var Detected: TDetectionKinds;
      out NotificationCount: Integer);
  end;

  TRegistryMonitor = class
  private
    FWatches: TList<TRegistryWatch>;
    FRecent: TList<UInt64>;
    FInBurst: Boolean;
    procedure AddWatch(const NativePath: string; PolicyScope: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestRegistry10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.Registry.EvidenceReader;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.Registry.Hooks.inc}
{$ENDIF}

const
  REG_PRIME_INTERVAL_MS = 500;
  REG_MAX_FAST_PRIME_ATTEMPTS = 12;
  REG_POLL_FALLBACK_MS = 15000;
  REG_REOPEN_INTERVAL_MS = 30000;
  REG_BURST_WINDOW_MS = 5000;
  REG_BURST_COUNT = 4;

{$Q-} // Preserve the original post-hash arithmetic mode.

procedure TRegistryEvidenceState.Reset;
begin
  FValuesKnown := False;
  FValuesHash := 0;
  FKeysKnown := False;
  FKeysHash := 0;
  FDaclKnown := False;
  FDaclHash := 0;
end;

procedure TRegistryEvidenceState.Observe(const E: TRegistryEvidence;
  Baseline: Boolean; var Detected: TDetectionKinds);
begin
  if E.ValuesKnown then
  begin
    if (not Baseline) and FValuesKnown and
       (FValuesHash <> E.ValuesHash) then
      Include(Detected, dkRegistryValue);
    FValuesKnown := True;
    FValuesHash := E.ValuesHash;
  end;
  if E.KeysKnown then
  begin
    if (not Baseline) and FKeysKnown and
       (FKeysHash <> E.KeysHash) then
      Include(Detected, dkRegistryKey);
    FKeysKnown := True;
    FKeysHash := E.KeysHash;
  end;
  if E.DaclKnown then
  begin
    if (not Baseline) and FDaclKnown and
       (FDaclHash <> E.DaclHash) then
      Include(Detected, dkRegistrySecurity);
    FDaclKnown := True;
    FDaclHash := E.DaclHash;
  end;
end;

constructor TRegistryWatch.Create(const Path: string; PolicyScope: Boolean);
begin
  inherited Create;
  FNativePath := Path;
  FPolicyScope := PolicyScope;
  FKey := 0;
  FEvent := 0;
  Reset;
end;

destructor TRegistryWatch.Destroy;
begin
  CloseHandles;
  inherited Destroy;
end;

procedure TRegistryWatch.CloseHandles;
begin
  // Closing the watched key cancels an outstanding native registry notify.
  NativeCloseRegistry(FKey);
  NativeCloseRegistry(FEvent);
  FArmed := False;
end;

procedure TRegistryWatch.ResetPrime;
begin
  FValuesPrime := 3;
  FKeysPrime := 3;
  FDaclPrime := 3;
  FPrimeRemaining := 3;
  FPrimeAttempts := 0;
end;

procedure TRegistryWatch.ApplyEvidence(const E: TRegistryEvidence;
  Baseline: Boolean; var Detected: TDetectionKinds);
var Part: TRegistryEvidence;
begin
  Part := Default(TRegistryEvidence);
  if E.ValuesKnown then
  begin
    Part.ValuesKnown := True;
    Part.ValuesHash := E.ValuesHash;
    FState.Observe(Part, Baseline or (FValuesPrime > 0), Detected);
    if FValuesPrime > 0 then Dec(FValuesPrime);
    Part.ValuesKnown := False;
  end;
  if E.KeysKnown then
  begin
    Part.KeysKnown := True;
    Part.KeysHash := E.KeysHash;
    FState.Observe(Part, Baseline or (FKeysPrime > 0), Detected);
    if FKeysPrime > 0 then Dec(FKeysPrime);
    Part.KeysKnown := False;
  end;
  if E.DaclKnown then
  begin
    Part.DaclKnown := True;
    Part.DaclHash := E.DaclHash;
    FState.Observe(Part, Baseline or (FDaclPrime > 0), Detected);
    if FDaclPrime > 0 then Dec(FDaclPrime);
  end;
  // A readable channel need not wait forever for an inaccessible DACL.
  // Each channel still has its own three-success warmup before it can alert.
  FPrimeRemaining := FValuesPrime;
  if FKeysPrime < FPrimeRemaining then FPrimeRemaining := FKeysPrime;
  if FDaclPrime < FPrimeRemaining then FPrimeRemaining := FDaclPrime;
end;

procedure TRegistryWatch.Reset;
begin
  CloseHandles;
  ResetPrime;
  FLastCheck := 0;
  FRetryAfter := 0;
  FIo := Default(TRegIoStatusBlock);
  FState.Reset;
end;

procedure TRegistryWatch.DeferRetry(Tick: UInt64);
begin
  Reset;
  FRetryAfter := Tick + REG_REOPEN_INTERVAL_MS;
end;

procedure TRegistryWatch.Arm;
var
  S: TRegNtStatus;
begin
  FArmed := False;
  if (FKey = 0) or (FEvent = 0) then Exit;
  FIo := Default(TRegIoStatusBlock);
  FIo.Status := TRegNtStatus(REG_STATUS_PENDING);
  S := NativeRegistryNotify(FKey, FEvent, @FIo);
  FArmed := (S = TRegNtStatus(REG_STATUS_PENDING)) or (S = 0);
end;

function TRegistryWatch.OpenIfNeeded(Tick: UInt64): Boolean;
var
  Empty: TDetectionKinds;
begin
  Result := FKey <> 0;
  if Result then Exit;
  if (FRetryAfter <> 0) and (Tick < FRetryAfter) then Exit(False);
  FRetryAfter := Tick + REG_REOPEN_INTERVAL_MS;
  FKey := NativeOpenRegistryKey(FNativePath);
  if FKey = 0 then Exit(False);
  // Event setup may fail under a restricted token; metadata polling is
  // still useful and has an explicit, slower fallback interval.
  FEvent := NativeCreateRegistryEvent;
  ResetPrime;
  FState.Reset;
  Empty := [];
  Capture(True, Empty);
  FLastCheck := Tick;
  Arm;
  Result := True;
end;

procedure TRegistryWatch.Capture(Baseline: Boolean;
  var Detected: TDetectionKinds);
var
  E: TRegistryEvidence;
begin
  if FKey = 0 then Exit;
  if FPrimeAttempts < REG_MAX_FAST_PRIME_ATTEMPTS then Inc(FPrimeAttempts);
  E := Default(TRegistryEvidence);
  E.ValuesKnown := ReadValues(FKey, E.ValuesHash);
  E.KeysKnown := ReadSubkeys(FKey, E.KeysHash);
  E.DaclKnown := ReadDacl(FKey, E.DaclHash);
  ApplyEvidence(E, Baseline, Detected);
end;

procedure TRegistryWatch.Poll(Tick: UInt64;
  var Detected: TDetectionKinds; out NotificationCount: Integer);
var
  ChangeEvent: Boolean;
  SavedStatus: TRegNtStatus;
  IsBaseline: Boolean;
begin
  NotificationCount := 0;
  if not OpenIfNeeded(Tick) then Exit;
  ChangeEvent := FArmed and NativePollRegistryEvent(FEvent);
  if ChangeEvent then
  begin
    SavedStatus := FIo.Status;
    FArmed := False;
    // Re-arm before the snapshot so the next event is not silently lost.
    if SavedStatus = 0 then
    begin
      IsBaseline := FPrimeRemaining > 0;
      if not IsBaseline then
      begin
        NotificationCount := 1;
        if FPolicyScope then Include(Detected, dkPolicy);
      end;
      Arm;
      Capture(False, Detected);
      FLastCheck := Tick;
    end
    else
    begin
      // Deleted/unavailable key: never compare against a fabricated empty key.
      CloseHandles;
      FRetryAfter := Tick + REG_REOPEN_INTERVAL_MS;
      Exit;
    end;
  end
  else if (FLastCheck = 0) or
          ((Tick >= FLastCheck) and
           (Tick - FLastCheck >= REG_POLL_FALLBACK_MS)) or
          ((FPrimeRemaining > 0) and
           (FPrimeAttempts < REG_MAX_FAST_PRIME_ATTEMPTS) and
           (Tick >= FLastCheck) and
           (Tick - FLastCheck >= REG_PRIME_INTERVAL_MS)) then
  begin
    Capture(False, Detected);
    FLastCheck := Tick;
    if not FArmed then Arm;
  end;
end;

constructor TRegistryMonitor.Create;
var
  W: TRegistryWatch;
begin
  inherited Create;
  FWatches := TList<TRegistryWatch>.Create;
  FRecent := TList<UInt64>.Create;
  FInBurst := False;
  try
    Reset;
  except
    // Optional registry instrumentation must not stop older detectors.
    for W in FWatches do W.Free;
    FWatches.Clear;
  end;
end;

destructor TRegistryMonitor.Destroy;
var
  W: TRegistryWatch;
begin
  for W in FWatches do W.Free;
  FRecent.Free;
  FWatches.Free;
  inherited Destroy;
end;

procedure TRegistryMonitor.AddWatch(const NativePath: string;
  PolicyScope: Boolean);
begin
  if NativePath <> '' then
    FWatches.Add(TRegistryWatch.Create(NativePath, PolicyScope));
end;

procedure TRegistryMonitor.Reset;
var
  W: TRegistryWatch;
  U: string;
begin
  for W in FWatches do W.Free;
  FWatches.Clear;
  FRecent.Clear;
  FInBurst := False;
  if not RegistryNativeAvailable then Exit;

  // Read-only, pre-existing OS configuration scopes. No key is ever created.
  AddWatch('\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies', True);
  AddWatch('\Registry\Machine\SOFTWARE\Policies\Microsoft\Windows', True);
  AddWatch('\Registry\Machine\SYSTEM\CurrentControlSet\Control\Session Manager', False);
  U := NativeCurrentUserRegistryRoot;
  if U <> '' then
  begin
    AddWatch(U + '\Software\Microsoft\Windows\CurrentVersion\Policies', True);
    AddWatch(U + '\Software\Policies\Microsoft\Windows', True);
  end;
end;

procedure TRegistryMonitor.Examine(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  W: TRegistryWatch;
  Count, I: Integer;
begin
  // A registry permission failure is UNKNOWN and must never stop the v15
  // process/thread/file monitoring pipeline.
  for W in FWatches do
  begin
    Count := 0;
    try
      W.Poll(Tick, Detected, Count);
    except
      W.DeferRetry(Tick);
    end;
    if Count > 0 then
      for I := 1 to Count do FRecent.Add(Tick);
  end;

  while (FRecent.Count > 0) and (Tick >= FRecent[0]) and
        (Tick - FRecent[0] > REG_BURST_WINDOW_MS) do
    FRecent.Delete(0);

  if FRecent.Count >= REG_BURST_COUNT then
  begin
    if not FInBurst then Include(Detected, dkRegistryBurst);
    FInBurst := True;
  end
  else
    FInBurst := False;
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.Registry.inc}
{$ENDIF}

end.
