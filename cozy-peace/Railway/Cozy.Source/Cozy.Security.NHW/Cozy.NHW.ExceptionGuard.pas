unit Cozy.NHW.ExceptionGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.Logging,
  Cozy.NHW.ExceptionRules,
  Cozy.NHW.SelfRules;

type
  TExceptionGuardMonitor = class
  private
    FTable: TStableFingerprint;
    FRanges: TStableFingerprint;
    FUnwind: TStableFingerprint;
    FCallback: TStableFingerprint;
    FRangeFault: TConfirmedCondition;
    FUnwindFault: TConfirmedCondition;
    FLookupFault: TConfirmedCondition;
    FInitialized: Boolean;
    FRegistration: Pointer;
    FRegisteredCallback: NativeUInt;
    FCallbackTicket: NativeUInt;
    FCallbackHandleCopy: NativeUInt;
    FCallbackMagic: UInt64;
    FCallbackExpected: UInt64;
    FLastExternalTick: UInt64;
    FLastCheck: UInt64;
    procedure BreakPending;
    function CallbackState(out Hash: UInt64): Boolean;
    procedure StartPassiveCallback;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      HighExternalAccess: Boolean; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5K_TESTS}
function TestExceptionGuard5K(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils, Cozy.NHW.ExceptionNative;

const
  EXCEPTION_QUERY_INTERVAL_MS = 2000;
  EXCEPTION_CORRELATION_WINDOW_MS = 8000;
  EXCEPTION_CALLBACK_MAGIC = UInt64($36B8ED45921AC07F);

{$IFDEF NHW_NATIVE5K_TESTS}
type
  TExceptionCapture5KHook = function(out S: TExceptionImageState): Boolean;
  TExceptionCallback5KHook = function(out Hash: UInt64): Boolean;
var
  ExceptionCapture5KHook: TExceptionCapture5KHook = nil;
  ExceptionCallback5KHook: TExceptionCallback5KHook = nil;
  ExceptionNoRegister5K: Boolean = False;
{$ENDIF}

procedure BreakFingerprintPending(var State: TStableFingerprint);
begin
  State.CandidateCount := 0;
  if not State.AlreadyReported then State.Candidate := State.Baseline;
end;

procedure TExceptionGuardMonitor.BreakPending;
begin
  BreakFingerprintPending(FTable);
  BreakFingerprintPending(FRanges);
  BreakFingerprintPending(FUnwind);
  BreakFingerprintPending(FCallback);
  FRangeFault.Consecutive := 0;
  FUnwindFault.Consecutive := 0;
  FLookupFault.Consecutive := 0;
end;

function CaptureGuardExceptionImage(out S: TExceptionImageState): Boolean;
begin
{$IFDEF NHW_NATIVE5K_TESTS}
  if Assigned(ExceptionCapture5KHook) then Exit(ExceptionCapture5KHook(S));
{$ENDIF}
  Result := CaptureExceptionImage(S);
end;

// Pass-through: never consume exceptions or modify the CONTEXT, and never
// call debugger-detection APIs. No artificial exception is triggered.
function PassiveExceptionHandler(ExceptionPointers: Pointer): LongInt; stdcall;
begin
  Result := 0; // EXCEPTION_CONTINUE_SEARCH
end;

constructor TExceptionGuardMonitor.Create;
begin
  inherited Create;
  FRegistration := nil;
  FRegisteredCallback := 0;
  FCallbackTicket := 0;
  Reset;
end;

destructor TExceptionGuardMonitor.Destroy;
begin
  UnregisterPassThroughExceptionHandler(FRegistration);
  inherited Destroy;
end;

procedure TExceptionGuardMonitor.StartPassiveCallback;
begin
{$IFDEF NHW_NATIVE5K_TESTS}
  if ExceptionNoRegister5K then Exit;
{$ENDIF}
  UnregisterPassThroughExceptionHandler(FRegistration);
  FRegisteredCallback := NativeUInt(@PassiveExceptionHandler);
  FRegistration := RegisterPassThroughExceptionHandler(
    Pointer(FRegisteredCallback));
  if FRegistration <> nil then
  begin
    FCallbackTicket := FRegisteredCallback;
    FCallbackHandleCopy := NativeUInt(FRegistration);
    FCallbackMagic := EXCEPTION_CALLBACK_MAGIC;
  end
  else
  begin
    FCallbackTicket := 0;
    FCallbackHandleCopy := 0;
    FCallbackMagic := 0;
  end;
  FCallbackExpected := 0;
end;

procedure TExceptionGuardMonitor.Reset;
begin
  FTable := Default(TStableFingerprint);
  FRanges := Default(TStableFingerprint);
  FUnwind := Default(TStableFingerprint);
  FCallback := Default(TStableFingerprint);
  FRangeFault := Default(TConfirmedCondition);
  FUnwindFault := Default(TConfirmedCondition);
  FLookupFault := Default(TConfirmedCondition);
  FInitialized := False;
  FLastCheck := 0;
  FLastExternalTick := 0;
  StartPassiveCallback;
end;

function TExceptionGuardMonitor.CallbackState(out Hash: UInt64): Boolean;
begin
  Result := False;
  Hash := 0;
{$IFDEF NHW_NATIVE5K_TESTS}
  if Assigned(ExceptionCallback5KHook) then Exit(ExceptionCallback5KHook(Hash));
{$ENDIF}
  if FRegistration = nil then Exit;
  // Inspect only the references that THIS monitor owns. The native VEH
  // registration chain is undocumented and is never traversed.
  try
    if FCallbackTicket = 0 then Exit;
    if not IsReadableLocalRange(NativeUInt(@FCallbackTicket),
       SizeOf(FCallbackTicket)) then Exit;
    if not IsReadableLocalRange(NativeUInt(@FCallbackHandleCopy),
       SizeOf(FCallbackHandleCopy)) then Exit;
    if not IsReadableLocalRange(NativeUInt(@FCallbackMagic),
       SizeOf(FCallbackMagic)) then Exit;
    Hash := ExceptionFingerprint(UInt64($CBF29CE484222325),
      UInt64(FCallbackTicket));
    Hash := ExceptionFingerprint(Hash, UInt64(FCallbackHandleCopy));
    Hash := ExceptionFingerprint(Hash, FCallbackMagic);
    // Stable nonzero expected state is recorded at registration. A change
    // here is the application's callback-reference mutation, not proof of
    // mutation of Windows' internal VEH list.
    Result := True;
  except
    Result := False;
  end;
end;

procedure TExceptionGuardMonitor.Examine(Baseline: Boolean; Tick: UInt64;
  HighExternalAccess: Boolean; var Detected: TDetectionKinds);
var
  S: TExceptionImageState;
  CallbackHash: UInt64;
  Internal: TDetectionKinds;
  HaveCallback: Boolean;

  procedure EstablishApprovedBaseline;
  begin
    FTable := Default(TStableFingerprint);
    FRanges := Default(TStableFingerprint);
    FUnwind := Default(TStableFingerprint);
    FCallback := Default(TStableFingerprint);
    ObserveFingerprint(FTable, S.TableDigest, True);
    ObserveFingerprint(FRanges, S.RangeDigest, True);
    ObserveFingerprint(FUnwind, S.UnwindDigest, True);
    if HaveCallback then
    begin
      FCallbackExpected := CallbackHash;
      ObserveFingerprint(FCallback, CallbackHash, True);
    end;
    FInitialized := True;
  end;

  procedure ObserveImageFingerprints;
  begin
    if ObserveFingerprint(FTable, S.TableDigest, True) then
      Include(Internal, dkFunctionTable);
    if ObserveFingerprint(FRanges, S.RangeDigest, True) then
      Include(Internal, dkExceptionRange);
    if S.HasUnwindSamples and S.UnwindValid then
    begin
      if ObserveFingerprint(FUnwind, S.UnwindDigest, True) then
        Include(Internal, dkUnwind);
    end
    else
      BreakFingerprintPending(FUnwind);
  end;

  procedure ObserveStructuralFaults;
  begin
    if ConfirmExceptionCondition(FRangeFault, not S.RangeValid) then
      Include(Internal, dkExceptionRange);
    if ConfirmExceptionCondition(FUnwindFault,
       S.RangeValid and not S.UnwindValid) then
      Include(Internal, dkUnwind);
    if ConfirmExceptionCondition(FLookupFault,
       S.RangeValid and S.HasLookupSamples and not S.LookupConsistent) then
      Include(Internal, dkFunctionTable);
  end;

  procedure ObserveCallbackFingerprint;
  begin
    if HaveCallback and (FCallbackExpected <> 0) then
    begin
      if ObserveFingerprint(FCallback, CallbackHash, True) then
        Include(Internal, dkExceptionCallback);
    end
    else
      BreakFingerprintPending(FCallback);
  end;

begin
  if HighExternalAccess and not Baseline then FLastExternalTick := Tick;
  if not Baseline and (FLastCheck <> 0) and (Tick >= FLastCheck) and
     ((Tick - FLastCheck) < EXCEPTION_QUERY_INTERVAL_MS) then Exit;
  if Baseline then
  begin
    BreakPending;
    FLastExternalTick := 0;
  end;
  if (FLastCheck <> 0) and
    ((Tick < FLastCheck) or (Tick - FLastCheck > EXCEPTION_CORRELATION_WINDOW_MS)) then
    BreakPending;
  FLastCheck := Tick;
  try
    if not CaptureGuardExceptionImage(S) then
    begin
      BreakPending;
      Exit;
    end;
    HaveCallback := CallbackState(CallbackHash);
  except
    BreakPending;
    raise;
  end;
  if Baseline or not FInitialized then
  begin
    // A malformed initial image is UNKNOWN; do not use it as a trusted
    // reference or spam a detection immediately at startup.
    if not S.RangeValid or not S.UnwindValid or
       not S.HasUnwindSamples then Exit;
    EstablishApprovedBaseline;
    Exit;
  end;

  Internal := [];
  ObserveImageFingerprints;
  ObserveStructuralFaults;
  ObserveCallbackFingerprint;
  Detected := Detected + Internal;
  if (Internal <> []) and WithinBoundaryWindow(Tick, FLastExternalTick,
       EXCEPTION_CORRELATION_WINDOW_MS) then
    Include(Detected, dkExceptionCorrelation);
end;

{$IFDEF NHW_NATIVE5K_TESTS}
{$I Cozy.NHW.Native5K.ExceptionGuard.inc}
{$ENDIF}

end.
