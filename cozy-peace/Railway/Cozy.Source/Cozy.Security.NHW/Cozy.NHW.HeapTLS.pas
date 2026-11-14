unit Cozy.NHW.HeapTLS;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Logging,
  Cozy.NHW.HeapTLSRules;

type
  THeapTLSMonitor = class
  private
    FSupported: Boolean;
    FOwnerThread: Cardinal;
    FTlsSlot: Cardinal;
    FFlsSlot: Cardinal;
    FPrivateHeap: THandle;
    FCanary: Pointer;
    FTicket: PHeapTLSCallbackTicket;
    FExpectedCallback: NativeUInt;
    FLastCheck: UInt64;
    FLastExternalHighTick: UInt64;
    FTlsPending: Integer;
    FFlsPending: Integer;
    FCanaryPending: Integer;
    FTlsAlerted: Boolean;
    FFlsAlerted: Boolean;
    FCanaryAlerted: Boolean;
    FHeapReady: Boolean;
    FHeapPending: Integer;
    FHeapExpected: TArray<NativeUInt>;
    FHeapCandidate: TArray<NativeUInt>;
    procedure BreakLocalConfirmations;
    procedure InspectHeapSet(Baseline: Boolean; var Detected: TDetectionKinds);
    procedure InspectLocalSlots(Baseline: Boolean; var Detected: TDetectionKinds);
    procedure PrepareOwnedResources;
    procedure PrepareTLSSlot;
    procedure PrepareFLSSlot;
    procedure ReleaseOwnedResources;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      HighExternalAccess: Boolean; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5L_TESTS}
function TestHeapTLS5L(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.HeapTLSNative;

const
  HEAP_TLS_INTERVAL_MS = 2000;
  HEAP_TLS_CORRELATION_MS = 8000;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.HeapTLS.Hooks.inc}
{$ENDIF}

procedure HeapTLSFlsCallback(Data: Pointer); stdcall;
begin
  // The slot refers to a private heap allocation; the owning monitor
  // releases it explicitly at shutdown. No memory is freed from a callback.
  if Data = nil then Exit;
end;

procedure THeapTLSMonitor.PrepareTLSSlot;
begin
  if FCanary <> nil then
  begin
    FTlsSlot := LocalTlsAlloc;
    if (FTlsSlot <> INVALID_LOCAL_SLOT) and
       not LocalTlsSetValue(FTlsSlot, FCanary) then
    begin
      LocalTlsFree(FTlsSlot);
      FTlsSlot := INVALID_LOCAL_SLOT;
    end;
  end;
end;

procedure THeapTLSMonitor.PrepareFLSSlot;
begin
  if FTicket <> nil then
  begin
    FFlsSlot := LocalFlsAlloc(@HeapTLSFlsCallback);
    if FFlsSlot <> INVALID_LOCAL_SLOT then
    begin
      FExpectedCallback := NativeUInt(@HeapTLSFlsCallback);
      FTicket^.CallbackAddress := FExpectedCallback;
      FTicket^.SlotIndex := FFlsSlot;
      FTicket^.Reserved := 0;
      FTicket^.Magic := HEAP_TLS_CALLBACK_MAGIC;
      if not LocalFlsSetValue(FFlsSlot, FTicket) then
      begin
        LocalFlsFree(FFlsSlot);
        FFlsSlot := INVALID_LOCAL_SLOT;
      end;
    end;
  end;
end;

procedure THeapTLSMonitor.PrepareOwnedResources;
begin
  if FSupported then
  begin
    FOwnerThread := LocalThreadID;
    FPrivateHeap := LocalHeapCreate;
    if FPrivateHeap <> 0 then
    begin
      FCanary := LocalHeapAlloc(FPrivateHeap, HEAP_TLS_CANARY_BYTES);
      FTicket := PHeapTLSCallbackTicket(LocalHeapAlloc(FPrivateHeap,
        SizeOf(THeapTLSCallbackTicket)));
      if FCanary <> nil then
        FillHeapTLSCanary(FCanary);

      PrepareTLSSlot;

      PrepareFLSSlot;
    end;
  end;
end;

constructor THeapTLSMonitor.Create;
begin
  inherited Create;
  FTlsSlot := INVALID_LOCAL_SLOT;
  FFlsSlot := INVALID_LOCAL_SLOT;
  FOwnerThread := 0;
  FPrivateHeap := 0;
  FCanary := nil;
  FTicket := nil;
  FSupported := ResolveHeapTLSFunctions;
  try
    PrepareOwnedResources;
  except
    // Optional monitor failure must not stop existing v31 functionality.
  end;
  Reset;
end;

procedure THeapTLSMonitor.ReleaseOwnedResources;
begin
  // Called on the original engine thread, where TLS/FLS slots were populated.
  if FTlsSlot <> INVALID_LOCAL_SLOT then
  begin
    LocalTlsSetValue(FTlsSlot, nil);
    LocalTlsFree(FTlsSlot);
  end;
  if FFlsSlot <> INVALID_LOCAL_SLOT then
  begin
    LocalFlsSetValue(FFlsSlot, nil);
    LocalFlsFree(FFlsSlot);
  end;
  LocalHeapFree(FPrivateHeap, FTicket);
  LocalHeapFree(FPrivateHeap, FCanary);
  LocalHeapDestroy(FPrivateHeap);
end;

destructor THeapTLSMonitor.Destroy;
begin
  ReleaseOwnedResources;
  inherited Destroy;
end;

procedure THeapTLSMonitor.Reset;
begin
  FLastCheck := 0;
  FLastExternalHighTick := 0;
  FTlsPending := 0;
  FFlsPending := 0;
  FCanaryPending := 0;
  FTlsAlerted := False;
  FFlsAlerted := False;
  FCanaryAlerted := False;
  FHeapReady := False;
  FHeapPending := 0;
  SetLength(FHeapExpected, 0);
  SetLength(FHeapCandidate, 0);
  // Deliberately do NOT rewrite TLS/FLS slots or the canary: a reset
  // re-baselines the *heap list* only, it does not erase a real modification.
end;

procedure THeapTLSMonitor.BreakLocalConfirmations;
begin
  // UNKNOWN is not recovery: retain alert latches until a valid good sample.
  FTlsPending := 0;
  FFlsPending := 0;
  FCanaryPending := 0;
end;

procedure THeapTLSMonitor.InspectHeapSet(Baseline: Boolean;
  var Detected: TDetectionKinds);
var
  Current: TArray<NativeUInt>;
begin
  try
    if not LocalHeapSnapshot(Current) then
    begin
      FHeapPending := 0;
      SetLength(FHeapCandidate, 0);
      Exit; // Preserve the last complete accepted heap set.
    end;
    if not FHeapReady or Baseline then
    begin
      FHeapExpected := Copy(Current, 0, Length(Current));
      SetLength(FHeapCandidate, 0);
      FHeapPending := 0;
      FHeapReady := True;
      Exit;
    end;
    if HeapTLSHeapsEqual(FHeapExpected, Current) then
    begin
      FHeapPending := 0;
      SetLength(FHeapCandidate, 0);
      Exit;
    end;
    if HeapTLSHeapsEqual(FHeapCandidate, Current) then
    begin
      if FHeapPending < 2 then Inc(FHeapPending);
    end
    else
    begin
      FHeapCandidate := Copy(Current, 0, Length(Current));
      FHeapPending := 1;
    end;
    if FHeapPending >= 2 then
    begin
      Include(Detected, dkHeapState);
      FHeapExpected := Copy(Current, 0, Length(Current));
      FHeapPending := 0;
      SetLength(FHeapCandidate, 0);
    end;
  except
    FHeapPending := 0;
    SetLength(FHeapCandidate, 0);
    raise; // Let the existing sensor-fault layer record the failure.
  end;
end;

procedure THeapTLSMonitor.InspectLocalSlots(Baseline: Boolean;
  var Detected: TDetectionKinds);
var
  TlsChanged, FlsChanged, CanaryChanged: Boolean;
  FlsValid, CanaryValid: Boolean;

  procedure ReadOwnedSlotState;
  var
    TlsValue, FlsValue: Pointer;
    TicketIntact, CanaryIntact: Boolean;
  begin
    TlsChanged := False;
    FlsChanged := False;
    CanaryChanged := False;

    if FTlsSlot <> INVALID_LOCAL_SLOT then
    begin
      TlsValue := LocalTlsGetValue(FTlsSlot);
      TlsChanged := TlsValue <> FCanary;
    end;

    FlsValid := FFlsSlot <> INVALID_LOCAL_SLOT;
    if FlsValid then
    begin
      FlsValue := LocalFlsGetValue(FFlsSlot);
      FlsValid := TryCallbackTicketIntact(FTicket, FExpectedCallback,
        FFlsSlot, TicketIntact);
      if FlsValid then
        FlsChanged := (FlsValue <> FTicket) or (not TicketIntact);
    end;

    CanaryValid := TryHeapTLSCanaryIntact(FCanary, CanaryIntact);
    if CanaryValid then CanaryChanged := not CanaryIntact;
  end;

  procedure ApplyTLSObservation;
  begin
    if FTlsSlot = INVALID_LOCAL_SLOT then
      FTlsPending := 0
    else if TlsChanged then
    begin
      if FTlsPending < 2 then Inc(FTlsPending);
      if (FTlsPending >= 2) and not FTlsAlerted then
      begin
        Include(Detected, dkTLSPointer);
        FTlsAlerted := True;
      end;
    end
    else
    begin
      FTlsPending := 0;
      FTlsAlerted := False;
    end;
  end;

  procedure ApplyFLSObservation;
  begin
    if FFlsSlot <> INVALID_LOCAL_SLOT then
    begin
      if FlsValid and FlsChanged then
      begin
        if FFlsPending < 2 then Inc(FFlsPending);
        if (FFlsPending >= 2) and not FFlsAlerted then
        begin
          Include(Detected, dkFLSCallback);
          FFlsAlerted := True;
        end;
      end
      else
      begin
        FFlsPending := 0;
        if FlsValid then FFlsAlerted := False;
      end;
    end
    else
      FFlsPending := 0;
  end;

  procedure ApplyCanaryObservation;
  begin
    if CanaryValid then
    begin
      if CanaryChanged then
      begin
        if FCanaryPending < 2 then Inc(FCanaryPending);
        if (FCanaryPending >= 2) and not FCanaryAlerted then
        begin
          Include(Detected, dkHeapIntegrity);
          FCanaryAlerted := True;
        end;
      end
      else
      begin
        FCanaryPending := 0;
        FCanaryAlerted := False;
      end;
    end
    else
      FCanaryPending := 0;
  end;

begin
  try
    if (LocalThreadID <> FOwnerThread) or Baseline then
    begin
      BreakLocalConfirmations;
      Exit;
    end;
    ReadOwnedSlotState;
    ApplyTLSObservation;
    ApplyFLSObservation;
    ApplyCanaryObservation;
  except
    BreakLocalConfirmations;
    raise;
  end;
end;

procedure THeapTLSMonitor.Examine(Baseline: Boolean; Tick: UInt64;
  HighExternalAccess: Boolean; var Detected: TDetectionKinds);
var
  Internal: TDetectionKinds;
begin
  if not FSupported then Exit;
  if HighExternalAccess and not Baseline then
    FLastExternalHighTick := Tick;
  if (not Baseline) and (FLastCheck <> 0) and
     (Tick >= FLastCheck) and
     ((Tick - FLastCheck) < HEAP_TLS_INTERVAL_MS) then Exit;
  FLastCheck := Tick;
  Internal := [];
  try
    InspectHeapSet(Baseline, Internal);
    InspectLocalSlots(Baseline, Internal);
  except
    // The second probe may not have run if the first one failed.
    FHeapPending := 0;
    SetLength(FHeapCandidate, 0);
    BreakLocalConfirmations;
    raise;
  end;
  Detected := Detected + Internal;
  if (Internal <> []) and
     HeapTLSRecent(Tick, FLastExternalHighTick,
       HEAP_TLS_CORRELATION_MS) then
    Include(Detected, dkHeapCorrelation);
end;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.HeapTLS.inc}
{$ENDIF}

end.
