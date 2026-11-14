unit Cozy.NHW.HandleSharingEvidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Logging;

type
  // Passive snapshot correlation, NOT proof of a DuplicateHandle call.
  TSharingHandle = record
    PID: Cardinal;
    Created: UInt64;
    ObjectIdentity: NativeUInt;
    HandleValue: NativeUInt;
    AccessMask: Cardinal;
    IsThread: Boolean;
  end;

  // Owned by the monitor thread. Callers must not mutate inputs concurrently.
  THandleSharingEvidence = class
  private
    FPrevious: TDictionary<string, TSharingHandle>;
    FPending: TDictionary<string, Byte>;
    FLastReport, FLastTick: UInt64;
    FHasSnapshot, FReported: Boolean;
    procedure BreakContinuity;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Handles: TList<TObservedHandle>;
      const Creations: TDictionary<Cardinal, UInt64>; ThreadSnapshotValid: Boolean;
      ProcessBaseline, ThreadBaseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function NHWPotentialSharedHandle(const PriorEntry,
  CurrentEntry: TSharingHandle; PriorStillPresent: Boolean): Boolean;
{$IFDEF NHW_NATIVE5J_TESTS}
function TestSharing5J(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils;

const
  MAX_SHARING_ENTRIES = 2048;
  SHARING_REPORT_COOLDOWN_MS = 30000;
  SHARING_MAX_GAP_MS = 15000;

{$IFDEF NHW_NATIVE5J_TESTS}
type
  TSharingTestMap = class(TDictionary<string, TSharingHandle>)
  private
    FCounted: Boolean;
  public
    constructor Create; reintroduce;
    destructor Destroy; override;
  end;
  TSharingTestByteMap = class(TDictionary<string, Byte>)
  private
    FCounted: Boolean;
  public
    constructor Create; reintroduce;
    destructor Destroy; override;
  end;
var
  SharingFailStage: Integer;
  SharingTestLive: Integer;
constructor TSharingTestMap.Create;
begin inherited Create; FCounted := True; Inc(SharingTestLive); end;
destructor TSharingTestMap.Destroy;
begin if FCounted then Dec(SharingTestLive); inherited Destroy; end;
constructor TSharingTestByteMap.Create;
begin inherited Create; FCounted := True; Inc(SharingTestLive); end;
destructor TSharingTestByteMap.Destroy;
begin if FCounted then Dec(SharingTestLive); inherited Destroy; end;
procedure SharingAllocationPoint(Stage: Integer);
begin
  if SharingFailStage = Stage then
    raise EOutOfMemory.Create('Synthetic temporary-map allocation failure');
end;
{$ENDIF}

function ObjectKey(const H: TSharingHandle): string;
begin
  if H.IsThread then Result := 'T:' else Result := 'P:';
  Result := Result + IntToHex(UInt64(H.ObjectIdentity), 16);
end;

function ActorObjectKey(const H: TSharingHandle): string;
begin
  Result := ObjectKey(H) + ':' + IntToStr(H.PID) + ':' +
    IntToHex(H.Created, 16);
end;

function FullKey(const H: TSharingHandle): string;
begin
  Result := ActorObjectKey(H) + ':' + IntToHex(UInt64(H.HandleValue), 16);
end;

function SensitiveMask(IsThread: Boolean): Cardinal;
begin
  if IsThread then
    Result := THREAD_SET_CONTEXT_RIGHT or THREAD_SUSPEND_RESUME_RIGHT
  else
    Result := ACCESS_DUP_HANDLE or ACCESS_VM_WRITE or
      ACCESS_VM_OPERATION or ACCESS_CREATE_THREAD;
end;

function NHWPotentialSharedHandle(const PriorEntry,
  CurrentEntry: TSharingHandle; PriorStillPresent: Boolean): Boolean;
begin
  Result := PriorStillPresent and (PriorEntry.PID > 4) and
    (CurrentEntry.PID > 4) and
    (PriorEntry.ObjectIdentity <> 0) and
    (PriorEntry.ObjectIdentity = CurrentEntry.ObjectIdentity) and
    (PriorEntry.IsThread = CurrentEntry.IsThread) and
    (PriorEntry.PID <> CurrentEntry.PID) and
    (PriorEntry.Created <> 0) and (CurrentEntry.Created <> 0) and
    ((PriorEntry.AccessMask and CurrentEntry.AccessMask and
      SensitiveMask(CurrentEntry.IsThread)) <> 0);
end;

constructor THandleSharingEvidence.Create;
begin
  inherited Create;
  FPrevious := TDictionary<string, TSharingHandle>.Create;
  FPending := TDictionary<string, Byte>.Create;
  Reset;
end;

destructor THandleSharingEvidence.Destroy;
begin
  FPending.Free;
  FPrevious.Free;
  inherited Destroy;
end;

procedure THandleSharingEvidence.BreakContinuity;
begin
  FPrevious.Clear;
  FPending.Clear;
  FLastTick := 0;
  FHasSnapshot := False;
  // Do not clear the report cooldown on a collection gap.
end;

procedure THandleSharingEvidence.Reset;
begin
  BreakContinuity;
  FLastReport := 0;
  FReported := False;
end;

procedure THandleSharingEvidence.Examine(
  const Handles: TList<TObservedHandle>;
  const Creations: TDictionary<Cardinal, UInt64>; ThreadSnapshotValid: Boolean;
  ProcessBaseline, ThreadBaseline: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Current, PriorByObjectA, PriorByObjectB: TDictionary<string, TSharingHandle>;
  OwnersNow, NextPending: TDictionary<string, Byte>;
  Confirmed: Boolean;

  function BuildCurrentSnapshot: Boolean;
  var
    Obs: TObservedHandle;
    H, Existing: TSharingHandle;
    Key: string;
    Created: UInt64;
  begin
    Result := False;
    for Obs in Handles do
    begin
      if Obs.IsThread and not ThreadSnapshotValid then Continue;
      if (Obs.OwnerPID <= 4) or (Obs.ObjectIdentity = 0) or
         (Obs.HandleValue = 0) then Continue;
      if (Obs.GrantedAccess and SensitiveMask(Obs.IsThread)) = 0 then Continue;
      if not Creations.TryGetValue(Obs.OwnerPID, Created) then Continue;
      if Created = 0 then Continue;
      H := Default(TSharingHandle);
      H.PID := Obs.OwnerPID;
      H.Created := Created;
      H.ObjectIdentity := Obs.ObjectIdentity;
      H.HandleValue := Obs.HandleValue;
      H.AccessMask := Obs.GrantedAccess;
      H.IsThread := Obs.IsThread;
      Key := FullKey(H);
      if Current.TryGetValue(Key, Existing) then
      begin
        if Existing.AccessMask <> H.AccessMask then
        begin BreakContinuity; Exit; end;
        Continue;
      end;
      Current.Add(Key, H);
      OwnersNow.AddOrSetValue(ActorObjectKey(H), 1);
    end;
    Result := True;
  end;

  procedure IndexPreviousOwners;
  var
    Pair: TPair<string, TSharingHandle>;
    H, Prior: TSharingHandle;
    Obj: string;
  begin
    for Pair in FPrevious do
    begin
      H := Pair.Value;
      Obj := ObjectKey(H);
      if not PriorByObjectA.TryGetValue(Obj, Prior) then
        PriorByObjectA.Add(Obj, H)
      else if (Prior.PID <> H.PID) or (Prior.Created <> H.Created) then
        PriorByObjectB.AddOrSetValue(Obj, H);
    end;
  end;

  procedure BuildSharingCandidates(out Confirmed: Boolean);
  var
    Pair: TPair<string, TSharingHandle>;
    H, Prior, Other: TSharingHandle;
    Key, Obj: string;
    Count: Byte;
    OtherPresent: Boolean;
  begin
    Confirmed := False;
    for Pair in Current do
    begin
      H := Pair.Value;
      if (H.IsThread and ThreadBaseline) or
         ((not H.IsThread) and ProcessBaseline) then Continue;
      Key := Pair.Key;
      Obj := ObjectKey(H);
      OtherPresent := False;
      if PriorByObjectA.TryGetValue(Obj, Prior) and
        OwnersNow.ContainsKey(ActorObjectKey(Prior)) and
        NHWPotentialSharedHandle(Prior, H, True) then
        OtherPresent := True
      else if PriorByObjectB.TryGetValue(Obj, Other) and
        OwnersNow.ContainsKey(ActorObjectKey(Other)) and
        NHWPotentialSharedHandle(Other, H, True) then
        OtherPresent := True;
      if not OtherPresent then Continue;
      if FPending.TryGetValue(Key, Count) then
      begin
        if Count < 3 then Inc(Count);
        NextPending.AddOrSetValue(Key, Count);
        if Count = 2 then Confirmed := True;
      end
      else if not FPrevious.ContainsKey(Key) then
        NextPending.AddOrSetValue(Key, 1);
    end;
  end;

  procedure CommitCompletedSnapshot;
  var
    OldPrevious: TDictionary<string, TSharingHandle>;
    OldPending: TDictionary<string, Byte>;
  begin
    OldPrevious := FPrevious;
    FPrevious := Current;
    Current := OldPrevious;
    OldPending := FPending;
    FPending := NextPending;
    NextPending := OldPending;
    FLastTick := Tick;
    FHasSnapshot := True;
  end;

begin
  if (Handles = nil) or (Creations = nil) then
  begin BreakContinuity; Exit; end;
  if Handles.Count > MAX_SHARING_ENTRIES then
  begin BreakContinuity; Exit; end;
  if FHasSnapshot then
  begin
    if Tick < FLastTick then BreakContinuity
    else if Tick - FLastTick > SHARING_MAX_GAP_MS then BreakContinuity
    else if Tick = FLastTick then
    begin
      if ProcessBaseline or ThreadBaseline then BreakContinuity;
      Exit;
    end;
  end;
  // All owning locals are initialized BEFORE the protected creation block.
  Current := nil;
  OwnersNow := nil;
  PriorByObjectA := nil;
  PriorByObjectB := nil;
  NextPending := nil;
  try
    try
{$IFDEF NHW_NATIVE5J_TESTS}
      SharingAllocationPoint(1); Current := TSharingTestMap.Create;
      SharingAllocationPoint(2); OwnersNow := TSharingTestByteMap.Create;
      SharingAllocationPoint(3); PriorByObjectA := TSharingTestMap.Create;
      SharingAllocationPoint(4); PriorByObjectB := TSharingTestMap.Create;
      SharingAllocationPoint(5); NextPending := TSharingTestByteMap.Create;
{$ELSE}
      Current := TDictionary<string, TSharingHandle>.Create;
      OwnersNow := TDictionary<string, Byte>.Create;
      PriorByObjectA := TDictionary<string, TSharingHandle>.Create;
      PriorByObjectB := TDictionary<string, TSharingHandle>.Create;
      NextPending := TDictionary<string, Byte>.Create;
{$ENDIF}
      if not BuildCurrentSnapshot then Exit;
      IndexPreviousOwners;
      BuildSharingCandidates(Confirmed);
{$IFDEF NHW_NATIVE5J_TESTS}
      SharingAllocationPoint(6); // fail before publishing any result
{$ENDIF}
      // Commit by swapping ownership; no allocating copies of a partial map.
      CommitCompletedSnapshot;
      if Confirmed and ((not FReported) or (Tick < FLastReport) or
         (Tick - FLastReport >= SHARING_REPORT_COOLDOWN_MS)) then
      begin
        Include(Detected, dkHandleSharingEvidence);
        FLastReport := Tick;
        FReported := True;
      end;
    except
      BreakContinuity;
      raise; // allocation/runtime failures remain visible to the supervisor
    end;
  finally
    NextPending.Free;
    PriorByObjectB.Free;
    PriorByObjectA.Free;
    OwnersNow.Free;
    Current.Free;
  end;
end;

{$IFDEF NHW_NATIVE5J_TESTS}
{$I Cozy.NHW.Native5J.Sharing.inc}
{$ENDIF}
end.
