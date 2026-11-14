unit Cozy.NHW.DetectionJournal;

{$B-}{$R+}{$Q+}

interface

uses System.SyncObjs, Cozy.NHW.Logging, Cozy.NHW.Context;

const
  NHWDetectionBatchCapacity = 12;
  NHWDetectionContextLanes = 4;

type
  TNHWDetectionOrigin = (ndoEngine, ndoKernelTrust, ndoHandleCoverage, ndoGuardCoverage);
  TNHWDetectionRecord = record
    Kind: TDetectionKind;
    Origin: TNHWDetectionOrigin;
    FirstTick, LastTick, AttestationSequence, Revision: UInt64;
    Count: Word;
    Families, Confidence: Byte;
    Correlated, ObservedOnly: Boolean;
    ContextLane: Byte;
    Context: TCozyDetectionContext;
  end;
  TNHWDetectionBatch = record
    Sequence: UInt64;
    Count: Integer;
    Records: array[0..NHWDetectionBatchCapacity - 1] of TNHWDetectionRecord;
  end;

  { Fixed per-kind aggregation, rather than an unbounded detection history.
    Each response path owns a separate instance/lock/revision/acknowledgement.
    No raw PID, path, machine name, user identity or key enters these records. }
  TNHWDetectionJournal = class
  private
    FLock: TCriticalSection;
    FItems: array[TNHWDetectionOrigin, TDetectionKind, 0..NHWDetectionContextLanes - 1] of TNHWDetectionRecord;
    FDeferred: array[TNHWDetectionOrigin, TDetectionKind, 0..NHWDetectionContextLanes - 1] of TNHWDetectionRecord;
    FAcknowledged: array[TNHWDetectionOrigin, TDetectionKind, 0..NHWDetectionContextLanes - 1] of UInt64;
    FSequence: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Append(const Kinds: TDetectionKinds; Origin: TNHWDetectionOrigin;
      Tick, AttestationSequence: UInt64; Families, Confidence: Byte;
      Correlated: Boolean);
    procedure AppendContext(const Kinds: TDetectionKinds; Origin: TNHWDetectionOrigin;
      Tick, AttestationSequence: UInt64; Families, Confidence: Byte;
      Correlated: Boolean; const Context: TCozyDetectionContext;
      ObservedOnly: Boolean = False);
    function Read(out Batch: TNHWDetectionBatch): Boolean;
    procedure Acknowledge(const Batch: TNHWDetectionBatch);
    function Pending: Boolean;
  end;

function NHWDetectionName(Kind: TDetectionKind): string;
function NHWDetectionSource(Origin: TNHWDetectionOrigin): string;

implementation

uses System.SysUtils, System.TypInfo;

function NHWDetectionName(Kind: TDetectionKind): string;
begin Result := GetEnumName(TypeInfo(TDetectionKind), Ord(Kind)); end;

function NHWDetectionSource(Origin: TNHWDetectionOrigin): string;
begin
  case Origin of
    ndoEngine: Result := 'Cozy.NHW.Engine';
    ndoKernelTrust: Result := 'Cozy.NHW.KernelTrust';
    ndoHandleCoverage: Result := 'Cozy.NHW.Handles';
    ndoGuardCoverage: Result := 'Cozy.NHW.Guard';
  else raise EArgumentOutOfRangeException.Create('NHW_DETECTION_ORIGIN_INVALID');
  end;
end;

constructor TNHWDetectionJournal.Create;
begin inherited Create; FLock := TCriticalSection.Create; end;

destructor TNHWDetectionJournal.Destroy;
begin
  { The owning authority joins all readers before the guard is released. }
  FillChar(FItems, SizeOf(FItems), 0);
  FillChar(FDeferred, SizeOf(FDeferred), 0);
  FillChar(FAcknowledged, SizeOf(FAcknowledged), 0);
  FSequence := 0;
  FLock.Free;
  inherited Destroy;
end;

procedure TNHWDetectionJournal.Append(const Kinds: TDetectionKinds;
  Origin: TNHWDetectionOrigin; Tick, AttestationSequence: UInt64;
  Families, Confidence: Byte; Correlated: Boolean);
var Context: TCozyDetectionContext; Kind: TDetectionKind;
begin
  for Kind := Low(TDetectionKind) to High(TDetectionKind) do
    if Kind in Kinds then
    begin
      Context := NHWReadDetectionContext(Kind, nil);
      AppendContext([Kind], Origin, Tick, AttestationSequence, Families, Confidence,
        Correlated, Context);
    end;
end;

procedure TNHWDetectionJournal.AppendContext(const Kinds: TDetectionKinds;
  Origin: TNHWDetectionOrigin; Tick, AttestationSequence: UInt64;
  Families, Confidence: Byte; Correlated: Boolean;
  const Context: TCozyDetectionContext; ObservedOnly: Boolean);
var Kind: TDetectionKind; Item, Deferred: TNHWDetectionRecord; Lane, Candidate: Integer;
  ContextValue: TCozyDetectionContext;
begin
  if (Kinds = []) or (Tick = 0) then Exit;
  if Confidence > 100 then Confidence := 100;
  FLock.Acquire;
  try
    for Kind := Low(TDetectionKind) to High(TDetectionKind) do
      if Kind in Kinds then
      begin
        Lane := -1;
        for Candidate := 0 to NHWDetectionContextLanes - 1 do
          if (FItems[Origin,Kind,Candidate].Count <> 0) and
            NHWSameObservationContext(FItems[Origin,Kind,Candidate].Context,Context) then
          begin Lane := Candidate; Break; end;
        if Lane < 0 then
          for Candidate := 0 to NHWDetectionContextLanes - 2 do
            if (FItems[Origin,Kind,Candidate].Count = 0) or
              (FItems[Origin,Kind,Candidate].Revision <= FAcknowledged[Origin,Kind,Candidate]) then
            begin
              Lane := Candidate;
              FItems[Origin,Kind,Lane] := Default(TNHWDetectionRecord);
              FDeferred[Origin,Kind,Lane] := Default(TNHWDetectionRecord);
              Break;
            end;
        ContextValue := Context;
        if Lane < 0 then
        begin
          { The bounded overflow lane cannot erase an unacknowledged actor.
            It conservatively preserves rights/deltas and marks attribution
            mixed. Such a record is never EXPECTED_FIRST_PARTY. }
          Lane := NHWDetectionContextLanes - 1;
          if (FItems[Origin,Kind,Lane].Count <> 0) and
            (Tick=FItems[Origin,Kind,Lane].LastTick) then
            ContextValue := NHWMergeObservationContext(FItems[Origin,Kind,Lane].Context,Context);
          ContextValue.ContextMixed := True;
          ContextValue.ActorClass := 'UNKNOWN'; ContextValue.ActorRole := '?';
          ContextValue.ActorIdentity := ''; ContextValue.PeerID := '';
          ContextValue.GrantID := ''; ContextValue.Baseline := False;
        end;
        Item := FItems[Origin,Kind,Lane];
        if Tick < Item.LastTick then Continue;
        { A lower-risk later sample cannot refresh the timestamp of a pending
          older attack. Keep that exact observation until it is ACKed. }
        if (Tick > Item.LastTick) and
          (Item.Revision > FAcknowledged[Origin,Kind,Lane]) and
          ((Item.Correlated and not Correlated) or
           ((not Item.ObservedOnly) and ObservedOnly) or
           (NHWContextRisk(Item.Context) > NHWContextRisk(Context))) then
        begin
          Deferred:=FDeferred[Origin,Kind,Lane];
          if (Tick<Deferred.LastTick) or
            ((Tick=Deferred.LastTick) and (Confidence<=Deferred.Confidence) and
             (not Correlated or Deferred.Correlated) and
             ((Families or Deferred.Families)=Deferred.Families) and
             ((ContextValue.AccessMask or Deferred.Context.AccessMask)=Deferred.Context.AccessMask) and
             ((ContextValue.TokenDelta or Deferred.Context.TokenDelta)=Deferred.Context.TokenDelta)) then Continue;
          if FSequence=High(UInt64) then Exit;
          Deferred:=Item;
          if FDeferred[Origin,Kind,Lane].Count>Deferred.Count then
            Deferred.Count:=FDeferred[Origin,Kind,Lane].Count;
          if Deferred.Count<High(Word) then Inc(Deferred.Count);
          Inc(FSequence); Deferred.Revision:=FSequence;
          Deferred.LastTick:=Tick; Deferred.Context:=ContextValue;
          Deferred.Families:=Families; Deferred.Confidence:=Confidence;
          Deferred.Correlated:=Correlated; Deferred.ObservedOnly:=ObservedOnly;
          Deferred.AttestationSequence:=AttestationSequence;
          FDeferred[Origin,Kind,Lane]:=Deferred;
          Continue;
        end;
        if FDeferred[Origin,Kind,Lane].Count>Item.Count then
          Item.Count:=FDeferred[Origin,Kind,Lane].Count;
        FDeferred[Origin,Kind,Lane]:=Default(TNHWDetectionRecord);
        if (Tick = Item.LastTick) and ((Item.Families or Families) = Item.Families) and
          (Confidence <= Item.Confidence) and (not Correlated or Item.Correlated) and
          (ObservedOnly or not Item.ObservedOnly) and
          ((Item.Context.AccessMask or ContextValue.AccessMask) = Item.Context.AccessMask) and
          ((Item.Context.TokenDelta or ContextValue.TokenDelta) = Item.Context.TokenDelta) then Continue;
        if FSequence = High(UInt64) then Exit;
        Inc(FSequence);
        if Item.Count = 0 then
        begin
          Item.Kind := Kind; Item.Origin := Origin; Item.FirstTick := Tick;
          Item.ContextLane := Lane; Item.Context := ContextValue;
          Item.ObservedOnly := ObservedOnly;
        end;
        if Tick > Item.LastTick then
        begin
          if Item.Count < High(Word) then Inc(Item.Count);
          { Do not overwrite a pending strong observation with a later benign
            observation. Once ACKed, metadata can describe the new sample. }
          Item.Families := 0; Item.Confidence := 0; Item.Correlated := False;
          Item.Context := ContextValue;
          Item.ObservedOnly := ObservedOnly;
        end
        else
          Item.ObservedOnly := Item.ObservedOnly and ObservedOnly;
        Item.LastTick := Tick; Item.Revision := FSequence;
        Item.AttestationSequence := AttestationSequence;
        Item.Families := Item.Families or Families;
        if Confidence > Item.Confidence then Item.Confidence := Confidence;
        Item.Correlated := Item.Correlated or Correlated;
        Item.Context := NHWMergeObservationContext(Item.Context,ContextValue);
        FItems[Origin,Kind,Lane] := Item;
      end;
  finally FLock.Release; end;
end;

function DeliveryPriority(const Item: TNHWDetectionRecord): Integer;
begin
  if Item.Correlated then Exit(4);
  if NHWContextRisk(Item.Context)>=3 then Exit(3);
  if Item.Kind in [dkWriteIntegrity,dkPECodeIntegrity,dkImageCOWIntegrity,
    dkImportRedirect,dkTLSCallbackIntegrity,dkTLSPointer,dkFLSCallback,
    dkHeapIntegrity,dkExceptionCallback,dkEvidenceIntegrity,dkControlFlow,
    dkFileAttestation,dkUnwindStructural,dkIAT,dkFunctionPointer,dkCallback,
    dkFunctionTable,dkExceptionRange,dkUnwind,dkPEHeader,dkSectionMapping,
    dkRelocation,dkTLSDirectory,dkLoadConfig,dkDirectoryBounds,dkExportTable,
    dkExportForwarder,dkAPISet,dkExportTarget,dkResolution,dkDelayImport,
    dkETWImageFusion,dkInjectionEvidence,dkSectionBacking,dkThreadStackOrigin,
    dkLoaderCrossView,dkSnapshotETW,dkObserverMismatch,dkRiskConfidence,
    dkCausalSequence,dkCodeProvenance,dkSectionCorrelation,dkIndirectTarget,
    dkThreadTimeline,dkIncidentReconstruction,dkAPCStyleEvidence,
    dkExecutableLifecycle,dkVulnerableDriver,dkKernelMappingEvidence,
    dkDriverSignerAttestation] then Exit(2);
  Result:=0;
end;

function BeforeForDelivery(const Left, Right: TNHWDetectionRecord): Boolean;
var LeftPriority, RightPriority: Integer;
begin
  { Bound shutdown delivery latency for concrete capability/mutation causes.
    Priority never creates confirmation, changes evidence or grants authority. }
  LeftPriority:=DeliveryPriority(Left); RightPriority:=DeliveryPriority(Right);
  if LeftPriority<>RightPriority then Exit(LeftPriority>RightPriority);
  Result := Left.Revision < Right.Revision;
end;

function TNHWDetectionJournal.Read(out Batch: TNHWDetectionBatch): Boolean;
var Origin: TNHWDetectionOrigin; Kind: TDetectionKind;
  Candidate: TNHWDetectionRecord; Position, Lane: Integer;
begin
  Batch := Default(TNHWDetectionBatch);
  FLock.Acquire;
  try
    Batch.Sequence := FSequence;
    { Oldest unacknowledged revision first: frequent events cannot starve
      a rare event or one of the remaining 204 detection meanings. }
    for Origin := Low(TNHWDetectionOrigin) to High(TNHWDetectionOrigin) do
      for Kind := Low(TDetectionKind) to High(TDetectionKind) do
      for Lane := 0 to NHWDetectionContextLanes - 1 do
      begin
        Candidate := FItems[Origin, Kind, Lane];
        if (Candidate.Count = 0) or
          (Candidate.Revision <= FAcknowledged[Origin, Kind, Lane]) then Continue;
        Position := Batch.Count;
        if Position > NHWDetectionBatchCapacity - 1 then
          Position := NHWDetectionBatchCapacity - 1;
        if (Batch.Count = NHWDetectionBatchCapacity) and
          (not BeforeForDelivery(Candidate, Batch.Records[Position])) then Continue;
        while (Position > 0) and
          BeforeForDelivery(Candidate, Batch.Records[Position - 1]) do
        begin
          Batch.Records[Position] := Batch.Records[Position - 1];
          Dec(Position);
        end;
        Batch.Records[Position] := Candidate;
        if Batch.Count < NHWDetectionBatchCapacity then Inc(Batch.Count);
      end;
  finally FLock.Release; end;
  Result := Batch.Count > 0;
end;

procedure TNHWDetectionJournal.Acknowledge(const Batch: TNHWDetectionBatch);
var I: Integer; Item: TNHWDetectionRecord;
begin
  if (Batch.Count < 0) or (Batch.Count > NHWDetectionBatchCapacity) then Exit;
  FLock.Acquire;
  try
    for I := 0 to Batch.Count - 1 do
    begin
      Item := Batch.Records[I];
      if Item.ContextLane >= NHWDetectionContextLanes then Continue;
      if (Item.Revision <= FItems[Item.Origin, Item.Kind, Item.ContextLane].Revision) and
        (Item.Revision > FAcknowledged[Item.Origin, Item.Kind, Item.ContextLane]) then
      begin
        FAcknowledged[Item.Origin, Item.Kind, Item.ContextLane] := Item.Revision;
        if (Item.Revision=FItems[Item.Origin,Item.Kind,Item.ContextLane].Revision) and
          (FDeferred[Item.Origin,Item.Kind,Item.ContextLane].Revision>Item.Revision) then
        begin
          FItems[Item.Origin,Item.Kind,Item.ContextLane]:=
            FDeferred[Item.Origin,Item.Kind,Item.ContextLane];
          FDeferred[Item.Origin,Item.Kind,Item.ContextLane]:=Default(TNHWDetectionRecord);
        end;
      end;
    end;
  finally FLock.Release; end;
end;

function TNHWDetectionJournal.Pending: Boolean;
var Batch: TNHWDetectionBatch;
begin
  Result := Read(Batch);
  FillChar(Batch, SizeOf(Batch), 0);
end;

end.
