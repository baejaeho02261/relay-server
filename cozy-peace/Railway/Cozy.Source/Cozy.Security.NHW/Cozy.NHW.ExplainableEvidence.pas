unit Cozy.NHW.ExplainableEvidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging, Cozy.NHW.EvidenceChain;

type
  TExplanationFlag = (xfExternalCapability, xfImageIntegrity,
    xfThreadOrigin, xfUnwindMetadata, xfImportedPointer,
    xfTLSCallback, xfExecutionPermissions, xfMappedFileIdentity,
    xfSamplingGap, xfUnattributed);
  TExplanationFlags = set of TExplanationFlag;

  TExplanationFrame = record
    Sequence: UInt64;
    Tick: UInt64;
    TargetPID: Cardinal;
    ActorPID: Cardinal; // 0: no reliable actor attribution
    EventKinds: TDetectionKinds;
    Reasons: TExplanationFlags;
  end;

  // v59: explanation metadata in a bounded, resettable RAM ring.
  // No disk, network or additional console output is generated.
  TExplainableEvidence = class
  private
    FItems: array[0..255] of TExplanationFrame;
    FNext: Integer;
    FCount: Integer;
    FSequence: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Prune(Tick: UInt64);
    procedure Reset;
    procedure RecordFrame(Tick: UInt64; TargetPID: Cardinal;
      const Detected: TDetectionKinds; Flags: TEvidenceFlags);
    function Recent(IndexFromNewest: Integer;
      out Frame: TExplanationFrame): Boolean;
    property Count: Integer read FCount;
  end;

function ExplainReasons(const Detected: TDetectionKinds;
  Flags: TEvidenceFlags): TExplanationFlags;

implementation

uses Cozy.NHW.NativeSafety;

function ExplainReasons(const Detected: TDetectionKinds;
  Flags: TEvidenceFlags): TExplanationFlags;
begin
  Result := [xfUnattributed];
  if efExternalCapability in Flags then Include(Result, xfExternalCapability);
  if efMemoryChange in Flags then Include(Result, xfImageIntegrity);
  if efThreadOrigin in Flags then Include(Result, xfThreadOrigin);
  if efETWGap in Flags then Include(Result, xfSamplingGap);
  if (Detected * [dkUnwindStructural, dkUnwind, dkFunctionTable]) <> [] then
    Include(Result, xfUnwindMetadata);
  if dkImportRedirect in Detected then Include(Result, xfImportedPointer);
  if dkTLSCallbackIntegrity in Detected then Include(Result, xfTLSCallback);
  if dkExecutableLifecycle in Detected then Include(Result, xfExecutionPermissions);
  if dkSectionBacking in Detected then Include(Result, xfMappedFileIdentity);
  if dkThreadStackOrigin in Detected then Include(Result, xfThreadOrigin);
  if dkCoverageGap in Detected then Include(Result, xfSamplingGap);
end;

constructor TExplainableEvidence.Create;
begin inherited Create; Reset; end;

destructor TExplainableEvidence.Destroy;
begin Reset; inherited Destroy; end;

procedure TExplainableEvidence.Prune(Tick: UInt64);
var Oldest: Integer;
begin
  while FCount > 0 do
  begin
    Oldest := (FNext - FCount + Length(FItems)) mod Length(FItems);
    if not NHWExpired(FItems[Oldest].Tick, Tick, 60000) then Break;
    FItems[Oldest] := Default(TExplanationFrame);
    Dec(FCount);
  end;
end;

procedure TExplainableEvidence.Reset;
begin
  FillChar(FItems, SizeOf(FItems), 0);
  FNext := 0;
  FCount := 0;
  FSequence := 0;
end;

procedure TExplainableEvidence.RecordFrame(Tick: UInt64;
  TargetPID: Cardinal; const Detected: TDetectionKinds;
  Flags: TEvidenceFlags);
begin
  if (Detected = []) and (Flags = []) then Exit;
  Inc(FSequence);
  FItems[FNext] := Default(TExplanationFrame);
  FItems[FNext].Sequence := FSequence;
  FItems[FNext].Tick := Tick;
  FItems[FNext].TargetPID := TargetPID;
  FItems[FNext].ActorPID := 0;
  FItems[FNext].EventKinds := Detected;
  FItems[FNext].Reasons := ExplainReasons(Detected, Flags);
  FNext := (FNext + 1) mod Length(FItems);
  if FCount < Length(FItems) then Inc(FCount);
end;

function TExplainableEvidence.Recent(IndexFromNewest: Integer;
  out Frame: TExplanationFrame): Boolean;
var Pos: Integer;
begin
  Frame := Default(TExplanationFrame);
  Result := (IndexFromNewest >= 0) and (IndexFromNewest < FCount);
  if not Result then Exit;
  Pos := (FNext - 1 - IndexFromNewest + Length(FItems)) mod Length(FItems);
  Frame := FItems[Pos];
end;

end.
