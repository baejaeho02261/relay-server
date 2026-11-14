unit Cozy.NHW.UnifiedEvidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Logging;

type
  // Conservative acquisition roots, NOT a claim of statistical independence.
  // ETW's original queue and its SPSC mirror are ONE root. Correlators and
  // risk engines are derived consumers and never manufacture a new root.
  TObservationRoot = (orHandleSnapshot, orThreadSnapshot, orETW,
    orSelfMemory, orModuleFile, orObjectState, orObserver,
    orDerived, orCoverage);
  TObservationRoots = set of TObservationRoot;
  TUnifiedFrame = record
    Sequence, Tick, TargetCreation: UInt64;
    TargetPID: Cardinal;
    Kinds: TDetectionKinds;
    Roots: TObservationRoots;
    RootKinds: array[TObservationRoot] of TDetectionKinds;
    DuplicateKinds: Cardinal;
    Incomplete: Boolean;
  end;

  // Sidecar provenance ledger: it does not erase any legacy detection.
  // Main-thread ownership, fixed capacity, expiring RAM only.
  TUnifiedEvidence = class
  private
    FItems: array[0..255] of TUnifiedFrame;
    FCurrent: TUnifiedFrame;
    FNext, FCount: Integer;
    FSequence: UInt64;
    FOpen: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure BeginFrame(Tick: UInt64; TargetPID: Cardinal;
      TargetCreation: UInt64);
    procedure Add(Root: TObservationRoot; const Kinds: TDetectionKinds);
    procedure MarkIncomplete;
    function PrimaryRootCount: Byte;
    function CurrentComplete: Boolean;
    procedure Commit;
    procedure Prune(Tick: UInt64);
    function Recent(Index: Integer; out Item: TUnifiedFrame): Boolean;
    property Count: Integer read FCount;
  end;

implementation

uses Cozy.NHW.NativeSafety;

constructor TUnifiedEvidence.Create;
begin inherited Create; Reset; end;

destructor TUnifiedEvidence.Destroy;
begin Reset; inherited Destroy; end;

procedure TUnifiedEvidence.Reset;
begin
  FillChar(FItems, SizeOf(FItems), 0);
  FCurrent := Default(TUnifiedFrame);
  FNext := 0; FCount := 0; FSequence := 0; FOpen := False;
end;

procedure TUnifiedEvidence.BeginFrame(Tick: UInt64; TargetPID: Cardinal;
  TargetCreation: UInt64);
begin
  FCurrent := Default(TUnifiedFrame);
  FSequence := NHWSaturatingAdd(FSequence, 1);
  FCurrent.Sequence := FSequence;
  FCurrent.Tick := Tick;
  FCurrent.TargetPID := TargetPID;
  FCurrent.TargetCreation := TargetCreation;
  FCurrent.Incomplete := (TargetPID = 0) or (TargetCreation = 0);
  FOpen := True;
end;

procedure TUnifiedEvidence.Add(Root: TObservationRoot;
  const Kinds: TDetectionKinds);
var Repeated: TDetectionKinds; K: TDetectionKind;
begin
  if not FOpen or (Kinds = []) then Exit;
  Repeated := FCurrent.RootKinds[Root] * Kinds;
  for K := Low(TDetectionKind) to High(TDetectionKind) do
    if (K in Repeated) and (FCurrent.DuplicateKinds < High(Cardinal)) then
      Inc(FCurrent.DuplicateKinds);
  FCurrent.RootKinds[Root] := FCurrent.RootKinds[Root] + Kinds;
  FCurrent.Kinds := FCurrent.Kinds + Kinds;
  if not (Root in [orDerived, orCoverage]) then
    Include(FCurrent.Roots, Root);
end;

procedure TUnifiedEvidence.MarkIncomplete;
begin if FOpen then FCurrent.Incomplete := True; end;

function TUnifiedEvidence.PrimaryRootCount: Byte;
var R: TObservationRoot;
begin
  Result := 0;
  if not FOpen then Exit;
  for R := Low(TObservationRoot) to High(TObservationRoot) do
    if R in FCurrent.Roots then Inc(Result);
end;

function TUnifiedEvidence.CurrentComplete: Boolean;
begin Result := FOpen and not FCurrent.Incomplete; end;

procedure TUnifiedEvidence.Commit;
begin
  if not FOpen then Exit;
  if (FCurrent.Kinds <> []) or FCurrent.Incomplete then
  begin
    FItems[FNext] := FCurrent;
    FNext := (FNext + 1) mod Length(FItems);
    if FCount < Length(FItems) then Inc(FCount);
  end;
  FCurrent := Default(TUnifiedFrame);
  FOpen := False;
end;

procedure TUnifiedEvidence.Prune(Tick: UInt64);
var Oldest: Integer;
begin
  while FCount > 0 do
  begin
    Oldest := (FNext - FCount + Length(FItems)) mod Length(FItems);
    if not NHWExpired(FItems[Oldest].Tick, Tick, 60000) then Break;
    FItems[Oldest] := Default(TUnifiedFrame);
    Dec(FCount);
  end;
end;

function TUnifiedEvidence.Recent(Index: Integer;
  out Item: TUnifiedFrame): Boolean;
var Pos: Integer;
begin
  Item := Default(TUnifiedFrame);
  Result := (Index >= 0) and (Index < FCount);
  if not Result then Exit;
  Pos := (FNext - 1 - Index + Length(FItems)) mod Length(FItems);
  Item := FItems[Pos];
end;

end.
