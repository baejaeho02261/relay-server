unit Cozy.NHW.MemoryEvidenceCapsule;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TMemoryEvidenceFrame = record
    Tick: UInt64;
    ActorAlias: UInt64;
    Confidence: Byte;
    VisibilityGap: Boolean;
    Kinds: TDetectionKinds;
  end;

  // v95: bounded RAM-only evidence, no paths, user names or raw actor PID.
  // Normal Windows swap/crash reporting is outside this module's control.
  TMemoryEvidenceCapsule = class
  private
    FEntries: array[0..127] of TMemoryEvidenceFrame;
    FNext, FCount: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Prune(Tick: UInt64);
    procedure Append(Tick, ActorAlias: UInt64; Confidence: Byte;
      VisibilityGap: Boolean; const Kinds: TDetectionKinds);
    function Recent(Index: Integer; out Item: TMemoryEvidenceFrame): Boolean;
    property Count: Integer read FCount;
  end;

implementation

uses Cozy.NHW.NativeSafety;

constructor TMemoryEvidenceCapsule.Create;
begin inherited Create; Reset; end;

destructor TMemoryEvidenceCapsule.Destroy;
begin Reset; inherited Destroy; end;

procedure TMemoryEvidenceCapsule.Reset;
begin
  FillChar(FEntries, SizeOf(FEntries), 0);
  FNext := 0;
  FCount := 0;
end;

procedure TMemoryEvidenceCapsule.Prune(Tick: UInt64);
var Oldest, Newest: Integer;
begin
  if FCount > 0 then
  begin
    Newest := (FNext - 1 + Length(FEntries)) mod Length(FEntries);
    if Tick < FEntries[Newest].Tick then
    begin Reset; Exit; end;
  end;
  while FCount > 0 do
  begin
    Oldest := (FNext - FCount + Length(FEntries)) mod Length(FEntries);
    if not NHWExpired(FEntries[Oldest].Tick, Tick, 60000) then Break;
    FEntries[Oldest] := Default(TMemoryEvidenceFrame);
    Dec(FCount);
  end;
end;

procedure TMemoryEvidenceCapsule.Append(Tick, ActorAlias: UInt64;
  Confidence: Byte; VisibilityGap: Boolean;
  const Kinds: TDetectionKinds);
begin
  Prune(Tick);
  if (Kinds = []) and not VisibilityGap then Exit;
  FEntries[FNext].Tick := Tick;
  FEntries[FNext].ActorAlias := ActorAlias;
  FEntries[FNext].Confidence := Confidence;
  FEntries[FNext].VisibilityGap := VisibilityGap;
  FEntries[FNext].Kinds := Kinds;
  FNext := (FNext + 1) mod Length(FEntries);
  if FCount < Length(FEntries) then Inc(FCount);
end;

function TMemoryEvidenceCapsule.Recent(Index: Integer;
  out Item: TMemoryEvidenceFrame): Boolean;
var I, Pos, Found: Integer;
begin
  Item := Default(TMemoryEvidenceFrame);
  Result := False;
  if (Index < 0) or (Index >= FCount) then Exit;
  Found := 0;
  for I := 0 to FCount - 1 do
  begin
    Pos := (FNext - 1 - I + Length(FEntries)) mod Length(FEntries);
    if FEntries[Pos].Tick = 0 then Continue;
    if Found = Index then
    begin
      Item := FEntries[Pos];
      Exit(True);
    end;
    Inc(Found);
  end;
end;

end.
