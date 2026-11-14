unit Cozy.NHW.EvidenceChain;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TEvidenceFlag = (efExternalCapability, efETWGap,
    efThreadOrigin, efMemoryChange, efReplaySynthetic);
  TEvidenceFlags = set of TEvidenceFlag;

  TEvidenceFrame = record
    Sequence: UInt64;
    Tick: UInt64;
    TargetPID: Cardinal;
    // ActorPID remains zero unless a source explicitly supplies verified
    // actor identity. Snapshot correlations never assign blame.
    ActorPID: Cardinal;
    Detected: TDetectionKinds;
    Flags: TEvidenceFlags;
  end;

  // v49: bounded in-memory ring. No logging, network, console or files.
  TEvidenceChain = class
  private
    FData: array[0..255] of TEvidenceFrame;
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
    function Recent(IndexFromNewest: Integer; out Frame: TEvidenceFrame): Boolean;
    property Count: Integer read FCount;
  end;

implementation

uses Cozy.NHW.NativeSafety;

constructor TEvidenceChain.Create;
begin
  inherited Create;
  Reset;
end;

destructor TEvidenceChain.Destroy;
begin Reset; inherited Destroy; end;

procedure TEvidenceChain.Prune(Tick: UInt64);
var Oldest: Integer;
begin
  while FCount > 0 do
  begin
    Oldest := (FNext - FCount + Length(FData)) mod Length(FData);
    if not NHWExpired(FData[Oldest].Tick, Tick, 60000) then Break;
    FData[Oldest] := Default(TEvidenceFrame);
    Dec(FCount);
  end;
end;

procedure TEvidenceChain.Reset;
begin
  FillChar(FData, SizeOf(FData), 0);
  FNext := 0;
  FCount := 0;
  FSequence := 0;
end;

procedure TEvidenceChain.RecordFrame(Tick: UInt64; TargetPID: Cardinal;
  const Detected: TDetectionKinds; Flags: TEvidenceFlags);
begin
  if (Detected = []) and (Flags = []) then Exit;
  Inc(FSequence);
  FData[FNext] := Default(TEvidenceFrame);
  FData[FNext].Sequence := FSequence;
  FData[FNext].Tick := Tick;
  FData[FNext].TargetPID := TargetPID;
  FData[FNext].ActorPID := 0;
  FData[FNext].Detected := Detected;
  FData[FNext].Flags := Flags;
  FNext := (FNext + 1) mod Length(FData);
  if FCount < Length(FData) then Inc(FCount);
end;

function TEvidenceChain.Recent(IndexFromNewest: Integer;
  out Frame: TEvidenceFrame): Boolean;
var
  Pos: Integer;
begin
  Frame := Default(TEvidenceFrame);
  Result := (IndexFromNewest >= 0) and (IndexFromNewest < FCount);
  if not Result then Exit;
  Pos := (FNext - 1 - IndexFromNewest + Length(FData)) mod Length(FData);
  Frame := FData[Pos];
end;

end.
