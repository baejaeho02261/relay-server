unit Cozy.NHW.PrecisionTimeline;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TPrecisionEvent = record
    Sequence: UInt64;
    AliasId: UInt64;
    ArrivalQpc: Int64;
    DrainedQpc: Int64;
    DispatchLatencyUS: UInt64;
    ObservedTick: UInt64;
    EventKind: Byte;
  end;

  // v93: timestamps describe observation/callback arrival, NOT
  // microsecond visibility into kernel-side OpenProcess operations.
  TPrecisionTimeline = class
  private
    FEntries: array[0..127] of TPrecisionEvent;
    FNext, FCount: Integer;
    FSequence: UInt64;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(AliasId: UInt64; EventKind: Byte;
      ArrivalQpc, DrainedQpc: Int64; ObservedTick: UInt64);
    function Recent(Index: Integer; out Item: TPrecisionEvent): Boolean;
    property Count: Integer read FCount;
  end;

implementation

uses Cozy.NHW.HighResolutionClock;

constructor TPrecisionTimeline.Create;
begin
  inherited Create;
  Reset;
end;

procedure TPrecisionTimeline.Reset;
begin
  FillChar(FEntries, SizeOf(FEntries), 0);
  FNext := 0;
  FCount := 0;
  FSequence := 0;
end;

procedure TPrecisionTimeline.Observe(AliasId: UInt64;
  EventKind: Byte; ArrivalQpc, DrainedQpc: Int64;
  ObservedTick: UInt64);
var ElapsedUS: UInt64;
begin
  if (ArrivalQpc <= 0) or
     not NHWTryQpcElapsedUS(ArrivalQpc, DrainedQpc, ElapsedUS) then Exit;
  if FSequence = High(UInt64) then Reset;
  Inc(FSequence);
  FEntries[FNext] := Default(TPrecisionEvent);
  FEntries[FNext].Sequence := FSequence;
  FEntries[FNext].AliasId := AliasId;
  FEntries[FNext].ArrivalQpc := ArrivalQpc;
  FEntries[FNext].DrainedQpc := DrainedQpc;
  FEntries[FNext].DispatchLatencyUS := ElapsedUS;
  FEntries[FNext].ObservedTick := ObservedTick;
  FEntries[FNext].EventKind := EventKind;
  FNext := (FNext + 1) mod Length(FEntries);
  if FCount < Length(FEntries) then Inc(FCount);
end;

function TPrecisionTimeline.Recent(Index: Integer;
  out Item: TPrecisionEvent): Boolean;
var Pos: Integer;
begin
  Item := Default(TPrecisionEvent);
  Result := (Index >= 0) and (Index < FCount);
  if not Result then Exit;
  Pos := (FNext - Index - 1 + Length(FEntries)) mod Length(FEntries);
  Item := FEntries[Pos];
end;

end.
