unit Cozy.NHW.TemporalHandleGraph;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.Generics.Collections, Cozy.NHW.Types, Cozy.NHW.Logging;

type
  THandleActorState = record
    FirstSeen: UInt64;
    LastSeen: UInt64;
    QueryOnlyTick: UInt64;
    HighAccessTick: UInt64;
    LastReport: UInt64;
    HighObservations: Byte;
    LastMask: Cardinal;
    LastSnapshot: UInt64;
  end;

  // v45: actor identity = PID + process creation timestamp + object type.
  // Tracks ACCESS RIGHTS, not API calls, memory writes or an attacker.
  TTemporalHandleGraph = class
  private
    FActors: TDictionary<string, THandleActorState>;
    FLastMaintenance: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Observe(const Holder: TTargetHolder; Baseline: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
    procedure Expire(Tick: UInt64);
  end;

function HandleSequenceRisk(QueryTick, HighTick: UInt64;
  HighObservations: Byte; Tick: UInt64): Boolean;
{$IFDEF NHW_NATIVE5H_TESTS}
function TestTemporalHandleHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils;

const
  HANDLE_SEQUENCE_WINDOW_MS = 15000;
  HANDLE_GRAPH_RETENTION_MS = 90000;
  HANDLE_REPORT_COOLDOWN_MS = 30000;
  MAX_GRAPH_ACTORS = 2048;

function HandleSequenceRisk(QueryTick, HighTick: UInt64;
  HighObservations: Byte; Tick: UInt64): Boolean;
begin
  Result := (QueryTick <> 0) and (HighTick > QueryTick) and
    (HighObservations >= 2) and (Tick >= HighTick) and
    (Tick - QueryTick <= HANDLE_SEQUENCE_WINDOW_MS);
end;

constructor TTemporalHandleGraph.Create;
begin
  inherited Create;
  FActors := TDictionary<string, THandleActorState>.Create;
  Reset;
end;

destructor TTemporalHandleGraph.Destroy;
begin
  FActors.Free;
  inherited Destroy;
end;

procedure TTemporalHandleGraph.Reset;
begin
  FActors.Clear;
  FLastMaintenance := 0;
end;

procedure ClearHandleSequence(var S: THandleActorState);
begin
  S.QueryOnlyTick := 0;
  S.HighAccessTick := 0;
  S.HighObservations := 0;
  S.LastSnapshot := 0;
end;

procedure TTemporalHandleGraph.Observe(const Holder: TTargetHolder;
  Baseline: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var
  Key: string;
  S: THandleActorState;
  HasHigh, HasQuery: Boolean;
  procedure ClassifyAccess(out HasHigh, HasQuery: Boolean);
  var
    HighMask, QueryMask: Cardinal;
  begin
    if Holder.IsThread then
    begin
      HighMask := THREAD_SET_CONTEXT_RIGHT or THREAD_SUSPEND_RESUME_RIGHT;
      QueryMask := THREAD_QUERY_INFORMATION_RIGHT or THREAD_QUERY_LIMITED_INFORMATION_RIGHT;
    end
    else
    begin
      HighMask := ACCESS_VM_WRITE or ACCESS_VM_OPERATION or ACCESS_CREATE_THREAD;
      QueryMask := ACCESS_VM_READ or ACCESS_QUERY_INFORMATION or ACCESS_QUERY_LIMITED;
    end;
    HasHigh := (Holder.RightsUnion and HighMask) <> 0;
    HasQuery := (Holder.RightsUnion and QueryMask) <> 0;
  end;

  procedure AdvanceAccessSequence;
  begin
    if Tick < S.LastSeen then
    begin
      ClearHandleSequence(S);
      S.LastReport := 0;
      S.FirstSeen := Tick;
    end;
    if Baseline then
      ClearHandleSequence(S)
    else if HasQuery and not HasHigh then
    begin
      // A query-only return begins a NEW sequence, never reusing old high counts.
      ClearHandleSequence(S);
      S.QueryOnlyTick := Tick;
      S.LastSnapshot := Tick;
    end
    else if HasHigh then
    begin
      if (S.QueryOnlyTick = 0) or (Tick <= S.QueryOnlyTick) then
      begin
        S.HighAccessTick := 0;
        S.HighObservations := 0;
        S.LastSnapshot := Tick;
      end
      else if Tick - S.QueryOnlyTick > HANDLE_SEQUENCE_WINDOW_MS then
        ClearHandleSequence(S)
      else
      begin
        if Tick > S.LastSnapshot then
        begin
          if S.HighObservations < 2 then Inc(S.HighObservations);
          S.LastSnapshot := Tick;
        end;
        S.HighAccessTick := Tick;
      end;
    end
    else
      ClearHandleSequence(S);
  end;

  procedure ReportConfirmedSequence;
  begin
    if not Baseline and HasHigh and
       HandleSequenceRisk(S.QueryOnlyTick, S.HighAccessTick,
         S.HighObservations, Tick) and
       ((S.LastReport = 0) or ((Tick >= S.LastReport) and
         (Tick - S.LastReport >= HANDLE_REPORT_COOLDOWN_MS))) then
    begin
      Include(Detected, dkTemporalHandleGraph);
      S.LastReport := Tick;
    end;
  end;

begin
  if (Holder.PID <= 4) or (Holder.CreateTime = 0) then Exit;
  ClassifyAccess(HasHigh, HasQuery);
  Key := IntToStr(Holder.PID) + ':' + IntToHex(Holder.CreateTime, 16);
  if Holder.IsThread then Key := Key + ':T' else Key := Key + ':P';
  if not FActors.TryGetValue(Key, S) then
  begin
    if Baseline then Exit;
    if FActors.Count >= MAX_GRAPH_ACTORS then Exit;
    S := Default(THandleActorState);
    S.FirstSeen := Tick;
  end;
  AdvanceAccessSequence;
  ReportConfirmedSequence;
  S.LastSeen := Tick;
  S.LastMask := Holder.RightsUnion;
  FActors.AddOrSetValue(Key, S);
end;

procedure TTemporalHandleGraph.Expire(Tick: UInt64);
var
  Item: TPair<string, THandleActorState>;
  DeleteKeys: TList<string>;
  Key: string;
begin
  if (FLastMaintenance <> 0) and (Tick >= FLastMaintenance) and
     (Tick - FLastMaintenance < 5000) then Exit;
  FLastMaintenance := Tick;
  DeleteKeys := TList<string>.Create;
  try
    for Item in FActors do
      if (Tick < Item.Value.LastSeen) or
         (Tick - Item.Value.LastSeen > HANDLE_GRAPH_RETENTION_MS) then
        DeleteKeys.Add(Item.Key);
    for Key in DeleteKeys do FActors.Remove(Key);
  finally
    DeleteKeys.Free;
  end;
end;

{$IFDEF NHW_NATIVE5H_TESTS}
{$I Cozy.NHW.Native5H.TemporalHandle.inc}
{$ENDIF}
end.
