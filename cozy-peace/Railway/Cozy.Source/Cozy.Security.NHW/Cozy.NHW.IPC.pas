unit Cozy.NHW.IPC;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types,
  Cozy.NHW.Logging;

type
  TIPCTrack = record
    Rights: Cardinal;
    Active: Boolean;
    Misses: Integer;
    LastTick: UInt64;
  end;

  TIPCRecent = record
    Kinds: TIPCObjectKinds;
    LastTick: UInt64;
    Emitted: Boolean;
  end;

  TIPCMonitor = class
  private
    FTracks: TDictionary<string, TIPCTrack>;
    FRecent: TDictionary<Cardinal, TIPCRecent>;
    FBaselineRemaining: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Observed: TList<TIPCObservation>;
      SnapshotValid: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestIPC10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.IPC.Hooks.inc}
{$ENDIF}

const
  IPC_CORRELATION_WINDOW_MS = 3000;
  IPC_TRACK_RETENTION_MS = 15 * 60 * 1000;
  IPC_MISS_THRESHOLD = 2;

function TrackKey(const O: TIPCObservation): string;
begin
  Result := IntToStr(Ord(O.Kind)) + ':' +
    IntToHex(UInt64(O.ObjectIdentity), 16) + ':' + IntToStr(O.OwnerPID);
end;

procedure IncludeObjectKind(Kind: TIPCObjectKind; var D: TDetectionKinds);
begin
  case Kind of
    ikEvent: Include(D, dkEvent);
    ikMutex: Include(D, dkMutex);
    ikSemaphore: Include(D, dkSemaphore);
    ikSection: Include(D, dkSection);
  end;
end;

function KindCount(Kinds: TIPCObjectKinds): Integer;
var
  K: TIPCObjectKind;
begin
  Result := 0;
  for K := ikEvent to ikSection do
    if K in Kinds then Inc(Result);
end;

constructor TIPCMonitor.Create;
begin
  inherited Create;
  FTracks := TDictionary<string, TIPCTrack>.Create;
  FRecent := TDictionary<Cardinal, TIPCRecent>.Create;
  Reset;
end;

destructor TIPCMonitor.Destroy;
begin
  FRecent.Free;
  FTracks.Free;
  inherited Destroy;
end;

procedure TIPCMonitor.Reset;
begin
  FTracks.Clear;
  FRecent.Clear;
  FBaselineRemaining := 3;
end;

procedure TIPCMonitor.Examine(const Observed: TList<TIPCObservation>;
  SnapshotValid: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var
  Current: TDictionary<string, TIPCObservation>;
  Keys: TList<string>;
  RecentKeys: TList<Cardinal>;
  Baseline: Boolean;

  procedure AggregateObservations;
  var
    O, Existing: TIPCObservation;
    Key: string;
  begin
    for O in Observed do
    begin
      if (O.OwnerPID = 0) or (O.Kind = ikNone) or
         (O.ObjectIdentity = 0) then Continue;
      Key := TrackKey(O);
      if Current.TryGetValue(Key, Existing) then
      begin
        Existing.GrantedAccess := Existing.GrantedAccess or O.GrantedAccess;
        Current.AddOrSetValue(Key, Existing);
      end
      else
        Current.Add(Key, O);
    end;
  end;

  procedure ApplyCurrentObservations;
  var
    Pair: TPair<string, TIPCObservation>;
    O: TIPCObservation;
    State: TIPCTrack;
    Recent: TIPCRecent;
    NewSignal: Boolean;
  begin
    for Pair in Current do
    begin
      O := Pair.Value;
      if FTracks.TryGetValue(Pair.Key, State) then
      begin
        NewSignal := (not State.Active) or
          ((O.GrantedAccess and (not State.Rights)) <> 0);
      end
      else
      begin
        State := Default(TIPCTrack);
        NewSignal := True;
      end;
      State.Rights := O.GrantedAccess;
      State.Active := True;
      State.Misses := 0;
      State.LastTick := Tick;
      FTracks.AddOrSetValue(Pair.Key, State);

      if not Baseline and NewSignal then
      begin
        IncludeObjectKind(O.Kind, Detected);
        if FRecent.TryGetValue(O.OwnerPID, Recent) then
        begin
          if (Tick < Recent.LastTick) or
             (Tick - Recent.LastTick > IPC_CORRELATION_WINDOW_MS) then
            Recent := Default(TIPCRecent);
        end
        else
          Recent := Default(TIPCRecent);
        Include(Recent.Kinds, O.Kind);
        Recent.LastTick := Tick;
        if (KindCount(Recent.Kinds) >= 2) and (not Recent.Emitted) then
        begin
          Include(Detected, dkIPC);
          Recent.Emitted := True;
        end;
        FRecent.AddOrSetValue(O.OwnerPID, Recent);
      end;
    end;
  end;

  procedure RetireMissingTracks;
  var
    TrackPair: TPair<string, TIPCTrack>;
    State: TIPCTrack;
    Key: string;
    I: Integer;
  begin
    for TrackPair in FTracks do
      if not Current.ContainsKey(TrackPair.Key) then
        Keys.Add(TrackPair.Key);
    for I := 0 to Keys.Count - 1 do
    begin
      Key := Keys[I];
      if not FTracks.TryGetValue(Key, State) then Continue;
      if State.Active then
      begin
        Inc(State.Misses);
        if State.Misses >= IPC_MISS_THRESHOLD then State.Active := False;
        FTracks.AddOrSetValue(Key, State);
      end
      else if (Tick >= State.LastTick) and
        (Tick - State.LastTick > IPC_TRACK_RETENTION_MS) then
        FTracks.Remove(Key);
    end;
  end;

  procedure ExpireRecentOwners;
  var
    Recent: TIPCRecent;
    PID: Cardinal;
    I: Integer;
  begin
    RecentKeys.Clear;
    for PID in FRecent.Keys do
    begin
      Recent := FRecent[PID];
      if (Tick >= Recent.LastTick) and
         (Tick - Recent.LastTick > IPC_CORRELATION_WINDOW_MS * 3) then
        RecentKeys.Add(PID);
    end;
    for I := 0 to RecentKeys.Count - 1 do
      FRecent.Remove(RecentKeys[I]);
  end;

begin
  if (not SnapshotValid) or (Observed = nil) then Exit; // do not infer disappearance on failure
  Baseline := FBaselineRemaining > 0;
  Current := nil;
  Keys := nil;
  RecentKeys := nil;
  try
    {$IFDEF NHW_NATIVE10M_TESTS}Current := TIPC10MCurrent.Create;{$ELSE}Current := TDictionary<string, TIPCObservation>.Create;{$ENDIF}
    {$IFDEF NHW_NATIVE10M_TESTS}Keys := TIPC10MKeys.Create;{$ELSE}Keys := TList<string>.Create;{$ENDIF}
    {$IFDEF NHW_NATIVE10M_TESTS}RecentKeys := TIPC10MRecent.Create;{$ELSE}RecentKeys := TList<Cardinal>.Create;{$ENDIF}
    AggregateObservations;
    ApplyCurrentObservations;
    RetireMissingTracks;
    ExpireRecentOwners;
    if FBaselineRemaining > 0 then Dec(FBaselineRemaining);
  finally
    RecentKeys.Free;
    Keys.Free;
    Current.Free;
  end;
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.IPC.inc}
{$ENDIF}

end.
