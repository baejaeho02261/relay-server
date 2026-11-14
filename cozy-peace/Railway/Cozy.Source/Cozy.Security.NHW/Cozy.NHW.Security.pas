unit Cozy.NHW.Security;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types,
  Cozy.NHW.Logging,
  Cozy.NHW.Lifecycle,
  Cozy.NHW.Security.Snapshot;

const
  TOKEN_ASSIGN_PRIMARY_RIGHT = $0001;
  TOKEN_DUPLICATE_RIGHT = $0002;
  TOKEN_IMPERSONATE_RIGHT = $0004;
  TOKEN_QUERY_RIGHT = $0008;
  TOKEN_QUERY_SOURCE_RIGHT = $0010;
  TOKEN_ADJUST_PRIVILEGES_RIGHT = $0020;
  TOKEN_ADJUST_GROUPS_RIGHT = $0040;
  TOKEN_ADJUST_DEFAULT_RIGHT = $0080;
  TOKEN_ADJUST_SESSIONID_RIGHT = $0100;

  TOKEN_MODIFY_RIGHTS = TOKEN_ASSIGN_PRIMARY_RIGHT or
    TOKEN_DUPLICATE_RIGHT or TOKEN_IMPERSONATE_RIGHT or
    TOKEN_ADJUST_PRIVILEGES_RIGHT or TOKEN_ADJUST_GROUPS_RIGHT or
    TOKEN_ADJUST_DEFAULT_RIGHT or TOKEN_ADJUST_SESSIONID_RIGHT;

type
  TTokenTrack = record
    Rights, ActorPID: Cardinal;
    ActorCreation: UInt64;
    Missing: Integer;
    Active: Boolean;
    LastTick: UInt64;
  end;

  TDaclTrack = record
    Signature: UInt64;
    LastTick: UInt64;
  end;

  TThreadTokenState = record
    Present: Boolean;
    TokenId: UInt64;
    LastTick: UInt64;
    SecurityState: TTokenSecuritySnapshot;
  end;

  TSecurityMonitor = class
  private
    FTokenTracks: TDictionary<string, TTokenTrack>;
    FDaclStates: TDictionary<string, TDaclTrack>;
    FThreadTokens: TDictionary<string, TThreadTokenState>;
    FPrimaryTokenState: TTokenSecuritySnapshot;
    FLastStateTick: UInt64;
    FThreadOffset: Integer;
    procedure CompareDacl(const Key: string; Signature: UInt64;
      Baseline: Boolean; var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure ExamineTokenHandles(const Observations: TList<TObservedTokenHandle>;
      TokenSnapshotValid: Boolean; TargetPID: Cardinal;
      OwnerCreated: TCreationTimeMap; Baseline: Boolean;
      var Detected: TDetectionKinds);
    procedure ExamineLocalState(TargetHandle: THandle; TargetPID: Cardinal;
      Threads: TThreadSampleMap; ThreadsValid: Boolean;
      Tick: UInt64; Baseline: Boolean;
      var Detected: TDetectionKinds);
  end;

// Pure exported helpers also used by the small regression test.
function TokenModificationRights(Rights: Cardinal): Cardinal;

{$IFDEF NHW_NATIVE5C_TESTS}
function TestSecurityHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers,
  Cozy.NHW.Native,
  Cozy.NHW.Process,
  Cozy.NHW.Context;

const
  SECURITY_INTERVAL_MS = 2000;
  MAX_THREADS_PER_SECURITY_PASS = 64;
  MAX_TOKEN_HANDLE_TRACKS = 4096;
  MAX_THREAD_TOKEN_STATES = 1024;
function TokenModificationRights(Rights: Cardinal): Cardinal;
begin
  Result := Rights and TOKEN_MODIFY_RIGHTS;
end;

{$Q-} // Preserve the original post-hash arithmetic mode.

function TryThreadTokenState(ThreadHandle: THandle;
  out State: TThreadTokenState): Boolean;
var
  Token: THandle;
  Status: TNTStatus;
begin
  State := Default(TThreadTokenState);
  Token := 0;
  Status := OpenNativeThreadToken(ThreadHandle, TOKEN_QUERY_RIGHT, Token);
  if Cardinal(Status) = STATUS_NO_TOKEN then
    Exit(True); // authoritative: there is no impersonation token
  if (Status < 0) or (Token = 0) then
    Exit(False); // inaccessible/incomplete is UNKNOWN, never "no token"
  try
    if not TryTokenSecuritySnapshot(Token, State.SecurityState) then Exit(False);
    State.Present := True;
    State.TokenId := State.SecurityState.TokenId;
    Result := True;
  finally
    CloseNativeProcess(Token);
  end;
end;

constructor TSecurityMonitor.Create;
begin
  inherited Create;
  FTokenTracks := TDictionary<string, TTokenTrack>.Create;
  FDaclStates := TDictionary<string, TDaclTrack>.Create;
  FThreadTokens := TDictionary<string, TThreadTokenState>.Create;
  Reset;
end;

destructor TSecurityMonitor.Destroy;
begin
  Reset;
  FThreadTokens.Free;
  FDaclStates.Free;
  FTokenTracks.Free;
  inherited Destroy;
end;

procedure TSecurityMonitor.Reset;
var Keys: array[0..MAX_THREAD_TOKEN_STATES - 1] of string;
  Key: string; Count, I: Integer;
begin
  { Fixed bounded key staging avoids a fresh heap allocation while shutting
    down. Overwrite token records before releasing dictionary storage. }
  if FThreadTokens <> nil then
  begin
    Count := 0;
    for Key in FThreadTokens.Keys do
    begin
      if Count = Length(Keys) then Break;
      Keys[Count] := Key; Inc(Count);
    end;
    for I := 0 to Count - 1 do
      FThreadTokens.AddOrSetValue(Keys[I], Default(TThreadTokenState));
    FThreadTokens.Clear;
  end;
  if FTokenTracks <> nil then FTokenTracks.Clear;
  if FDaclStates <> nil then FDaclStates.Clear;
  FillChar(FPrimaryTokenState, SizeOf(FPrimaryTokenState), 0);
  FLastStateTick := 0;
  FThreadOffset := 0;
end;

procedure TSecurityMonitor.CompareDacl(const Key: string; Signature: UInt64;
  Baseline: Boolean; var Detected: TDetectionKinds);
var
  Previous: TDaclTrack;
begin
  if FDaclStates.TryGetValue(Key, Previous) then
  begin
    if (Previous.Signature <> Signature) and not Baseline then
      Include(Detected, dkDacl);
  end;
  Previous.Signature := Signature;
  Previous.LastTick := WinTick64;
  FDaclStates.AddOrSetValue(Key, Previous);
end;

procedure TSecurityMonitor.ExamineTokenHandles(
  const Observations: TList<TObservedTokenHandle>;
  TokenSnapshotValid: Boolean; TargetPID: Cardinal;
  OwnerCreated: TCreationTimeMap; Baseline: Boolean;
  var Detected: TDetectionKinds);
var
  Rights: TDictionary<string, TTokenTrack>;
  Seen: TDictionary<string, Byte>;
  OwnerTimes: TCreationTimeMap;
  O: TObservedTokenHandle;
  Owner: TTargetHolder;
  Pair: TPair<string, TTokenTrack>;
  PairTrack: TPair<string, TTokenTrack>;
  Track, Observation: TTokenTrack;
  OwnerCreate: UInt64;
  CurrentRights: Cardinal;
  K: string;
  Keys: TList<string>;
  I: Integer;
  TickNow: UInt64;
  IdentityComplete, NewHolder, NewRights: Boolean;
begin
  if not TokenSnapshotValid or (Observations = nil) or (TargetPID = 0) then Exit;
  TickNow := WinTick64;
  IdentityComplete := True;
  Rights := nil;
  Seen := nil;
  OwnerTimes := nil;
  Keys := nil;
  try
    Rights := TDictionary<string, TTokenTrack>.Create;
    Seen := TDictionary<string, Byte>.Create;
    OwnerTimes := TCreationTimeMap.Create;
    Keys := TList<string>.Create;
    for I := 0 to Observations.Count - 1 do
    begin
      O := Observations[I];
      if (O.OwnerPID = 0) or (O.OwnerPID = TargetPID) or
         (O.OwnerPID = WinCurrentProcessId) then Continue;
      if not OwnerTimes.TryGetValue(O.OwnerPID, OwnerCreate) then
      begin
        OwnerCreate := 0;
        if OwnerCreated <> nil then OwnerCreated.TryGetValue(O.OwnerPID, OwnerCreate);
        if OwnerCreate = 0 then
        begin
          Owner := Default(TTargetHolder);
          Owner.PID := O.OwnerPID;
          QueryOwnerInfo(Owner);
          OwnerCreate := Owner.CreateTime;
        end;
        OwnerTimes.AddOrSetValue(O.OwnerPID, OwnerCreate);
      end;
      if (OwnerCreate = 0) or (O.TokenObject = 0) then
      begin
        IdentityComplete := False;
        Continue; // do not join different unknown process lifetimes
      end;
      K := IntToHex(UInt64(O.TokenObject), 16) + ':' +
        IntToStr(O.OwnerPID) + ':' + IntToStr(Int64(OwnerCreate));
      if not Rights.TryGetValue(K, Observation) then
      begin
        Observation := Default(TTokenTrack);
        Observation.ActorPID := O.OwnerPID;
        Observation.ActorCreation := OwnerCreate;
      end;
      Observation.Rights := Observation.Rights or O.GrantedAccess;
      Rights.AddOrSetValue(K, Observation);
    end;

    for Pair in Rights do
    begin
      K := Pair.Key;
      Observation := Pair.Value;
      CurrentRights := Observation.Rights;
      Seen.AddOrSetValue(K, 1);
      if not FTokenTracks.TryGetValue(K, Track) then
        Track := Default(TTokenTrack);
      NewHolder := not Track.Active;
      NewRights := (TokenModificationRights(CurrentRights) and
        (not TokenModificationRights(Track.Rights))) <> 0;
      { A token-object handle is not evidence that the token changed. Query
        handles, including a reappearing handle, stay observable telemetry.
        External modification rights remain visible even during bootstrap;
        Baseline is context, never a security-off grace period. }
      if TokenModificationRights(CurrentRights) = 0 then
        NHWNoteAccessContext(dkTokenObject, Observation.ActorPID,
          Observation.ActorCreation, TargetPID, 'TOKEN_ACCESS', CurrentRights, Baseline)
      else
      begin
        NHWNoteAccessContext(dkTokenRights, Observation.ActorPID,
          Observation.ActorCreation, TargetPID, 'TOKEN_ACCESS', CurrentRights, Baseline);
        if NewHolder then
        begin
          { Preserve the real token-handle observation during bootstrap, but
            match original NHW v109: only post-baseline arrivals are an alert. }
          if not Baseline then Include(Detected, dkTokenObject);
          NHWNoteAccessContext(dkTokenObject, Observation.ActorPID,
            Observation.ActorCreation, TargetPID, 'TOKEN_ACCESS', CurrentRights, Baseline);
        end;
        if (NewHolder or NewRights) and not Baseline then
          Include(Detected, dkTokenRights);
      end;
      Track.ActorPID := Observation.ActorPID;
      Track.ActorCreation := Observation.ActorCreation;
      Track.Active := True;
      Track.Rights := CurrentRights;
      Track.Missing := 0;
      Track.LastTick := TickNow;
      if FTokenTracks.ContainsKey(K) or (FTokenTracks.Count < MAX_TOKEN_HANDLE_TRACKS) then
        FTokenTracks.AddOrSetValue(K, Track)
      else
        Include(Detected, dkSensorPressure);
    end;

    // An unresolved owner makes absence ambiguous. Do not age live tracks
    // as missing from this partial identity view.
    if not IdentityComplete then Exit;
    for PairTrack in FTokenTracks do Keys.Add(PairTrack.Key);
    for I := 0 to Keys.Count - 1 do
    begin
      K := Keys[I];
      if Seen.ContainsKey(K) then Continue;
      if not FTokenTracks.TryGetValue(K, Track) then Continue;
      if (not Track.Active) and (TickNow >= Track.LastTick) and
         (TickNow - Track.LastTick > TRACK_RETENTION_MS) then
      begin
        FTokenTracks.Remove(K);
        Continue;
      end;
      if Track.Active then
      begin
        Inc(Track.Missing);
        if Track.Missing >= 2 then Track.Active := False;
        FTokenTracks.AddOrSetValue(K, Track);
      end;
    end;
  finally
    Keys.Free;
    OwnerTimes.Free;
    Seen.Free;
    Rights.Free;
  end;
end;

procedure TSecurityMonitor.ExamineLocalState(TargetHandle: THandle;
  TargetPID: Cardinal; Threads: TThreadSampleMap; ThreadsValid: Boolean;
  Tick: UInt64; Baseline: Boolean; var Detected: TDetectionKinds);
var
  Token: THandle;
  ProcessDaclHandle: THandle;
  ThreadHandle, DaclThreadHandle: THandle;
  Signature: UInt64;
  TokenState: TTokenSecuritySnapshot;
  TokenDelta: Word;
  ThreadIds: TList<Cardinal>;
  ThreadID: Cardinal;
  I, Index, MaxCount: Integer;
  ThreadState, PrevThreadState: TThreadTokenState;
  ThreadIdentity, TKey: string;
  CreateStamp, DaclCreateStamp, CheckStamp: UInt64;
  HaveToken: Boolean;
  Keys: TList<string>;
  K: string;
  DaclCache: TDaclTrack;
begin
  if (FLastStateTick <> 0) and (Tick >= FLastStateTick) and
     (Tick - FLastStateTick < SECURITY_INTERVAL_MS) then Exit;
  if (TargetHandle = 0) or (TargetPID = 0) then Exit;
  FLastStateTick := Tick;
  if not SecurityNativeAvailable then
  begin
    Include(Detected, dkObservationUncertain);
    Exit;
  end;

  { The first successful state is a baseline for this process instance.
    A later unavailable class does not become a measured zero. Changes are
    evaluated even during sensor bootstrap; there is no blanket grace gap. }
  TokenState := Default(TTokenSecuritySnapshot);
  Token := OpenNativeProcessToken(TargetHandle, TOKEN_QUERY_RIGHT);
  if Token <> 0 then
  try
    if TryTokenSecuritySnapshot(Token, TokenState) then
    begin
      if (FPrimaryTokenState.ValidFields and TOKEN_FIELD_STATISTICS) = 0 then
        NHWNoteTokenBaseline(TargetPID)
      else
      begin
        TokenDelta := TokenSecurityDelta(FPrimaryTokenState, TokenState);
        if TokenDelta <> 0 then
        begin
          Include(Detected, dkTokenChange);
          NHWNoteTokenDelta(dkTokenChange, TargetPID, TokenDelta);
          if (TokenDelta and TOKEN_DELTA_REPLACED) <> 0 then
          begin
            Include(Detected, dkTokenObject);
            NHWNoteTokenDelta(dkTokenObject, TargetPID, TokenDelta);
          end;
          if (TokenDelta and (TOKEN_DELTA_PRIVILEGE_ESCALATED or
            TOKEN_DELTA_INTEGRITY_RAISED or TOKEN_DELTA_RESTRICTION_REMOVED or
            TOKEN_DELTA_APPCONTAINER_REMOVED)) <> 0 then
          begin
            Include(Detected, dkTokenRights);
            NHWNoteTokenDelta(dkTokenRights, TargetPID, TokenDelta);
          end;
        end;
      end;
      MergeTokenSecuritySnapshot(FPrimaryTokenState, TokenState);
    end
    else
      Include(Detected, dkObservationUncertain);
  finally
    FillChar(TokenState, SizeOf(TokenState), 0);
    CloseNativeProcess(Token);
  end
  else
    Include(Detected, dkObservationUncertain);

  // 4: query DACL using a separate READ_CONTROL handle. Insufficient rights
  // means UNKNOWN, not that the DACL has changed or vanished.
  ProcessDaclHandle := OpenNativeProcess(TargetPID,
    ACCESS_READ_CONTROL or ACCESS_QUERY_LIMITED);
  if ProcessDaclHandle <> 0 then
  try
    if SameProcessCreation(TargetHandle, ProcessDaclHandle) and
       TryDaclSignature(ProcessDaclHandle, Signature) then
      CompareDacl('P', Signature, Baseline, Detected);
  finally
    CloseNativeProcess(ProcessDaclHandle);
  end;

  if not ThreadsValid or (Threads = nil) then Exit;
  ThreadIds := nil;
  Keys := nil;
  try
    ThreadIds := TList<Cardinal>.Create;
    Keys := TList<string>.Create;
    for ThreadID in Threads.Keys do ThreadIds.Add(ThreadID);
    ThreadIds.Sort;
    if ThreadIds.Count = 0 then Exit;
    if FThreadOffset >= ThreadIds.Count then FThreadOffset := 0;
    MaxCount := ThreadIds.Count;
    if MaxCount > MAX_THREADS_PER_SECURITY_PASS then
      MaxCount := MAX_THREADS_PER_SECURITY_PASS;

    for I := 0 to MaxCount - 1 do
    begin
      Index := (FThreadOffset + I) mod ThreadIds.Count;
      ThreadID := ThreadIds[Index];
      // Separate handles keep token inspection independent of READ_CONTROL.
      // A DACL result is accepted only with verifiable creation identity.
      ThreadHandle := 0;
      DaclThreadHandle := 0;
      try
        ThreadHandle := OpenNativeThread(TargetPID, ThreadID,
          THREAD_QUERY_INFORMATION_RIGHT);
        if ThreadHandle = 0 then
          ThreadHandle := OpenNativeThread(TargetPID, ThreadID,
            THREAD_QUERY_LIMITED_INFORMATION_RIGHT);
        DaclThreadHandle := OpenNativeThread(TargetPID, ThreadID,
          ACCESS_READ_CONTROL or THREAD_QUERY_LIMITED_INFORMATION_RIGHT);
        CreateStamp := 0;
        DaclCreateStamp := 0;
        CheckStamp := 0;
        if ThreadHandle <> 0 then TryThreadCreationStamp(ThreadHandle, CreateStamp);
        if DaclThreadHandle <> 0 then
          TryThreadCreationStamp(DaclThreadHandle, DaclCreateStamp);
        if (DaclCreateStamp <> 0) and
           ((CreateStamp = 0) or (CreateStamp = DaclCreateStamp)) and
           ThreadSecurityIdentity(ThreadID, DaclCreateStamp, ThreadIdentity) and
           TryDaclSignature(DaclThreadHandle, Signature) and
           TryThreadCreationStamp(DaclThreadHandle, CheckStamp) and
           (CheckStamp = DaclCreateStamp) then
          CompareDacl(ThreadIdentity, Signature, Baseline, Detected);
        if not ThreadSecurityIdentity(ThreadID, CreateStamp, ThreadIdentity) then
          Continue; // unknown creation time must never enter a TID:0 cache
        // A query failure is unknown, not "no token". TokenId (TokenStatistics)
        // also catches an observed switch to another impersonation token.
        if ThreadHandle <> 0 then
        begin
          HaveToken := TryThreadTokenState(ThreadHandle, ThreadState);
          if HaveToken and TryThreadCreationStamp(ThreadHandle, CheckStamp) and
             (CheckStamp = CreateStamp) then
          begin
            TKey := ThreadIdentity;
            if FThreadTokens.TryGetValue(TKey, PrevThreadState) then
            begin
              { RevertToSelf is not an escalation. Introduction/replacement
                remains an observation requiring role/capability adjudication;
                token ID alone does not identify the actor causing a change. }
              if ThreadState.Present and
                 ((not PrevThreadState.Present) or
                  ((PrevThreadState.TokenId <> 0) and (ThreadState.TokenId <> 0) and
                   (PrevThreadState.TokenId <> ThreadState.TokenId))) then
              begin
                Include(Detected, dkThreadToken);
                { Impersonation by itself is context, not proof of attack.
                  Compare posture to the primary token, ignoring token/object
                  identity differences inherent in normal impersonation. }
                TokenDelta := TokenSecurityDelta(FPrimaryTokenState,
                  ThreadState.SecurityState) and
                  (TOKEN_DELTA_PRIVILEGE_ESCALATED or TOKEN_DELTA_INTEGRITY_RAISED or
                   TOKEN_DELTA_RESTRICTION_REMOVED or TOKEN_DELTA_APPCONTAINER_REMOVED);
                NHWNoteTokenDelta(dkThreadToken, TargetPID,
                  TOKEN_DELTA_IMPERSONATION_CHANGED or TokenDelta);
              end
              else if PrevThreadState.Present and ThreadState.Present then
              begin
                TokenDelta := TokenSecurityDelta(PrevThreadState.SecurityState,
                  ThreadState.SecurityState) and
                  (TOKEN_DELTA_PRIVILEGE_ESCALATED or TOKEN_DELTA_INTEGRITY_RAISED or
                   TOKEN_DELTA_RESTRICTION_REMOVED or TOKEN_DELTA_APPCONTAINER_REMOVED);
                if TokenDelta <> 0 then
                begin
                  Include(Detected, dkThreadToken);
                  NHWNoteTokenDelta(dkThreadToken, TargetPID, TokenDelta);
                end;
              end;
            end
            else if ThreadState.Present then
            begin
              TokenDelta := TokenSecurityDelta(FPrimaryTokenState,
                ThreadState.SecurityState) and
                (TOKEN_DELTA_PRIVILEGE_ESCALATED or TOKEN_DELTA_INTEGRITY_RAISED or
                 TOKEN_DELTA_RESTRICTION_REMOVED or TOKEN_DELTA_APPCONTAINER_REMOVED);
              if TokenDelta <> 0 then Include(Detected, dkThreadToken);
              NHWNoteTokenDelta(dkThreadToken, TargetPID,
                TOKEN_DELTA_IMPERSONATION_CHANGED or TokenDelta);
            end;
            ThreadState.LastTick := Tick;
            if FThreadTokens.ContainsKey(TKey) or
              (FThreadTokens.Count < MAX_THREAD_TOKEN_STATES) then
              FThreadTokens.AddOrSetValue(TKey, ThreadState)
            else
              Include(Detected, dkSensorPressure);
            FillChar(ThreadState, SizeOf(ThreadState), 0);
            FillChar(PrevThreadState, SizeOf(PrevThreadState), 0);
          end;
        end;
      finally
        CloseNativeProcess(DaclThreadHandle);
        CloseNativeProcess(ThreadHandle);
      end;
    end;
    FThreadOffset := (FThreadOffset + MaxCount) mod ThreadIds.Count;

    // Bounded state retention for gone threads, not a disappearance event.
    for K in FThreadTokens.Keys do Keys.Add(K);
    for I := 0 to Keys.Count - 1 do
      if FThreadTokens.TryGetValue(Keys[I], PrevThreadState) and
         (Tick >= PrevThreadState.LastTick) and
         (Tick - PrevThreadState.LastTick > TRACK_RETENTION_MS) then
      begin
        FThreadTokens.AddOrSetValue(Keys[I], Default(TThreadTokenState));
        FThreadTokens.Remove(Keys[I]);
      end;
    Keys.Clear;
    for K in FDaclStates.Keys do Keys.Add(K);
    for I := 0 to Keys.Count - 1 do
    begin
      K := Keys[I];
      if (K = 'P') then Continue;
      if FDaclStates.TryGetValue(K, DaclCache) and
         (Tick >= DaclCache.LastTick) and
         (Tick - DaclCache.LastTick > TRACK_RETENTION_MS) then
        FDaclStates.Remove(K);
    end;
  finally
    FillChar(ThreadState, SizeOf(ThreadState), 0);
    FillChar(PrevThreadState, SizeOf(PrevThreadState), 0);
    Keys.Free;
    ThreadIds.Free;
  end;
end;

{$IFDEF NHW_NATIVE5C_TESTS}
  {$I Cozy.NHW.Native5C.Security.inc}
{$ENDIF}
end.
