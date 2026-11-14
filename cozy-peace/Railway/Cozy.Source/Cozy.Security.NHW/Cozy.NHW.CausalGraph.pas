unit Cozy.NHW.CausalGraph;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TCorrelatedSequence = record
    TargetPID: Cardinal;
    Epoch: Cardinal;
    AccessTick: UInt64;
    MemoryTick: UInt64;
    ThreadTick: UInt64;
    // A temporal sequence cannot establish an actor or prove causation.
    ActorPID: Cardinal;
    ConfirmedTemporalOrder: Boolean;
  end;

  // v71: strict ordered correlation within one target creation / module
  // epoch. Does not infer API calls or attacker identity from handle rights.
  TCausalAttackGraph = class
  private
    FPhase: Byte;
    FCurrent: TCorrelatedSequence;
    FLast: TCorrelatedSequence;
    FLastReport: UInt64;
    FLastTick: UInt64;
  public
    constructor Create;
    procedure Reset;
    procedure ObservationGap;
    procedure Examine(OwnTarget, Baseline, IdentityValid,
      TrustReliable: Boolean; TargetPID, Epoch: Cardinal;
      HighExternal: Boolean; const Kinds: TDetectionKinds;
      Tick: UInt64; var Detected: TDetectionKinds;
      ObservationValid: Boolean = True);
    property LastSequence: TCorrelatedSequence read FLast;
  end;

function CausalSequenceCandidate(AccessTick, MemoryTick,
  ThreadTick: UInt64; IdentityValid, TrustReliable: Boolean): Boolean;
function IsMemoryEvidence(const Kinds: TDetectionKinds): Boolean;
function IsThreadEvidence(const Kinds: TDetectionKinds): Boolean;

implementation

const MAX_CAUSAL_WINDOW_MS = 20000;

function CausalSequenceCandidate(AccessTick, MemoryTick,
  ThreadTick: UInt64; IdentityValid, TrustReliable: Boolean): Boolean;
begin
  Result := False;
  if not IdentityValid or not TrustReliable then Exit;
  if (AccessTick = 0) or (MemoryTick <= AccessTick) then Exit;
  if ThreadTick <= MemoryTick then Exit;
  Result := ThreadTick - AccessTick <= MAX_CAUSAL_WINDOW_MS;
end;

function IsMemoryEvidence(const Kinds: TDetectionKinds): Boolean;
begin
  Result := (Kinds * [dkPECodeIntegrity, dkImageCOWIntegrity,
    dkPrivateExecRegion, dkExecutableLifecycle, dkWriteIntegrity,
    dkImportRedirect, dkTLSCallbackIntegrity,
    dkUnwindStructural, dkSectionBacking,
    dkCodeProvenance, dkSectionCorrelation]) <> [];
end;

function IsThreadEvidence(const Kinds: TDetectionKinds): Boolean;
begin
  Result := (Kinds * [dkPrivateThread, dkRemoteThread,
    dkExecutionProvenance, dkThreadProvenance,
    dkThreadSpawn, dkThreadTimeline]) <> [];
end;

constructor TCausalAttackGraph.Create;
begin inherited Create; Reset; end;

procedure TCausalAttackGraph.Reset;
begin
  FPhase := 0;
  FCurrent := Default(TCorrelatedSequence);
  FLast := Default(TCorrelatedSequence);
  FLastReport := 0;
  FLastTick := 0;
end;

procedure TCausalAttackGraph.ObservationGap;
begin
  FPhase := 0;
  FCurrent := Default(TCorrelatedSequence);
  // LastSequence is historical, not a current validity flag. Keep cooldown.
end;

procedure TCausalAttackGraph.Examine(OwnTarget, Baseline,
  IdentityValid, TrustReliable: Boolean; TargetPID, Epoch: Cardinal;
  HighExternal: Boolean; const Kinds: TDetectionKinds;
  Tick: UInt64; var Detected: TDetectionKinds; ObservationValid: Boolean);

  function AcceptObservation: Boolean;
  begin
    if not OwnTarget or Baseline or not IdentityValid or
       not TrustReliable or not ObservationValid or (Epoch = 0) or
       (TargetPID = 0) or (Tick = 0) then
    begin
      ObservationGap;
      if Tick > FLastTick then FLastTick := Tick;
      Exit(False);
    end;
    if (FPhase <> 0) and ((FCurrent.TargetPID <> TargetPID) or
       (FCurrent.Epoch <> Epoch)) then ObservationGap;
    if FLastTick <> 0 then
    begin
      if Tick < FLastTick then
      begin
        ObservationGap;
        FLastTick := Tick;
        if FLastReport <> 0 then FLastReport := Tick;
        Exit(False); // a clock boundary is not a new evidence sample
      end;
      if Tick = FLastTick then Exit(False);
    end;
    FLastTick := Tick;
    Result := True;
  end;

  procedure ExpirePendingSequence;
  begin
    if FPhase <> 0 then
    begin
      if Tick < FCurrent.AccessTick then ObservationGap
      else if Tick - FCurrent.AccessTick > MAX_CAUSAL_WINDOW_MS then
        ObservationGap;
    end;
  end;

  procedure ConfirmAndStoreSequence;
  var
    CanReport: Boolean;
  begin
    FCurrent.ThreadTick := Tick;
    FCurrent.ActorPID := 0;
    FCurrent.ConfirmedTemporalOrder :=
      CausalSequenceCandidate(FCurrent.AccessTick,
        FCurrent.MemoryTick, FCurrent.ThreadTick,
        IdentityValid, TrustReliable);
    CanReport := FLastReport = 0;
    if not CanReport then
      if Tick >= FLastReport then
        CanReport := Tick - FLastReport >= 60000;
    if FCurrent.ConfirmedTemporalOrder and CanReport then
    begin
      Include(Detected, dkCausalSequence);
      FLast := FCurrent;
      FLastReport := Tick;
    end;
    FPhase := 0;
  end;

  procedure AdvanceTemporalPhase;
  begin
    case FPhase of
      0:
        if HighExternal and (Tick > 0) then
        begin
          FCurrent := Default(TCorrelatedSequence);
          FCurrent.TargetPID := TargetPID;
          FCurrent.Epoch := Epoch;
          FCurrent.AccessTick := Tick;
          FPhase := 1;
        end;
      1:
        begin
          if IsMemoryEvidence(Kinds) and
             (Tick > FCurrent.AccessTick) then
          begin
            FCurrent.MemoryTick := Tick;
            FPhase := 2;
          end;
        end;
      2:
        if IsThreadEvidence(Kinds) and
           (Tick > FCurrent.MemoryTick) then
        begin
          ConfirmAndStoreSequence;
        end;
    end;
  end;

begin
  if not AcceptObservation then Exit;
  ExpirePendingSequence;
  AdvanceTemporalPhase;
end;

end.
