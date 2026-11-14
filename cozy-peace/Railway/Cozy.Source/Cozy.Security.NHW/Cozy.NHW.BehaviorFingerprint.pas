unit Cozy.NHW.BehaviorFingerprint;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TActorBehaviorFrame = record
    AliasId: UInt64;
    FirstTick: UInt64;
    LastTick: UInt64;
    LastRights: Cardinal; // diagnostic only; never compare different object rights
    LastProcessRights: Cardinal;
    LastThreadRights: Cardinal;
    LastProcessTick: UInt64;
    LastThreadTick: UInt64;
    HasProcessRights: Boolean;
    HasThreadRights: Boolean;
    ReadEdges: Word;
    WriteEdges: Word;
    ThreadEdges: Word;
    Escalations: Word;
  end;

  // v94: rights-sequence metadata, not an API-call trace or tool signature.
  TBehaviorFingerprint = class
  private
    FFrames: array[0..127] of TActorBehaviorFrame;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(AliasId: UInt64; Rights: Cardinal;
      IsThread, NewlyObserved: Boolean; Tick: UInt64);
    function Score(AliasId: UInt64; Tick: UInt64): Integer;
  end;

function NHWBehaviorScore(ReadEdges, WriteEdges, ThreadEdges,
  Escalations: Word): Integer;

{$IFDEF NHW_NATIVE5I_TESTS}
function TestBehavior5I(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.Types
{$IFDEF NHW_NATIVE5I_TESTS}
  , System.SysUtils
{$ENDIF}
  ;

const
  BEHAVIOR_LIFETIME_MS = 60000;

function NHWBehaviorScore(ReadEdges, WriteEdges, ThreadEdges,
  Escalations: Word): Integer;
begin
  Result := 0;
  if ReadEdges >= 2 then Inc(Result, 18);
  if WriteEdges >= 2 then Inc(Result, 32);
  if ThreadEdges >= 2 then Inc(Result, 22);
  if Escalations > 0 then Inc(Result, 18);
  if (WriteEdges > 0) and (ThreadEdges > 0) then Inc(Result, 10);
  if Result > 100 then Result := 100;
end;

constructor TBehaviorFingerprint.Create;
begin
  inherited Create;
  Reset;
end;

procedure TBehaviorFingerprint.Reset;
begin
  FillChar(FFrames, SizeOf(FFrames), 0);
end;

procedure TBehaviorFingerprint.Observe(AliasId: UInt64;
  Rights: Cardinal; IsThread, NewlyObserved: Boolean; Tick: UInt64);
var
  Slot: Integer;
  HighRights: Cardinal;
  procedure SelectActorSlot(out Slot: Integer);
  var
    I, Reusable, OldestSlot: Integer;
    Oldest: UInt64;
  begin
    Slot := -1;
    Reusable := -1;
    OldestSlot := -1;
    Oldest := High(UInt64);
    // Search the WHOLE table for the actor before reusing an earlier empty or
    // expired slot. A live actor later in the table must not acquire a duplicate.
    for I := Low(FFrames) to High(FFrames) do
    begin
      if FFrames[I].AliasId = AliasId then
      begin Slot := I; Break; end;
      if (Reusable < 0) and ((FFrames[I].AliasId = 0) or
         ((Tick >= FFrames[I].LastTick) and
          (Tick - FFrames[I].LastTick > BEHAVIOR_LIFETIME_MS))) then
        Reusable := I;
      if (OldestSlot < 0) or (FFrames[I].LastTick < Oldest) then
      begin Oldest := FFrames[I].LastTick; OldestSlot := I; end;
    end;
    if Slot < 0 then
    begin
      if Reusable >= 0 then Slot := Reusable else Slot := OldestSlot;
    end;
  end;

  procedure EvaluateRightsTransition(out HighRights: Cardinal);
  var
    PriorTick: UInt64;
    PriorRights: Cardinal;
    HavePrior: Boolean;
  begin
    HighRights := ACCESS_VM_WRITE or ACCESS_VM_OPERATION or ACCESS_CREATE_THREAD;
    if IsThread then
    begin
      HighRights := THREAD_SET_CONTEXT_RIGHT or THREAD_SUSPEND_RESUME_RIGHT;
      PriorRights := FFrames[Slot].LastThreadRights;
      PriorTick := FFrames[Slot].LastThreadTick;
      HavePrior := FFrames[Slot].HasThreadRights;
    end
    else
    begin
      PriorRights := FFrames[Slot].LastProcessRights;
      PriorTick := FFrames[Slot].LastProcessTick;
      HavePrior := FFrames[Slot].HasProcessRights;
    end;
    // A busy process lane does not keep the thread lane's old rights alive.
    if HavePrior then
      HavePrior := (Tick >= PriorTick) and
        (Tick - PriorTick <= BEHAVIOR_LIFETIME_MS);
    if HavePrior and ((Rights and HighRights) <> 0) and
       ((PriorRights and HighRights) = 0) and (PriorRights <> 0) and
       (FFrames[Slot].Escalations < High(Word)) then
      Inc(FFrames[Slot].Escalations);
  end;

  procedure UpdateActorHistory;
  begin
    if IsThread then
    begin
      if FFrames[Slot].ThreadEdges < High(Word) then Inc(FFrames[Slot].ThreadEdges);
      FFrames[Slot].LastThreadRights := Rights;
      FFrames[Slot].LastThreadTick := Tick;
      FFrames[Slot].HasThreadRights := True;
    end
    else
    begin
      if ((Rights and ACCESS_VM_READ) <> 0) and
         (FFrames[Slot].ReadEdges < High(Word)) then Inc(FFrames[Slot].ReadEdges);
      if ((Rights and HighRights) <> 0) and
         (FFrames[Slot].WriteEdges < High(Word)) then Inc(FFrames[Slot].WriteEdges);
      FFrames[Slot].LastProcessRights := Rights;
      FFrames[Slot].LastProcessTick := Tick;
      FFrames[Slot].HasProcessRights := True;
    end;
    FFrames[Slot].LastRights := Rights;
    FFrames[Slot].LastTick := Tick;
  end;

begin
  if (AliasId = 0) or not NewlyObserved or (Rights = 0) then Exit;
  SelectActorSlot(Slot);
  if Slot < 0 then Exit;
  // An out-of-order observation cannot roll a live actor's history backwards.
  if (FFrames[Slot].AliasId = AliasId) and
     (Tick < FFrames[Slot].LastTick) then Exit;
  if (FFrames[Slot].AliasId <> AliasId) or
     (Tick - FFrames[Slot].LastTick > BEHAVIOR_LIFETIME_MS) then
  begin
    FFrames[Slot] := Default(TActorBehaviorFrame);
    FFrames[Slot].AliasId := AliasId;
    FFrames[Slot].FirstTick := Tick;
  end;
  EvaluateRightsTransition(HighRights);
  UpdateActorHistory;
end;

function TBehaviorFingerprint.Score(AliasId: UInt64;
  Tick: UInt64): Integer;
var I: Integer;
begin
  Result := 0;
  if AliasId = 0 then Exit;
  for I := Low(FFrames) to High(FFrames) do
    if (FFrames[I].AliasId = AliasId) and
       (Tick >= FFrames[I].LastTick) and
       (Tick - FFrames[I].LastTick <= 15000) then
      Exit(NHWBehaviorScore(FFrames[I].ReadEdges,
        FFrames[I].WriteEdges, FFrames[I].ThreadEdges,
        FFrames[I].Escalations));
end;

{$IFDEF NHW_NATIVE5I_TESTS}
{$I Cozy.NHW.Native5I.Behavior.inc}
{$ENDIF}

end.
