unit Cozy.NHW.Scheduler.Rules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils, Cozy.NHW.Logging;

type
  TProcessScheduleState = record
    ClassKnown: Boolean;
    PriorityClass: Cardinal;
    AffinityKnown: Boolean;
    ProcessMask: NativeUInt;
    GroupsKnown: Boolean;
    Groups: string;
    BoostKnown: Boolean;
    BoostDisabled: Boolean;
    MitigationKnown: array[0..7] of Boolean;
    MitigationFlags: array[0..7] of Cardinal;
  end;

  TThreadScheduleState = record
    CreationTime: UInt64;
    PriorityKnown: Boolean;
    Priority: Integer;
    GroupKnown: Boolean;
    Group: Word;
    AffinityMask: NativeUInt;
    BoostKnown: Boolean;
    BoostDisabled: Boolean;
    PowerKnown: Boolean;
    PowerControl: Cardinal;
    PowerState: Cardinal;
  end;


const
  // Every entry here has a 4-byte policy flags structure in the Windows SDK.
  // Failed/unsupported policy queries are NOT events.
  MITIGATION_POLICIES: array[0..7] of Cardinal = (2, 3, 6, 7, 8, 9, 10, 13);

function CompareProcessSchedule(const OldState, NewState: TProcessScheduleState): TDetectionKinds;
function CompareThreadSchedule(const OldState, NewState: TThreadScheduleState): TDetectionKinds;

implementation

function CompareProcessSchedule(const OldState, NewState: TProcessScheduleState): TDetectionKinds;
var I: Integer;
begin
  Result := [];
  if OldState.ClassKnown and NewState.ClassKnown and
     (OldState.PriorityClass <> NewState.PriorityClass) then
    Include(Result, dkProcessPriority);
  if OldState.AffinityKnown and NewState.AffinityKnown and
     (OldState.ProcessMask <> NewState.ProcessMask) then
    Include(Result, dkAffinity);
  if OldState.GroupsKnown and NewState.GroupsKnown and
     (OldState.Groups <> NewState.Groups) then
    Include(Result, dkCPUGroup);
  if OldState.BoostKnown and NewState.BoostKnown and
     (OldState.BoostDisabled <> NewState.BoostDisabled) then
    Include(Result, dkScheduling);
  for I := Low(MITIGATION_POLICIES) to High(MITIGATION_POLICIES) do
    if OldState.MitigationKnown[I] and NewState.MitigationKnown[I] and
       (OldState.MitigationFlags[I] <> NewState.MitigationFlags[I]) then
    begin
      Include(Result, dkMitigation);
      Break;
    end;
end;

function CompareThreadSchedule(const OldState, NewState: TThreadScheduleState): TDetectionKinds;
begin
  Result := [];
  if OldState.PriorityKnown and NewState.PriorityKnown and
     (OldState.Priority <> NewState.Priority) then
    Include(Result, dkThreadPriority);
  if OldState.GroupKnown and NewState.GroupKnown then
  begin
    if OldState.Group <> NewState.Group then
      Include(Result, dkCPUGroup);
    if OldState.AffinityMask <> NewState.AffinityMask then
      Include(Result, dkAffinity);
  end;
  if OldState.BoostKnown and NewState.BoostKnown and
     (OldState.BoostDisabled <> NewState.BoostDisabled) then
    Include(Result, dkScheduling);
  if OldState.PowerKnown and NewState.PowerKnown and
     ((OldState.PowerControl <> NewState.PowerControl) or
      (OldState.PowerState <> NewState.PowerState)) then
    Include(Result, dkScheduling);
end;

end.
