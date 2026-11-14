unit Cozy.NHW.ReadRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Types;

const
  READ_WINDOW_MS = 10000;
  READ_CORRELATION_MS = 3000;
  READ_PATTERN_EPISODES = 4;
  CANARY_PATTERN_EPISODES = 3;

function ReadCapable(IsThread: Boolean; Rights: Cardinal): Boolean;
function NewlyReadCapable(IsThread, First, WasInactive: Boolean;
  PreviousRights, CurrentRights: Cardinal): Boolean;
function RecentObservation(NowTick, PriorTick, WindowMS: UInt64): Boolean;
function SamplingGapRelevant(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal): Boolean;
function CanaryGuardLost(HadBaseline, PreviousGuarded,
  QueryValid, CurrentGuarded: Boolean): Boolean;

implementation

function ReadCapable(IsThread: Boolean; Rights: Cardinal): Boolean;
begin
  Result := (not IsThread) and ((Rights and ACCESS_VM_READ) <> 0);
end;

function NewlyReadCapable(IsThread, First, WasInactive: Boolean;
  PreviousRights, CurrentRights: Cardinal): Boolean;
begin
  Result := ReadCapable(IsThread, CurrentRights) and
    (First or WasInactive or ((PreviousRights and ACCESS_VM_READ) = 0));
end;

function RecentObservation(NowTick, PriorTick, WindowMS: UInt64): Boolean;
begin
  Result := (PriorTick <> 0) and (NowTick >= PriorTick) and
    (NowTick - PriorTick <= WindowMS);
end;

function SamplingGapRelevant(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal): Boolean;
begin
  Result := (ScanMS > UInt64(IntervalMS)) or
    ((GapMS > 0) and (GapMS > UInt64(IntervalMS) * 2));
end;

function CanaryGuardLost(HadBaseline, PreviousGuarded,
  QueryValid, CurrentGuarded: Boolean): Boolean;
begin
  // Protection is observed, not a verified external read operation.
  Result := HadBaseline and PreviousGuarded and QueryValid and
    (not CurrentGuarded);
end;

end.
