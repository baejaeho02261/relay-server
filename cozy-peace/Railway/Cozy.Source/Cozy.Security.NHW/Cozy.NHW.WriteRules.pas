unit Cozy.NHW.WriteRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Types;

const
  WRITE_WATCH_SAMPLE_MS = 500;
  WRITE_WINDOW_MS = 10000;
  WRITE_BURST_WINDOW_MS = 2500;
  WRITE_REPEAT_EPISODES = 3;
  WRITE_BURST_PAGES = 3;
  WRITE_CORRELATION_MS = 3000;
  WRITE_CORRELATION_COOLDOWN_MS = 3000;
  WRITE_SIGNAL_COOLDOWN_MS = 8000;

function WriteCapable(IsThread: Boolean; Rights: Cardinal): Boolean;
function NewlyWriteCapable(IsThread, First, WasInactive: Boolean;
  PreviousRights, CurrentRights: Cardinal): Boolean;
function RecentWriteObservation(NowTick, LastTick, WindowMS: UInt64): Boolean;
function CountSetBits(Mask: Cardinal): Integer;

implementation

function WriteCapable(IsThread: Boolean; Rights: Cardinal): Boolean;
begin
  // Only PROCESS_VM_WRITE. Thread access flags have DIFFERENT bit meanings.
  Result := (not IsThread) and ((Rights and ACCESS_VM_WRITE) <> 0);
end;

function NewlyWriteCapable(IsThread, First, WasInactive: Boolean;
  PreviousRights, CurrentRights: Cardinal): Boolean;
begin
  Result := WriteCapable(IsThread, CurrentRights) and
    (First or WasInactive or ((PreviousRights and ACCESS_VM_WRITE) = 0));
end;

function RecentWriteObservation(NowTick, LastTick, WindowMS: UInt64): Boolean;
begin
  Result := (LastTick <> 0) and (NowTick >= LastTick) and
    (NowTick - LastTick <= WindowMS);
end;

function CountSetBits(Mask: Cardinal): Integer;
begin
  Result := 0;
  while Mask <> 0 do
  begin
    Inc(Result);
    Mask := Mask and (Mask - 1);
  end;
end;

end.
