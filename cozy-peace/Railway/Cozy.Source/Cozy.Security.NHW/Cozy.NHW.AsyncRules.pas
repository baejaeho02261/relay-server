unit Cozy.NHW.AsyncRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows;

// Pure validation functions for self-owned completion and threadpool probes.
// They never attribute the source of an unexpected packet to an external PID.
function ExpectedCompletion(Key, ExpectedKey: NativeUInt;
  Bytes, ExpectedBytes: Cardinal; Overlapped: Pointer): Boolean;
function WorkCountersConsistent(Submitted, Completed: LongInt): Boolean;
function InRecentWindow(NowTick, EventTick: UInt64;
  WindowMS: UInt64): Boolean;

implementation

function ExpectedCompletion(Key, ExpectedKey: NativeUInt;
  Bytes, ExpectedBytes: Cardinal; Overlapped: Pointer): Boolean;
begin
  Result := (Key = ExpectedKey) and (Bytes = ExpectedBytes) and
    (Overlapped = nil);
end;

function WorkCountersConsistent(Submitted, Completed: LongInt): Boolean;
begin
  Result := (Submitted >= 0) and (Completed >= 0) and
    (Completed <= Submitted);
end;

function InRecentWindow(NowTick, EventTick: UInt64;
  WindowMS: UInt64): Boolean;
begin
  Result := (EventTick <> 0) and (NowTick >= EventTick) and
    ((NowTick - EventTick) <= WindowMS);
end;

end.
