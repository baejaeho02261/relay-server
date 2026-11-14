unit Cozy.NHW.WaitChainRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.WCTNative;

type
  TWaitFacts = record
    Cycle: Boolean;
    HasOwner: Boolean;
    SameProcessOwner: Boolean;
    ExternalOwner: Boolean;
    CriticalSection: Boolean;
    Blocked: Boolean;
    OwnerPID: Cardinal;
    OwnerTID: Cardinal;
  end;

function ClassifyWait(const Nodes: PWaitChainNode;
  NodeCount, TargetPID, RootTID: Cardinal; Cycle: Boolean;
  out Facts: TWaitFacts): Boolean;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestWaitChainRules10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

function ClassifyWait(const Nodes: PWaitChainNode;
  NodeCount, TargetPID, RootTID: Cardinal; Cycle: Boolean;
  out Facts: TWaitFacts): Boolean;
var
  Local: array[0..WCT_MAX_NODE_COUNT - 1] of TWaitChainNode;
  Candidate: TWaitFacts;
  Span: NativeUInt;
  function ValidateRootThread: Boolean;
  var
    Owner: PWaitThreadNode;
  begin
    Result := False;
    if (Local[0].ObjectType <> WCT_OBJECT_THREAD) or
       (Local[0].ObjectStatus <> WCT_STATUS_BLOCKED) then Exit;
    Owner := PWaitThreadNode(@Local[0].Payload[0]);
    if (Owner^.ProcessId <> TargetPID) or (Owner^.ThreadId <> RootTID) then Exit;
    Candidate.Blocked := True;
    Result := True;
  end;

  function ClassifyValidatedNodes: Boolean;
  var
    I: Cardinal;
    N: PWaitChainNode;
    Owner: PWaitThreadNode;
  begin
    Result := False;
    for I := 0 to NodeCount - 1 do
    begin
      N := @Local[I];
      // Inaccessible/unknown/error nodes do not support ownership claims.
      if (N^.ObjectStatus < 2) or (N^.ObjectStatus >= 9) or
         (N^.ObjectType = 0) or (N^.ObjectType >= 10) then Exit;
      if (I and 1) = 0 then
      begin
        if N^.ObjectType <> WCT_OBJECT_THREAD then Exit;
        Owner := PWaitThreadNode(@N^.Payload[0]);
        // WCT can legitimately return TID=0 for COM/ALPC. Such a partial
        // owner is UNKNOWN for this detector, not a wrong/malicious owner.
        if (Owner^.ProcessId = 0) or (Owner^.ThreadId = 0) or
           (N^.ObjectStatus in [4, 5]) then Exit;
        if (Owner^.ThreadId = RootTID) and (Owner^.ProcessId <> TargetPID) then Exit;
        if (I + 1 < NodeCount) and
           (N^.ObjectStatus <> WCT_STATUS_BLOCKED) then Exit;
        if (I > 0) and (Owner^.ThreadId <> RootTID) then
        begin
          Candidate.HasOwner := True;
          Candidate.OwnerPID := Owner^.ProcessId;
          Candidate.OwnerTID := Owner^.ThreadId;
          if Owner^.ProcessId = TargetPID then Candidate.SameProcessOwner := True
          else Candidate.ExternalOwner := True;
        end;
      end
      else
      begin
        if N^.ObjectType = WCT_OBJECT_THREAD then Exit;
        // A following owner thread requires an owned/blocked object.
        if (I + 1 < NodeCount) and not (N^.ObjectStatus in [3, 6]) then Exit;
        if N^.ObjectType = WCT_OBJECT_CRITICAL_SECTION then
          Candidate.CriticalSection := True;
      end;
    end;
    Result := True;
  end;

begin
  Facts := Default(TWaitFacts);
  Candidate := Default(TWaitFacts);
  Result := False;
  if (Nodes = nil) or (NodeCount < 2) or
     (NodeCount > WCT_MAX_NODE_COUNT) or
     (TargetPID = 0) or (RootTID = 0) then Exit;
  Span := NativeUInt(NodeCount) * SizeOf(TWaitChainNode);
  if NativeUInt(Nodes) > High(NativeUInt) - Span then Exit;
  try
    // The owner supplies a completed callback buffer. Work on one bounded
    // copy, and publish Facts only after the entire chain has been checked.
    Move(Nodes^, Local[0], NativeInt(Span));
    if not ValidateRootThread then Exit;
    if not ClassifyValidatedNodes then Exit;
    Candidate.Cycle := Cycle;
    Facts := Candidate;
    Result := True;
  except
    Facts := Default(TWaitFacts);
    Result := False;
  end;
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.WaitChainRules.inc}
{$ENDIF}

end.
