unit Cozy.NHW.Observer.ChildRuntime;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows;

function TryRunObserverMode: Boolean;

implementation

uses
  System.SysUtils, Cozy.NHW.Observer.Protocol, Cozy.NHW.ObserverAuthenticator,
  Cozy.NHW.Observer.Launch;

function TryRunObserverMode: Boolean;
var
  Mapping, ProcessHandle: THandle;
  View: PObserverShared;
  ActualTime, Tick, Revision, OwnerTick: UInt64;
  E: TObserverSessionEvidence;
  M: TObserverSessionMAC;
  SessionKey: TObserverSessionKey;
  MappingFlags: DWORD;
begin
  { Consuming this command never enters license/bootstrap/overlay execution.
    Invalid or replayed capabilities terminate quietly with a nonzero code. }
  Result := (ParamCount > 0) and (ParamStr(1) = '--cozy-nhw-observer');
  if not Result then Exit;
  ExitCode := 1;
  if (ParamCount <> 3) or
    not ObserverHandleArgument(ParamStr(2), Mapping) or
    not ObserverHandleArgument(ParamStr(3), ProcessHandle) or
    (Mapping = ProcessHandle) then Exit;
  if not GetHandleInformation(Mapping, MappingFlags) or
    ((MappingFlags and HANDLE_FLAG_INHERIT) = 0) then Exit;
  try
    View := PObserverShared(Winapi.Windows.MapViewOfFile(Mapping,
      FILE_MAP_ALL_ACCESS, 0, 0, SizeOf(TObserverShared)));
    if View = nil then Exit;
    try
      if ((NativeUInt(@View^.ProofRevision) and 7) <> 0) or
         ((NativeUInt(@View^.OwnerTick) and 7) <> 0) or
         not ValidateObserverParent(ProcessHandle, View) then Exit;
      SetHandleInformation(Mapping, HANDLE_FLAG_INHERIT, 0);
      SetHandleInformation(ProcessHandle, HANDLE_FLAG_INHERIT, 0);
      SessionKey := View^.SessionKey;
      try
        try
          Revision := 0;
          while not ObserverStopped(View) do
          begin
            Tick := ObserverClockTick;
            OwnerTick := ObserverLoad64(View^.OwnerTick);
            if (Tick < OwnerTick) or (Tick - OwnerTick > OBSERVER_STALE_MS) or
               (Winapi.Windows.WaitForSingleObject(ProcessHandle, 0) <> WAIT_TIMEOUT) then Break;
            if Revision > UInt64(High(Int64)) - 2 then Break;
            Inc(Revision, 2);
            E := Default(TObserverSessionEvidence);
            E.Sequence := Revision;
            E.OwnerPID := View^.OwnerPID;
            E.ObserverPID := Winapi.Windows.GetCurrentProcessId;
            E.OwnerCreated := View^.OwnerCreated;
            E.ObservedTick := Tick;
            if QueryProcessCreation(ProcessHandle, ActualTime) then
            begin
              E.ObservedCreation := ActualTime;
              if ObserverIdentityMatches(E.OwnerPID, E.OwnerCreated,
                View^.OwnerPID, ActualTime) then E.State := 1
              else E.State := 2;
            end;
            // Full interlocked barriers bracket the payload. Ordinary stores
            // to Revision are not sufficient to implement a seqlock.
            ObserverStore64(View^.ProofRevision, Revision - 1);
            View^.ObserverPID := E.ObserverPID;
            View^.ObservedCreation := E.ObservedCreation;
            View^.State := E.State;
            View^.ObserverTick := E.ObservedTick;
            if NHWSessionMAC(SessionKey, E, M) then
            begin
              View^.ProofEvidence := E;
              View^.ProofMAC := M;
              ObserverStore64(View^.ProofRevision, Revision);
            end
            else
              ObserverStore64(View^.ProofRevision, 0);
            { Parent exit wakes promptly; the mapping stop flag is polled. }
            Winapi.Windows.WaitForSingleObject(ProcessHandle, OBSERVER_POLL_MS);
          end;
          ExitCode := 0;
        finally
          FillChar(M, SizeOf(M), 0);
        end;
      finally
        FillChar(SessionKey, SizeOf(SessionKey), 0);
      end;
    finally
      Winapi.Windows.UnmapViewOfFile(View);
    end;
  finally
    Winapi.Windows.CloseHandle(ProcessHandle);
    Winapi.Windows.CloseHandle(Mapping);
  end;
end;

end.
