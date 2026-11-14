unit Cozy.NHW.Threads;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.Generics.Collections;

// The caller owns this list exclusively until capture/release completes.
// A successful capture owns every listed handle until the handle snapshot ends.
// False or an exception leaves no partial reference set behind.
function CaptureThreadReferences(TargetPID: Cardinal;
  References: TList<THandle>): Boolean;
procedure ReleaseThreadReferences(References: TList<THandle>);

{$IFDEF NHW_NATIVE5C_TESTS}
function TestThreadsHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils,
  Cozy.NHW.Types,
  Cozy.NHW.Native;

type
  TReferenceOpen = function(PID, Rights: Cardinal): THandle;
  TReferenceNext = function(ProcessHandle, Previous: THandle;
    Rights: Cardinal; out Next: THandle): TNTStatus;
  TReferenceClose = procedure(var Handle: THandle);

procedure ReleaseReferencesCore(References: TList<THandle>;
  CloseHandle: TReferenceClose);
var
  I, J: Integer;
  H: THandle;
  Notify: TCollectionNotifyEvent<THandle>;
begin
  if References = nil then Exit;
  // Cleanup must neither allocate memory nor re-enter a caller notification.
  // A malformed caller list can contain duplicates: close each value once.
  Notify := References.OnNotify;
  References.OnNotify := nil;
  try
    for I := 0 to References.Count - 1 do
    begin
      H := References[I];
      References[I] := 0;
      if (H = 0) or (H = THandle(High(NativeUInt))) then Continue;
      for J := I + 1 to References.Count - 1 do
        if References[J] = H then References[J] := 0;
      CloseHandle(H);
    end;
    References.Clear;
  finally
    References.OnNotify := Notify;
  end;
end;

procedure ReleaseThreadReferences(References: TList<THandle>);
begin
  ReleaseReferencesCore(References, CloseNativeProcess);
end;

function CaptureReferencesCore(TargetPID: Cardinal;
  References: TList<THandle>; Available: Boolean;
  OpenProcess: TReferenceOpen; Next: TReferenceNext;
  CloseHandle: TReferenceClose): Boolean;
var
  ProcessHandle, PrevThread, NextThread: THandle;
  BeforeCount: Integer;
  Status: TNTStatus;
begin
  Result := False;
  if References = nil then Exit;
  ReleaseReferencesCore(References, CloseHandle);
  if (TargetPID = 0) or not Available then Exit;
  ProcessHandle := 0;
  PrevThread := 0;
  NextThread := 0;
  try
    ProcessHandle := OpenProcess(TargetPID, ACCESS_QUERY_INFORMATION);
    if (ProcessHandle = 0) or
       (ProcessHandle = THandle(High(NativeUInt))) then
    begin
      ProcessHandle := 0;
      Exit;
    end;
    while References.Count < MAX_TARGET_THREADS do
    begin
      NextThread := 0;
      Status := Next(ProcessHandle, PrevThread,
        THREAD_QUERY_LIMITED_INFORMATION_RIGHT, NextThread);
      if Status <> 0 then
      begin
        // Only explicit normal end WITH NO new handle proves completion.
        Result := (Cardinal(Status) = $8000001A) and (NextThread = 0);
        Break;
      end;
      if (NextThread = 0) or
         (NextThread = THandle(High(NativeUInt))) then
      begin
        NextThread := 0;
        Break;
      end;
      if References.IndexOf(NextThread) >= 0 then
      begin
        // Already owned by the list; never close the same value twice.
        NextThread := 0;
        Break;
      end;
      PrevThread := NextThread;
      BeforeCount := References.Count;
      try
        References.Add(NextThread);
      finally
        // Add can raise before insertion (allocation) or after insertion
        // (OnNotify). Transfer ownership only if the entry actually exists.
        if References.Count > BeforeCount then
          if References[BeforeCount] = NextThread then NextThread := 0;
      end;
    end;
  finally
    try
      // Includes a handle returned alongside an unexpected failure status.
      if NextThread <> 0 then
      begin
        if References.IndexOf(NextThread) >= 0 then NextThread := 0
        else CloseHandle(NextThread);
      end;
    finally
      try
        if ProcessHandle <> 0 then CloseHandle(ProcessHandle);
      finally
        if not Result then ReleaseReferencesCore(References, CloseHandle);
      end;
    end;
  end;
end;

function CaptureThreadReferences(TargetPID: Cardinal;
  References: TList<THandle>): Boolean;
begin
  // Failure must not disable the original process-handle monitor.
  Result := CaptureReferencesCore(TargetPID, References,
    NativeThreadEnumerationAvailable, OpenNativeProcess,
    GetNextNativeThread, CloseNativeProcess);
end;

{$IFDEF NHW_NATIVE5C_TESTS}
  {$I Cozy.NHW.Native5C.Threads.inc}
{$ENDIF}
end.
