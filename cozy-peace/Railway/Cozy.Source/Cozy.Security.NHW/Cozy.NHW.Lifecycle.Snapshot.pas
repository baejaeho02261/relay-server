unit Cozy.NHW.Lifecycle.Snapshot;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections;

type
  TThreadSample = record
    ThreadID: Cardinal;
    StartAddress: NativeUInt;
    ThreadState: Cardinal;
    WaitReason: Cardinal;
  end;

  // Logical process parentage, not proof of inherited handles.
  TProcessParentMap = TDictionary<Cardinal, Cardinal>;
  TThreadSampleMap = TDictionary<Cardinal, TThreadSample>;

function ReadSystemThreadSnapshot(TargetPID: Cardinal;
  Parents: TProcessParentMap; Threads: TThreadSampleMap): Boolean;
{$IFDEF NHW_NATIVE10M_TESTS}
function TestLifecycle10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.Native, Cozy.NHW.Types;

const
  // SystemProcessInformation structure is native and version-sensitive.
  // x64 byte layout from Windows SDK; checked before any pointer access.
  PROCESS_INFORMATION_X64_BYTES = 256;
  THREAD_INFORMATION_X64_BYTES = 80;
type
  PProcessInfoX64 = ^TProcessInfoX64;
  TProcessInfoX64 = record
    NextEntryOffset: Cardinal;
    NumberOfThreads: Cardinal;
    Reserved1: array[0..47] of Byte;
    ImageName: TNativeUnicode;
    BasePriority: LongInt;
    UniqueProcessId: THandle;
    InheritedFromUniqueProcessId: THandle;
    ReservedTail: array[0..159] of Byte;
  end;

  PThreadInfoX64 = ^TThreadInfoX64;
  TThreadInfoX64 = record
    Reserved1: array[0..2] of Int64;
    Reserved2: Cardinal;
    StartAddress: Pointer;
    ClientProcessId: THandle;
    ClientThreadId: THandle;
    Priority: LongInt;
    BasePriority: LongInt;
    Reserved3: Cardinal;
    ThreadState: Cardinal;
    WaitReason: Cardinal;
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.Lifecycle.Hooks.inc}
{$ENDIF}

function ParseSystemThreadSnapshot(const Data: TBytes; TargetPID: Cardinal;
  Parents: TProcessParentMap; Threads: TThreadSampleMap): Boolean;
var
  Offset, RecordLen, NextOffset, ThreadStart, Required: NativeUInt;
  BufLen: NativeUInt;
  P: PProcessInfoX64;
  ThreadPtr: PThreadInfoX64;
  CurrentPID, ParentPID, ThreadPID: NativeUInt;
  Info: TThreadSample;
  I: Cardinal;
  TargetFound: Boolean;
begin
  Result := False;
  if Parents <> nil then Parents.Clear;
  if Threads <> nil then Threads.Clear;
  if (Parents = nil) or (Threads = nil) or (TargetPID = 0) then Exit;
  try
    if (SizeOf(TProcessInfoX64) <> PROCESS_INFORMATION_X64_BYTES) or
       (SizeOf(TThreadInfoX64) <> THREAD_INFORMATION_X64_BYTES) then Exit;
    BufLen := NativeUInt(Length(Data));
    if BufLen < PROCESS_INFORMATION_X64_BYTES then Exit;
    Offset := 0;
    TargetFound := False;
    repeat
      if Offset > BufLen - PROCESS_INFORMATION_X64_BYTES then Exit;
      P := PProcessInfoX64(NativeUInt(@Data[0]) + Offset);
      NextOffset := P^.NextEntryOffset;
      if NextOffset = 0 then RecordLen := BufLen - Offset
      else
      begin
        if (NextOffset < PROCESS_INFORMATION_X64_BYTES) or
           (NextOffset > BufLen - Offset) then Exit;
        RecordLen := NextOffset;
      end;
      CurrentPID := NativeUInt(P^.UniqueProcessId);
      ParentPID := NativeUInt(P^.InheritedFromUniqueProcessId);
      if (CurrentPID > 0) and (CurrentPID <= High(Cardinal)) then
      begin
        if ParentPID <= High(Cardinal) then
          Parents.AddOrSetValue(Cardinal(CurrentPID), Cardinal(ParentPID));
        if CurrentPID = TargetPID then
        begin
          if TargetFound then Exit; // duplicate target process is inconsistent
          TargetFound := True;
          if P^.NumberOfThreads > MAX_TARGET_THREADS then Exit;
          ThreadStart := PROCESS_INFORMATION_X64_BYTES;
          Required := NativeUInt(P^.NumberOfThreads) * THREAD_INFORMATION_X64_BYTES;
          if (ThreadStart > RecordLen) or (Required > RecordLen - ThreadStart) then Exit;
          if P^.NumberOfThreads > 0 then
          for I := 0 to P^.NumberOfThreads - 1 do
          begin
            ThreadPtr := PThreadInfoX64(NativeUInt(P) + ThreadStart +
              NativeUInt(I) * THREAD_INFORMATION_X64_BYTES);
            ThreadPID := NativeUInt(ThreadPtr^.ClientThreadId);
            if (NativeUInt(ThreadPtr^.ClientProcessId) <> TargetPID) or
               (ThreadPID = 0) or (ThreadPID > High(Cardinal)) then Exit;
            Info := Default(TThreadSample);
            Info.ThreadID := Cardinal(ThreadPID);
            Info.StartAddress := NativeUInt(ThreadPtr^.StartAddress);
            Info.ThreadState := ThreadPtr^.ThreadState;
            Info.WaitReason := ThreadPtr^.WaitReason;
            if Threads.ContainsKey(Info.ThreadID) then Exit;
            {$IFDEF NHW_NATIVE10M_TESTS}
            if Lifecycle10MFailInsert then raise EOutOfMemory.Create('injected thread insertion');
            {$ENDIF}
            Threads.Add(Info.ThreadID, Info);
          end;
        end;
      end;
      if NextOffset = 0 then Break;
      Inc(Offset, NextOffset);
    until False;
    Result := TargetFound;
  finally
    if not Result then
    begin
      Parents.Clear;
      Threads.Clear;
    end;
  end;
end;

function ReadSystemThreadSnapshot(TargetPID: Cardinal;
  Parents: TProcessParentMap; Threads: TThreadSampleMap): Boolean;
var
  Data: TBytes;
  Failure: TNTStatus;
begin
  Result := False;
  if Parents <> nil then Parents.Clear;
  if Threads <> nil then Threads.Clear;
  if (Parents = nil) or (Threads = nil) or (TargetPID = 0) then Exit;
  if not FetchSystemData(SYSTEM_PROCESS_INFORMATION_CLASS,
    1024 * 1024, MAX_PROCESS_BYTES, Data, Failure) then Exit;
  Result := ParseSystemThreadSnapshot(Data, TargetPID, Parents, Threads);
end;


{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.Lifecycle.inc}
{$ENDIF}

end.
