unit Cozy.NHW.Validation.Process;

interface

uses
  Winapi.Windows, System.SysUtils;

{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Validation requires Delphi Win64.'}
{$ENDIF}
{$ALIGN 8}

type
  TValidationSample = record
    PrivateBytes, WorkingSetBytes, Cpu100ns: UInt64;
    Handles: Cardinal;
  end;

  TValidationMetrics = record
    Samples, FailedSamples: UInt64;
    First, Last, Maximum, WarmBaseline: TValidationSample;
    HasWarmBaseline: Boolean;
  end;

  TValidationRun = record
    Started, Exited, TimedOut, DurationReached, Cancelled: Boolean;
    GracefulSignalSent, ForcedTermination, DescendantsForced: Boolean;
    JobDrained, OutputTruncated, OutputReadError: Boolean;
    ExitCode, NativeError: Cardinal;
    ElapsedMS: UInt64;
    ErrorText: string;
    Output: RawByteString;
    Metrics: TValidationMetrics;
  end;

procedure RequestValidationStop;
function ValidationStopRequested: Boolean;
function RunValidationChild(const Exe, Arguments: string;
  DurationMS: Cardinal; SoakMode: Boolean): TValidationRun;

implementation

const
  OUTPUT_LIMIT = 262144;
  GRACE_MS = 10000;
  JOB_DRAIN_MS = 5000;

type
  // Explicit ABI layouts avoid depending on optional PsAPI RTL aliases.
  TValidationMemoryCounters = record
    Size, PageFaultCount: Cardinal;
    PeakWorkingSet, WorkingSet, PeakPaged, Paged, PeakNonPaged,
      NonPaged, Pagefile, PeakPagefile, PrivateUsage: NativeUInt;
  end;
  TValidationBasicJobLimits = record
    ProcessUserTime, JobUserTime: Int64;
    Flags: Cardinal;
    MinWorkingSet, MaxWorkingSet: NativeUInt;
    ActiveProcessLimit: Cardinal;
    Affinity: NativeUInt;
    PriorityClass, SchedulingClass: Cardinal;
  end;
  TValidationJobLimits = record
    Basic: TValidationBasicJobLimits;
    ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes: UInt64;
    ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory: NativeUInt;
  end;
  TValidationJobAccounting = record
    UserTime, KernelTime, PeriodUserTime, PeriodKernelTime: Int64;
    PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses: Cardinal;
  end;

  TValidationChild = class
  private
    FProcess, FThread, FReadPipe, FWritePipe, FInput, FJob: THandle;
    FProcessID: Cardinal;
    FOutput: RawByteString;
    FTruncated, FReadError: Boolean;
    procedure CloseOwned(var Handle: THandle);
    function WaitMS(MS: Cardinal): Cardinal;
  public
    destructor Destroy; override;
    function Start(const Exe, Arguments: string; out NativeError: Cardinal;
      out ErrorText: string): Boolean;
    procedure PumpOutput;
    function ReadSample(out Sample: TValidationSample): Boolean;
    procedure StopOwned(var R: TValidationRun);
    function DrainJob(out Forced: Boolean): Boolean;
    property ProcessHandle: THandle read FProcess;
    property Output: RawByteString read FOutput;
    property Truncated: Boolean read FTruncated;
    property ReadError: Boolean read FReadError;
  end;

function VGetProcessMemoryInfo(Process: THandle; Counters: Pointer;
  Size: Cardinal): BOOL; stdcall; external 'psapi.dll' name 'GetProcessMemoryInfo';
function VGetProcessHandleCount(Process: THandle; var Count: Cardinal): BOOL; stdcall;
  external 'kernel32.dll' name 'GetProcessHandleCount';
function VSetJobInfo(Job: THandle; InfoClass: Integer; Data: Pointer;
  Size: Cardinal): BOOL; stdcall; external 'kernel32.dll' name 'SetInformationJobObject';
function VQueryJobInfo(Job: THandle; InfoClass: Integer; Data: Pointer;
  Size: Cardinal; ReturnLength: Pointer): BOOL; stdcall;
  external 'kernel32.dll' name 'QueryInformationJobObject';

var
  GValidationStop: LongInt = 0;

procedure RequestValidationStop;
begin
  InterlockedExchange(GValidationStop, 1);
end;

function ValidationStopRequested: Boolean;
begin
  Result := InterlockedCompareExchange(GValidationStop, 0, 0) <> 0;
end;

procedure TValidationChild.CloseOwned(var Handle: THandle);
begin
  if (Handle <> 0) and (Handle <> INVALID_HANDLE_VALUE) then
    CloseHandle(Handle);
  Handle := 0;
end;

function TValidationChild.WaitMS(MS: Cardinal): Cardinal;
begin
  if FProcess = 0 then Exit(WAIT_FAILED);
  Result := WaitForSingleObject(FProcess, MS);
end;

destructor TValidationChild.Destroy;
begin
  // This object owns only processes it created. Never kill by a looked-up PID.
  if (FProcess <> 0) and (WaitMS(0) <> WAIT_OBJECT_0) then
  begin
    if FJob <> 0 then TerminateJobObject(FJob, ERROR_PROCESS_ABORTED);
    TerminateProcess(FProcess, ERROR_PROCESS_ABORTED);
    WaitMS(5000);
  end;
  // KILL_ON_JOB_CLOSE also contains an observer child on an exceptional exit.
  CloseOwned(FJob);
  CloseOwned(FThread);
  CloseOwned(FProcess);
  CloseOwned(FInput);
  CloseOwned(FWritePipe);
  CloseOwned(FReadPipe);
  inherited;
end;

function TValidationChild.Start(const Exe, Arguments: string;
  out NativeError: Cardinal; out ErrorText: string): Boolean;
var
  SA: TSecurityAttributes;
  SI: TStartupInfoW;
  PI: TProcessInformation;
  Limits: TValidationJobLimits;
  Command, WorkDir: string;
begin
  Result := False;
  NativeError := 0;
  ErrorText := '';
  if (SizeOf(TValidationMemoryCounters) <> 80) or
     (SizeOf(TValidationJobLimits) <> 144) or
     (SizeOf(TValidationJobAccounting) <> 48) then
  begin
    NativeError := ERROR_BAD_FORMAT;
    ErrorText := 'Win64 validation ABI mismatch';
    Exit;
  end;
  if not FileExists(Exe) then
  begin
    NativeError := ERROR_FILE_NOT_FOUND;
    ErrorText := 'Missing executable; build the full project group first';
    Exit;
  end;
  SA := Default(TSecurityAttributes);
  SA.nLength := SizeOf(SA);
  SA.bInheritHandle := True;
  if not CreatePipe(FReadPipe, FWritePipe, @SA, 0) then
  begin
    NativeError := GetLastError; ErrorText := 'CreatePipe'; Exit;
  end;
  if not SetHandleInformation(FReadPipe, HANDLE_FLAG_INHERIT, 0) then
  begin
    NativeError := GetLastError; ErrorText := 'Pipe inheritance'; Exit;
  end;
  FInput := CreateFileW('NUL', GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_WRITE, @SA, OPEN_EXISTING, 0, 0);
  if FInput = INVALID_HANDLE_VALUE then
  begin
    NativeError := GetLastError; ErrorText := 'Open NUL input'; Exit;
  end;
  FJob := CreateJobObjectW(nil, nil); // handle is not inherited
  if FJob = 0 then
  begin
    NativeError := GetLastError; ErrorText := 'Create owned job'; Exit;
  end;
  Limits := Default(TValidationJobLimits);
  Limits.Basic.Flags := $00002000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
  if not VSetJobInfo(FJob, 9, @Limits, SizeOf(Limits)) then
  begin
    NativeError := GetLastError; ErrorText := 'Set owned job limits'; Exit;
  end;
  SI := Default(TStartupInfoW);
  SI.cb := SizeOf(SI);
  SI.dwFlags := STARTF_USESTDHANDLES;
  SI.hStdInput := FInput;
  SI.hStdOutput := FWritePipe;
  SI.hStdError := FWritePipe;
  PI := Default(TProcessInformation);
  Command := '"' + Exe + '"';
  if Arguments <> '' then Command := Command + ' ' + Arguments;
  UniqueString(Command); // CreateProcessW can modify its command-line buffer.
  WorkDir := ExtractFileDir(Exe);
  if not CreateProcessW(PWideChar(Exe), PWideChar(Command), nil, nil, True,
    CREATE_SUSPENDED or CREATE_NEW_PROCESS_GROUP, nil, PWideChar(WorkDir), SI, PI) then
  begin
    NativeError := GetLastError; ErrorText := 'CreateProcessW'; Exit;
  end;
  FProcess := PI.hProcess;
  FThread := PI.hThread;
  FProcessID := PI.dwProcessId;
  // Assign before user code runs, including any observer process creation.
  if not AssignProcessToJobObject(FJob, FProcess) then
  begin
    NativeError := GetLastError;
    ErrorText := 'Assign owned job (no uncontained fallback)';
    Exit;
  end;
  CloseOwned(FWritePipe);
  CloseOwned(FInput);
  if ResumeThread(FThread) = High(Cardinal) then
  begin
    NativeError := GetLastError; ErrorText := 'Resume owned child'; Exit;
  end;
  CloseOwned(FThread);
  Result := True;
end;

procedure TValidationChild.PumpOutput;
var
  Available, ReadCount, ToRead: Cardinal;
  Buffer: array[0..4095] of AnsiChar;
  I, OldLength, ToKeep: Integer;
begin
  if FReadPipe = 0 then Exit;
  // Bound time spent on output: a noisy child cannot block deadline checks.
  for I := 1 to 16 do
  begin
    if not PeekNamedPipe(FReadPipe, nil, 0, nil, @Available, nil) then
    begin
      if GetLastError <> ERROR_BROKEN_PIPE then FReadError := True;
      CloseOwned(FReadPipe);
      Exit;
    end;
    if Available = 0 then Exit;
    ToRead := Available;
    if ToRead > Cardinal(SizeOf(Buffer)) then ToRead := SizeOf(Buffer);
    ReadCount := 0;
    if not ReadFile(FReadPipe, Buffer, ToRead, ReadCount, nil) then
    begin
      if GetLastError <> ERROR_BROKEN_PIPE then FReadError := True;
      CloseOwned(FReadPipe);
      Exit;
    end;
    if ReadCount = 0 then Exit;
    OldLength := Length(FOutput);
    ToKeep := Integer(ReadCount);
    if ToKeep > OUTPUT_LIMIT - OldLength then
    begin
      ToKeep := OUTPUT_LIMIT - OldLength;
      FTruncated := True;
    end;
    if ToKeep > 0 then
    begin
      SetLength(FOutput, OldLength + ToKeep);
      Move(Buffer[0], FOutput[OldLength + 1], ToKeep);
    end;
  end;
end;

function TValidationChild.ReadSample(out Sample: TValidationSample): Boolean;
var
  M: TValidationMemoryCounters;
  Created, Ended, Kernel, User: TFileTime;
  KernelTicks, UserTicks: UInt64;
  Handles: Cardinal;
begin
  Result := False;
  Sample := Default(TValidationSample);
  M := Default(TValidationMemoryCounters);
  M.Size := SizeOf(M);
  if not VGetProcessMemoryInfo(FProcess, @M, SizeOf(M)) then Exit;
  Handles := 0;
  if not VGetProcessHandleCount(FProcess, Handles) then Exit;
  if not GetProcessTimes(FProcess, Created, Ended, Kernel, User) then Exit;
  KernelTicks := (UInt64(Kernel.dwHighDateTime) shl 32) or Kernel.dwLowDateTime;
  UserTicks := (UInt64(User.dwHighDateTime) shl 32) or User.dwLowDateTime;
  if KernelTicks > High(UInt64) - UserTicks then Exit;
  Sample.PrivateBytes := M.PrivateUsage;
  Sample.WorkingSetBytes := M.WorkingSet;
  Sample.Handles := Handles;
  Sample.Cpu100ns := KernelTicks + UserTicks;
  Result := True;
end;

procedure TValidationChild.StopOwned(var R: TValidationRun);
var
  Began: UInt64;
  Status: Cardinal;
begin
  if WaitMS(0) = WAIT_OBJECT_0 then Exit;
  R.GracefulSignalSent := GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, FProcessID);
  Began := GetTickCount64;
  repeat
    PumpOutput;
    Status := WaitMS(25);
    if Status = WAIT_OBJECT_0 then Exit;
    if Status = WAIT_FAILED then Break;
  until GetTickCount64 - Began >= GRACE_MS;
  R.ForcedTermination := True;
  if not TerminateJobObject(FJob, ERROR_TIMEOUT) then
    TerminateProcess(FProcess, ERROR_TIMEOUT);
  Began := GetTickCount64;
  repeat
    PumpOutput;
    Status := WaitMS(25);
    if Status = WAIT_OBJECT_0 then Exit;
    if Status = WAIT_FAILED then Break;
  until GetTickCount64 - Began >= 5000;
end;

function TValidationChild.DrainJob(out Forced: Boolean): Boolean;
var
  A: TValidationJobAccounting;
  Started: UInt64;
begin
  Result := False;
  Forced := False;
  Started := GetTickCount64;
  repeat
    A := Default(TValidationJobAccounting);
    if not VQueryJobInfo(FJob, 1, @A, SizeOf(A), nil) then Exit;
    if A.ActiveProcesses = 0 then Exit(True);
    PumpOutput;
    Sleep(25);
  until GetTickCount64 - Started >= JOB_DRAIN_MS;
  Forced := True;
  if not TerminateJobObject(FJob, ERROR_PROCESS_ABORTED) then Exit;
  Started := GetTickCount64;
  repeat
    A := Default(TValidationJobAccounting);
    if not VQueryJobInfo(FJob, 1, @A, SizeOf(A), nil) then Exit;
    if A.ActiveProcesses = 0 then Exit(True);
    PumpOutput;
    Sleep(25);
  until GetTickCount64 - Started >= 5000;
end;

procedure AddSample(var M: TValidationMetrics; const S: TValidationSample;
  Elapsed: UInt64);
begin
  if M.Samples = 0 then M.First := S;
  M.Last := S;
  if S.PrivateBytes > M.Maximum.PrivateBytes then M.Maximum.PrivateBytes := S.PrivateBytes;
  if S.WorkingSetBytes > M.Maximum.WorkingSetBytes then M.Maximum.WorkingSetBytes := S.WorkingSetBytes;
  if S.Handles > M.Maximum.Handles then M.Maximum.Handles := S.Handles;
  if S.Cpu100ns > M.Maximum.Cpu100ns then M.Maximum.Cpu100ns := S.Cpu100ns;
  if not M.HasWarmBaseline and (Elapsed >= 30000) then
  begin
    M.WarmBaseline := S;
    M.HasWarmBaseline := True;
  end;
  Inc(M.Samples);
end;

function RunValidationChild(const Exe, Arguments: string;
  DurationMS: Cardinal; SoakMode: Boolean): TValidationRun;
var
  Child: TValidationChild;
  StartTick, NowTick, LastSample, LastProgress, Elapsed: UInt64;
  Status: Cardinal;
  Sample: TValidationSample;
  I: Integer;
begin
  Result := Default(TValidationRun);
  Result.ExitCode := High(Cardinal);
  Child := TValidationChild.Create;
  try
    if DurationMS = 0 then
    begin
      Result.ErrorText := 'Duration must be positive';
      Exit;
    end;
    if not Child.Start(Exe, Arguments, Result.NativeError, Result.ErrorText) then Exit;
    Result.Started := True;
    StartTick := GetTickCount64;
    LastSample := StartTick;
    LastProgress := StartTick;
    repeat
      Child.PumpOutput;
      Status := WaitForSingleObject(Child.ProcessHandle, 25);
      if Status = WAIT_OBJECT_0 then Break;
      if Status = WAIT_FAILED then
      begin
        Result.NativeError := GetLastError;
        Result.ErrorText := 'WaitForSingleObject';
        Break;
      end;
      NowTick := GetTickCount64;
      Elapsed := NowTick - StartTick;
      if ValidationStopRequested then
      begin
        Result.Cancelled := True;
        Break;
      end;
      if SoakMode and (((Result.Metrics.Samples = 0) and (Result.Metrics.FailedSamples = 0)) or
        (NowTick - LastSample >= 1000)) then
      begin
        LastSample := NowTick;
        if Child.ReadSample(Sample) then AddSample(Result.Metrics, Sample, Elapsed)
        else Inc(Result.Metrics.FailedSamples);
      end;
      if SoakMode and (NowTick - LastProgress >= 60000) then
      begin
        LastProgress := NowTick;
        Writeln('SOAK progress: elapsed_seconds=', Elapsed div 1000,
          ' samples=', Result.Metrics.Samples,
          ' private_bytes=', Result.Metrics.Last.PrivateBytes,
          ' handles=', Result.Metrics.Last.Handles);
      end;
      if Elapsed >= DurationMS then
      begin
        Result.DurationReached := SoakMode;
        Result.TimedOut := not SoakMode;
        Break;
      end;
    until False;
    Child.StopOwned(Result);
    Result.Exited := WaitForSingleObject(Child.ProcessHandle, 0) = WAIT_OBJECT_0;
    if Result.Exited then
      if not GetExitCodeProcess(Child.ProcessHandle, Result.ExitCode) then
      begin
        Result.NativeError := GetLastError;
        Result.ErrorText := 'GetExitCodeProcess';
      end;
    Result.JobDrained := Child.DrainJob(Result.DescendantsForced);
    // Pipe capacity is bounded by the OS; do not wait for EOF from a stuck child.
    for I := 1 to 4 do Child.PumpOutput;
    Result.Output := Child.Output;
    Result.OutputTruncated := Child.Truncated;
    Result.OutputReadError := Child.ReadError;
    Result.ElapsedMS := GetTickCount64 - StartTick;
  finally
    Child.Free;
  end;
end;

end.
