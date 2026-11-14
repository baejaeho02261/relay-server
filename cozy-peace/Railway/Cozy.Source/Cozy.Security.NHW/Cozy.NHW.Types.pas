unit Cozy.NHW.Types;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils;

const
  ACCESS_TERMINATE = $0001;
  ACCESS_CREATE_THREAD = $0002;
  ACCESS_VM_OPERATION = $0008;
  ACCESS_VM_READ = $0010;
  ACCESS_VM_WRITE = $0020;
  ACCESS_DUP_HANDLE = $0040;
  ACCESS_CREATE_PROCESS = $0080;
  ACCESS_SET_QUOTA = $0100;
  ACCESS_SET_INFORMATION = $0200;
  ACCESS_QUERY_INFORMATION = $0400;
  ACCESS_SUSPEND_RESUME = $0800;
  ACCESS_QUERY_LIMITED = $1000;
  ACCESS_READ_CONTROL = $00020000;
  ACCESS_DELETE = $00010000;
  ACCESS_WRITE_DAC = $00040000;
  ACCESS_WRITE_OWNER = $00080000;
  ACCESS_SYNCHRONIZE = $00100000;

  THREAD_TERMINATE_RIGHT = $0001;
  THREAD_SUSPEND_RESUME_RIGHT = $0002;
  THREAD_GET_CONTEXT_RIGHT = $0008;
  THREAD_SET_CONTEXT_RIGHT = $0010;
  THREAD_SET_INFORMATION_RIGHT = $0020;
  THREAD_QUERY_INFORMATION_RIGHT = $0040;
  THREAD_SET_THREAD_TOKEN_RIGHT = $0080;
  THREAD_IMPERSONATE_RIGHT = $0100;
  THREAD_DIRECT_IMPERSONATION_RIGHT = $0200;
  THREAD_SET_LIMITED_INFORMATION_RIGHT = $0400;
  THREAD_QUERY_LIMITED_INFORMATION_RIGHT = $0800;

  PROCESS_SIGNIFICANT_RIGHTS = ACCESS_TERMINATE or ACCESS_CREATE_THREAD or
    ACCESS_VM_OPERATION or ACCESS_VM_READ or ACCESS_VM_WRITE or
    ACCESS_DUP_HANDLE or ACCESS_CREATE_PROCESS or ACCESS_SET_QUOTA or
    ACCESS_SET_INFORMATION or ACCESS_SUSPEND_RESUME or ACCESS_DELETE or
    ACCESS_WRITE_DAC or ACCESS_WRITE_OWNER;
  PROCESS_QUERY_RIGHTS = ACCESS_QUERY_INFORMATION or ACCESS_QUERY_LIMITED or
    ACCESS_READ_CONTROL;
  THREAD_SIGNIFICANT_RIGHTS = THREAD_TERMINATE_RIGHT or
    THREAD_SUSPEND_RESUME_RIGHT or THREAD_GET_CONTEXT_RIGHT or
    THREAD_SET_CONTEXT_RIGHT or THREAD_SET_INFORMATION_RIGHT or
    THREAD_SET_THREAD_TOKEN_RIGHT or THREAD_IMPERSONATE_RIGHT or
    THREAD_DIRECT_IMPERSONATION_RIGHT or THREAD_SET_LIMITED_INFORMATION_RIGHT or
    ACCESS_DELETE or ACCESS_WRITE_DAC or ACCESS_WRITE_OWNER;
  THREAD_QUERY_RIGHTS = THREAD_QUERY_INFORMATION_RIGHT or
    THREAD_QUERY_LIMITED_INFORMATION_RIGHT or ACCESS_READ_CONTROL;

  MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;
  MAX_PROCESS_BYTES = 64 * 1024 * 1024;
  MAX_TARGET_THREADS = 4096;
  TRACK_RETENTION_MS = 15 * 60 * 1000;

type
  TIPCObjectKind = (ikNone, ikEvent, ikMutex, ikSemaphore, ikSection);
  TIPCObjectKinds = set of TIPCObjectKind;

  TIPCObservation = record
    OwnerPID: Cardinal;
    ObjectIdentity: NativeUInt; // opaque kernel identity, never dereferenced
    Kind: TIPCObjectKind;
    GrantedAccess: Cardinal;
  end;

  TOptions = record
    TargetPID: Cardinal;
    TargetName: string;
    PIDSpecified: Boolean;
    IgnorePID: Cardinal;
    IgnorePathPrefix: string;
    MissThreshold: Integer;
    BaselineScans: Integer;
    IntervalMS: Cardinal;
    SummaryMS: Cardinal;
    MinLevel: Integer;
    ThreadMinLevel: Integer;
    ThreadWatch: Boolean;
    ReportHandleCount: Boolean;
    Watch: Boolean;
    PauseOnExit: Boolean;
    Help: Boolean;
  end;

  TTargetHolder = record
    PID: Cardinal;
    CreateTime: UInt64;
    ImagePath: string;
    HandleCount: Integer;
    RightsUnion: Cardinal;
    RepresentativeRights: Cardinal;
    RepresentativeHandle: NativeUInt;
    Level: Integer;
    IsThread: Boolean;
    ObjectIdentity: NativeUInt; // opaque kernel object identity; NEVER dereference
  end;

  // Exact handle snapshot entry for correlating parent/child candidates.
  // ObjectIdentity is an opaque NT kernel address used ONLY for equality;
  // it is never dereferenced.
  TObservedHandle = record
    OwnerPID: Cardinal;
    ObjectIdentity: NativeUInt;
    HandleValue: NativeUInt;
    GrantedAccess: Cardinal;
    Attributes: Cardinal;
    IsThread: Boolean;
  end;

  // Token-object handle observation, not a token mutation or API-call trace.
  TObservedTokenHandle = record
    OwnerPID: Cardinal;
    TokenObject: NativeUInt;  // opaque kernel address; equality only
    GrantedAccess: Cardinal;
  end;

  TTrackState = record
    PID: Cardinal;
    CreateTime: UInt64;
    LastSeenTick: UInt64;
    MissingScans: Integer;
    LastLevel: Integer;
    LastRightsUnion: Cardinal;
    LastHandleCount: Integer;
    Active: Boolean;
    IsThread: Boolean;
  end;

  TObjectState = record
    LastOwnerCount: Integer;
    MultiOwnerActive: Boolean;
    LastSeenTick: UInt64;
  end;

  TScanStats = record
    ScanMS: UInt64;
    GapMS: UInt64;
  end;

function LevelForProcessRights(R: Cardinal): Integer;
function LevelForThreadRights(R: Cardinal): Integer;
function IdentityKey(const Holder: TTargetHolder): string;
function ObjectKey(const Holder: TTargetHolder): string;
function SignificantRights(const Holder: TTargetHolder): Cardinal;
function QueryRights(const Holder: TTargetHolder): Cardinal;

implementation

function LevelForProcessRights(R: Cardinal): Integer;
begin
  if (R and (ACCESS_VM_WRITE or ACCESS_VM_OPERATION or
      ACCESS_CREATE_THREAD)) <> 0 then Exit(3);
  if (R and (ACCESS_TERMINATE or ACCESS_DUP_HANDLE or
      ACCESS_CREATE_PROCESS or ACCESS_SET_INFORMATION or ACCESS_SET_QUOTA or
      ACCESS_SUSPEND_RESUME or ACCESS_DELETE or ACCESS_WRITE_DAC or
      ACCESS_WRITE_OWNER)) <> 0 then Exit(2);
  if (R and ACCESS_VM_READ) <> 0 then Exit(1);
  Result := 0;
end;

function LevelForThreadRights(R: Cardinal): Integer;
begin
  if (R and (THREAD_SET_CONTEXT_RIGHT or
      THREAD_DIRECT_IMPERSONATION_RIGHT)) <> 0 then Exit(3);
  if (R and (THREAD_TERMINATE_RIGHT or THREAD_SUSPEND_RESUME_RIGHT or
      THREAD_SET_INFORMATION_RIGHT or THREAD_SET_LIMITED_INFORMATION_RIGHT or
      THREAD_SET_THREAD_TOKEN_RIGHT or THREAD_IMPERSONATE_RIGHT or
      ACCESS_DELETE or ACCESS_WRITE_DAC or ACCESS_WRITE_OWNER)) <> 0 then Exit(2);
  if (R and THREAD_GET_CONTEXT_RIGHT) <> 0 then Exit(1);
  Result := 0;
end;

function IdentityKey(const Holder: TTargetHolder): string;
begin
  if Holder.IsThread then
    Result := 'T:' + IntToHex(UInt64(Holder.ObjectIdentity), 16) + ':'
  else
    Result := 'P:';
  Result := Result + IntToStr(Holder.PID) + ':' +
    IntToStr(Int64(Holder.CreateTime));
end;

function ObjectKey(const Holder: TTargetHolder): string;
begin
  if Holder.IsThread then
    Result := 'OT:' + IntToHex(UInt64(Holder.ObjectIdentity), 16)
  else if Holder.ObjectIdentity <> 0 then
    Result := 'OP:' + IntToHex(UInt64(Holder.ObjectIdentity), 16)
  else
    Result := 'OPID:' + IntToStr(Holder.PID);
end;

function SignificantRights(const Holder: TTargetHolder): Cardinal;
begin
  if Holder.IsThread then Result := THREAD_SIGNIFICANT_RIGHTS
  else Result := PROCESS_SIGNIFICANT_RIGHTS;
end;

function QueryRights(const Holder: TTargetHolder): Cardinal;
begin
  if Holder.IsThread then Result := THREAD_QUERY_RIGHTS
  else Result := PROCESS_QUERY_RIGHTS;
end;

end.
