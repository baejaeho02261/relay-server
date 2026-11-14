unit Cozy.NHW.ETWNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.WinPointers;

const
  ETW_REAL_TIME_MODE = $00000100;
  ETW_SYSTEM_LOGGER_MODE = $02000000;
  ETW_PROCESS_FLAG = $00000001;
  ETW_THREAD_FLAG = $00000002;
  ETW_IMAGE_LOAD_FLAG = $00000004;
  ETW_REGISTRY_FLAG = $00020000;
  ETW_FILE_IO_FLAG = $02000000;
  ETW_FILE_IO_INIT_FLAG = $04000000;
  ETW_WNODE_TRACED_GUID = $00020000;
  ETW_RECORD_MODE = $10000000;
  ETW_TRACE_CONTROL_QUERY = 0;
  ETW_TRACE_CONTROL_STOP = 1;
  ETW_INVALID_HANDLE = High(UInt64);

type
  // Each record is x64 C ABI aligned. Validate sizes before use.
  TEtwWnodeHeader = record
    BufferSize: Cardinal;
    ProviderId: Cardinal;
    HistoricalContext: UInt64;
    TimeStamp: Int64;
    Guid: TGUID;
    ClientContext: Cardinal;
    Flags: Cardinal;
  end;

  TEtwTraceProperties = record
    Wnode: TEtwWnodeHeader;
    BufferSize: Cardinal;
    MinimumBuffers: Cardinal;
    MaximumBuffers: Cardinal;
    MaximumFileSize: Cardinal;
    LogFileMode: Cardinal;
    FlushTimer: Cardinal;
    EnableFlags: Cardinal;
    AgeLimit: LongInt;
    NumberOfBuffers: Cardinal;
    FreeBuffers: Cardinal;
    EventsLost: Cardinal;
    BuffersWritten: Cardinal;
    LogBuffersLost: Cardinal;
    RealTimeBuffersLost: Cardinal;
    LoggerThreadId: THandle;
    LogFileNameOffset: Cardinal;
    LoggerNameOffset: Cardinal;
  end;
  PEtwTraceProperties = ^TEtwTraceProperties;

  TEtwDescriptor = record
    Id: Word;
    Version: Byte;
    Channel: Byte;
    Level: Byte;
    Opcode: Byte;
    Task: Word;
    Keyword: UInt64;
  end;

  TEtwHeader = record
    Size: Word;
    HeaderType: Word;
    Flags: Word;
    EventProperty: Word;
    ThreadId: Cardinal;
    ProcessId: Cardinal;
    TimeStamp: Int64;
    ProviderId: TGUID;
    Descriptor: TEtwDescriptor;
    ProcessorTime: UInt64;
    ActivityId: TGUID;
  end;

  PEtwEventRecord = ^TEtwEventRecord;
  TEtwEventRecord = record
    Header: TEtwHeader;
    BufferContext: Cardinal;
    ExtendedDataCount: Word;
    UserDataLength: Word;
    ExtendedData: Pointer;
    UserData: Pointer;
    UserContext: Pointer;
  end;

  TEtwClassicTraceHeader = record
    Size: Word;
    FieldTypeFlags: Word;
    Version: Cardinal;
    ThreadId: Cardinal;
    ProcessId: Cardinal;
    TimeStamp: Int64;
    Guid: TGUID;
    ProcessorTime: UInt64;
  end;

  TEtwClassicTrace = record
    Header: TEtwClassicTraceHeader;
    InstanceId: Cardinal;
    ParentInstanceId: Cardinal;
    ParentGuid: TGUID;
    MofData: Pointer;
    MofLength: Cardinal;
    ClientContext: Cardinal;
  end;

  TEtwLogfileHeader = record
    BufferSize: Cardinal;
    Version: Cardinal;
    ProviderVersion: Cardinal;
    NumberOfProcessors: Cardinal;
    EndTime: Int64;
    TimerResolution: Cardinal;
    MaximumFileSize: Cardinal;
    LogFileMode: Cardinal;
    BuffersWritten: Cardinal;
    // Same C union as LogInstanceGuid; [2] is EventsLost.
    LogInstanceCounters: array[0..3] of Cardinal;
    // TIME_ZONE_INFORMATION (172 bytes) / pointer union (16 bytes),
    // with x64 union padding to 176 bytes.
    TimeZoneUnion: array[0..175] of Byte;
    BootTime: Int64;
    PerfFreq: Int64;
    StartTime: Int64;
    ReservedFlags: Cardinal;
    BuffersLost: Cardinal;
  end;

  PEtwTraceLogfileW = ^TEtwTraceLogfileW;
  TEtwTraceLogfileW = record
    LogFileName: PWideChar;
    LoggerName: PWideChar;
    CurrentTime: Int64;
    BuffersRead: Cardinal;
    ProcessTraceMode: Cardinal;
    CurrentEvent: TEtwClassicTrace;
    LogfileHeader: TEtwLogfileHeader;
    BufferCallback: Pointer;
    BufferSize: Cardinal;
    Filled: Cardinal;
    EventsLost: Cardinal;
    EventRecordCallback: Pointer;
    IsKernelTrace: Cardinal;
    Context: Pointer;
  end;

  TEtwPropertyDescriptor = record
    PropertyName: UInt64;
    ArrayIndex: Cardinal;
    Reserved: Cardinal;
  end;

  TStartTraceW = function(var Session: UInt64; Name: PWideChar;
    Props: PEtwTraceProperties): Cardinal; stdcall;
  TControlTraceW = function(Session: UInt64; Name: PWideChar;
    Props: PEtwTraceProperties; Command: Cardinal): Cardinal; stdcall;
  TOpenTraceW = function(Logfile: PEtwTraceLogfileW): UInt64; stdcall;
  TProcessTrace = function(Handles: PUInt64; Count: Cardinal;
    StartTime, EndTime: Pointer): Cardinal; stdcall;
  TCloseTrace = function(Handle: UInt64): Cardinal; stdcall;
  TTdhGetPropertySize = function(Rec: PEtwEventRecord;
    ContextCount: Cardinal; Context: Pointer;
    PropertyCount: Cardinal; PropertyDescriptor: Pointer;
    var Required: Cardinal): Cardinal; stdcall;
  TTdhGetProperty = function(Rec: PEtwEventRecord;
    ContextCount: Cardinal; Context: Pointer;
    PropertyCount: Cardinal; PropertyDescriptor: Pointer;
    BufferSize: Cardinal; Buffer: PByte): Cardinal; stdcall;

var
  EtwStartTrace: TStartTraceW = nil;
  EtwControlTrace: TControlTraceW = nil;
  EtwOpenTrace: TOpenTraceW = nil;
  EtwProcessTrace: TProcessTrace = nil;
  EtwCloseTrace: TCloseTrace = nil;
  EtwPropertySize: TTdhGetPropertySize = nil;
  EtwGetProperty: TTdhGetProperty = nil;

function ResolveETW: Boolean;
function EtwAbiValid: Boolean;
function ReadEtwUInt(Rec: PEtwEventRecord; const PropName: string;
  out V: Cardinal): Boolean;
function ReadEtwText(Rec: PEtwEventRecord; const PropName: string;
  out S: string): Boolean;

{$IFDEF NHW_NATIVE5_TESTS}
function TestETWNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.NativeSafety,
  Cozy.NHW.ETW.PropertyDecoders;

var
  ETWLock: TCriticalSection;
  ETWReady: Boolean = False;
  AdvModule, SecModule, TdhModule: HMODULE;

function EtwAbiValid: Boolean;
begin
  Result := (SizeOf(TEtwWnodeHeader) = 48) and
    (SizeOf(TEtwTraceProperties) = 120) and
    (SizeOf(TEtwDescriptor) = 16) and
    (SizeOf(TEtwHeader) = 80) and
    (SizeOf(TEtwEventRecord) = 112) and
    (SizeOf(TEtwClassicTrace) = 88) and
    (SizeOf(TEtwLogfileHeader) = 264) and
    (SizeOf(TEtwTraceLogfileW) = 432) and
    (SizeOf(TEtwPropertyDescriptor) = 16);
end;

function ResolveETW: Boolean;
var
  StartFn: TStartTraceW;
  ControlFn: TControlTraceW;
  OpenFn: TOpenTraceW;
  ProcessFn: TProcessTrace;
  CloseFn: TCloseTrace;
  SizeFn: TTdhGetPropertySize;
  PropertyFn: TTdhGetProperty;
  procedure KeepModule(const Name: string; var M: HMODULE);
  begin
    if M <> 0 then Exit;
    // One owned reference per module; borrowed handles do not prevent unload.
    M := WinLoadLibrary(Name);
  end;
  function FindEtw(const Name: AnsiString): Pointer;
  begin
    Result := WinExport(AdvModule, Name);
    if Result = nil then Result := WinExport(SecModule, Name);
  end;
begin
  Result := False;
  if not EtwAbiValid then Exit;
  ETWLock.Acquire;
  try
    if ETWReady then Exit(True);
    KeepModule('advapi32.dll', AdvModule);
    KeepModule('sechost.dll', SecModule);
    KeepModule('tdh.dll', TdhModule);
    if ((AdvModule = 0) and (SecModule = 0)) or (TdhModule = 0) then Exit;
    StartFn := TStartTraceW(FindEtw('StartTraceW'));
    ControlFn := TControlTraceW(FindEtw('ControlTraceW'));
    OpenFn := TOpenTraceW(FindEtw('OpenTraceW'));
    ProcessFn := TProcessTrace(FindEtw('ProcessTrace'));
    CloseFn := TCloseTrace(FindEtw('CloseTrace'));
    SizeFn := TTdhGetPropertySize(WinExport(TdhModule, 'TdhGetPropertySize'));
    PropertyFn := TTdhGetProperty(WinExport(TdhModule, 'TdhGetProperty'));
    if not (Assigned(StartFn) and Assigned(ControlFn) and Assigned(OpenFn) and
      Assigned(ProcessFn) and Assigned(CloseFn) and Assigned(SizeFn) and
      Assigned(PropertyFn)) then Exit;
    // Publish once, only after the entire table is usable. A call made before
    // bootstrap does not permanently mark this resolver as unavailable.
    EtwStartTrace := StartFn;
    EtwControlTrace := ControlFn;
    EtwOpenTrace := OpenFn;
    EtwProcessTrace := ProcessFn;
    EtwCloseTrace := CloseFn;
    EtwPropertySize := SizeFn;
    EtwGetProperty := PropertyFn;
    ETWReady := True;
    Result := True;
  finally
    ETWLock.Release;
  end;
end;

function EtwRecordValid(Rec: PEtwEventRecord): Boolean;
begin
  Result := False;
  if not NHWAddressSpan(NativeUInt(Rec), SizeOf(TEtwEventRecord)) then Exit;
  if Rec^.Header.Size < SizeOf(TEtwHeader) then Exit;
  if Rec^.UserDataLength <> 0 then
    if not NHWAddressSpan(NativeUInt(Rec^.UserData), Rec^.UserDataLength) then Exit;
  if Rec^.ExtendedDataCount <> 0 then
    if not NHWAddressSpan(NativeUInt(Rec^.ExtendedData),
      NativeUInt(Rec^.ExtendedDataCount) * NativeUInt(16)) then Exit;
  Result := True;
end;

function ReadEtwBytes(Rec: PEtwEventRecord; const PropName: string;
  out Data: TBytes): Boolean;
var
  D: TEtwPropertyDescriptor;
  Required, Status: Cardinal;
  Attempt: Integer;
begin
  Result := False;
  Data := nil;
  if not EtwRecordValid(Rec) or not Assigned(EtwPropertySize) or
     not Assigned(EtwGetProperty) then Exit;
  if (PropName = '') or (Length(PropName) > 1024) or (Pos(#0, PropName) <> 0) then Exit;
  D := Default(TEtwPropertyDescriptor);
  D.PropertyName := UInt64(NativeUInt(PWideChar(PropName)));
  D.ArrayIndex := High(Cardinal);
  try
    for Attempt := 1 to 2 do
    begin
      Required := 0;
      if EtwPropertySize(Rec, 0, nil, 1, @D, Required) <> 0 then Exit;
      if (Required = 0) or (Required > 4096) then Exit;
      SetLength(Data, Integer(Required));
      FillChar(Data[0], Length(Data), 0);
      Status := EtwGetProperty(Rec, 0, nil, 1, @D, Required, @Data[0]);
      if Status = 0 then Exit(True);
      if Status <> ERROR_INSUFFICIENT_BUFFER then Exit;
      Data := nil; // Requery the size once; never return a half-filled property.
    end;
  finally
    if not Result then Data := nil;
  end;
end;

function ReadEtwUInt(Rec: PEtwEventRecord; const PropName: string;
  out V: Cardinal): Boolean;
var
  B: TBytes;
begin
  V := 0;
  Result := False;
  if not ReadEtwBytes(Rec, PropName, B) then Exit;
  Result := DecodeEtwUInt(B, V);
end;

function ReadEtwText(Rec: PEtwEventRecord; const PropName: string;
  out S: string): Boolean;
var B: TBytes;
begin
  S := '';
  Result := False;
  if not ReadEtwBytes(Rec, PropName, B) then Exit;
  Result := DecodeEtwText(B, S);
end;

{$IFDEF NHW_NATIVE5_TESTS}
  {$I Cozy.NHW.Native5.ETW.inc}
{$ENDIF}
initialization
  ETWLock := TCriticalSection.Create;
finalization
  ETWLock.Free;
end.
