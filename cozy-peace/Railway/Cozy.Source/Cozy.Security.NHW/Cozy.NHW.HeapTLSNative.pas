unit Cozy.NHW.HeapTLSNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils;

// Windows heap, TLS and FLS operations are resolved to function pointers.
// All pointers passed here belong to the current process and current thread.
function ResolveHeapTLSFunctions: Boolean;
function LocalThreadID: Cardinal;
function LocalTlsAlloc: Cardinal;
function LocalTlsSetValue(Index: Cardinal; Value: Pointer): Boolean;
function LocalTlsGetValue(Index: Cardinal): Pointer;
procedure LocalTlsFree(Index: Cardinal);
function LocalFlsAlloc(Callback: Pointer): Cardinal;
function LocalFlsSetValue(Index: Cardinal; Value: Pointer): Boolean;
function LocalFlsGetValue(Index: Cardinal): Pointer;
procedure LocalFlsFree(Index: Cardinal);
function LocalHeapCreate: THandle;
function LocalHeapAlloc(Heap: THandle; Bytes: NativeUInt): Pointer;
procedure LocalHeapFree(Heap: THandle; Block: Pointer);
procedure LocalHeapDestroy(var Heap: THandle);
function LocalHeapSnapshot(out Heaps: TArray<NativeUInt>): Boolean;

const
  INVALID_LOCAL_SLOT = Cardinal($FFFFFFFF);

{$IFDEF NHW_NATIVE5B_TESTS}
function TestHeapTLSNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.WinPointers;

type
  TTlsAllocFn = function: Cardinal; stdcall;
  TTlsFreeFn = function(Index: Cardinal): BOOL; stdcall;
  TTlsSetFn = function(Index: Cardinal; Value: Pointer): BOOL; stdcall;
  TTlsGetFn = function(Index: Cardinal): Pointer; stdcall;
  TFlsAllocFn = function(Callback: Pointer): Cardinal; stdcall;
  TFlsFreeFn = function(Index: Cardinal): BOOL; stdcall;
  TFlsSetFn = function(Index: Cardinal; Value: Pointer): BOOL; stdcall;
  TFlsGetFn = function(Index: Cardinal): Pointer; stdcall;
  THeapCreateFn = function(Flags: Cardinal; InitialSize, MaximumSize: NativeUInt): THandle; stdcall;
  THeapAllocFn = function(Heap: THandle; Flags: Cardinal; Size: NativeUInt): Pointer; stdcall;
  THeapFreeFn = function(Heap: THandle; Flags: Cardinal; Block: Pointer): BOOL; stdcall;
  THeapDestroyFn = function(Heap: THandle): BOOL; stdcall;
  TProcessHeapsFn = function(NumberOfHeaps: Cardinal; Heaps: Pointer): Cardinal; stdcall;
  TThreadIDFn = function: Cardinal; stdcall;

var
  HeapTLSLock: TCriticalSection;
  HeapTLSResolved: Integer = 0;
  FAvailable: Boolean = False;
  TlsAllocFn: TTlsAllocFn = nil;
  TlsFreeFn: TTlsFreeFn = nil;
  TlsSetFn: TTlsSetFn = nil;
  TlsGetFn: TTlsGetFn = nil;
  FlsAllocFn: TFlsAllocFn = nil;
  FlsFreeFn: TFlsFreeFn = nil;
  FlsSetFn: TFlsSetFn = nil;
  FlsGetFn: TFlsGetFn = nil;
  HeapCreateFn: THeapCreateFn = nil;
  HeapAllocFn: THeapAllocFn = nil;
  HeapFreeFn: THeapFreeFn = nil;
  HeapDestroyFn: THeapDestroyFn = nil;
  ProcessHeapsFn: TProcessHeapsFn = nil;
  ThreadIDFn: TThreadIDFn = nil;

procedure ResolveTLSPointers(K: HMODULE);
begin
  TlsAllocFn := TTlsAllocFn(WinExport(K, 'TlsAlloc'));
  TlsFreeFn := TTlsFreeFn(WinExport(K, 'TlsFree'));
  TlsSetFn := TTlsSetFn(WinExport(K, 'TlsSetValue'));
  TlsGetFn := TTlsGetFn(WinExport(K, 'TlsGetValue'));
end;

procedure ResolveFLSPointers(K: HMODULE);
begin
  FlsAllocFn := TFlsAllocFn(WinExport(K, 'FlsAlloc'));
  FlsFreeFn := TFlsFreeFn(WinExport(K, 'FlsFree'));
  FlsSetFn := TFlsSetFn(WinExport(K, 'FlsSetValue'));
  FlsGetFn := TFlsGetFn(WinExport(K, 'FlsGetValue'));
end;

procedure ResolveHeapPointers(K: HMODULE);
begin
  HeapCreateFn := THeapCreateFn(WinExport(K, 'HeapCreate'));
  HeapAllocFn := THeapAllocFn(WinExport(K, 'HeapAlloc'));
  HeapFreeFn := THeapFreeFn(WinExport(K, 'HeapFree'));
  HeapDestroyFn := THeapDestroyFn(WinExport(K, 'HeapDestroy'));
  ProcessHeapsFn := TProcessHeapsFn(WinExport(K, 'GetProcessHeaps'));
  ThreadIDFn := TThreadIDFn(WinExport(K, 'GetCurrentThreadId'));
end;

function HeapTLSFunctionTableReady: Boolean;
begin
  Result := Assigned(TlsAllocFn) and Assigned(TlsFreeFn) and
    Assigned(TlsSetFn) and Assigned(TlsGetFn) and
    Assigned(FlsAllocFn) and Assigned(FlsFreeFn) and
    Assigned(FlsSetFn) and Assigned(FlsGetFn) and
    Assigned(HeapCreateFn) and Assigned(HeapAllocFn) and
    Assigned(HeapFreeFn) and Assigned(HeapDestroyFn) and
    Assigned(ProcessHeapsFn) and Assigned(ThreadIDFn);
end;

function ResolveHeapTLSFunctions: Boolean;
var
  K: HMODULE;
begin
  if TInterlocked.CompareExchange(HeapTLSResolved, 0, 0) <> 0 then
    Exit(FAvailable);
  HeapTLSLock.Acquire;
  try
    if HeapTLSResolved <> 0 then Exit(FAvailable);
    K := WinModule('kernel32.dll');
    if K = 0 then Exit(False);
    ResolveTLSPointers(K);
    ResolveFLSPointers(K);
    ResolveHeapPointers(K);
    FAvailable := HeapTLSFunctionTableReady;
    TInterlocked.Exchange(HeapTLSResolved, 1);
    Result := FAvailable;
  finally
    HeapTLSLock.Release;
  end;
end;

function LocalThreadID: Cardinal;
begin
  ResolveHeapTLSFunctions;
  Result := 0;
  if Assigned(ThreadIDFn) then Result := ThreadIDFn();
end;

function LocalTlsAlloc: Cardinal;
begin
  ResolveHeapTLSFunctions;
  Result := INVALID_LOCAL_SLOT;
  if Assigned(TlsAllocFn) and Assigned(TlsFreeFn) and
     Assigned(TlsSetFn) and Assigned(TlsGetFn) then Result := TlsAllocFn();
end;

function LocalTlsSetValue(Index: Cardinal; Value: Pointer): Boolean;
begin
  ResolveHeapTLSFunctions;
  Result := False;
  if Assigned(TlsSetFn) and (Index <> INVALID_LOCAL_SLOT) then
    Result := TlsSetFn(Index, Value);
end;

function LocalTlsGetValue(Index: Cardinal): Pointer;
begin
  ResolveHeapTLSFunctions;
  Result := nil;
  if Assigned(TlsGetFn) and (Index <> INVALID_LOCAL_SLOT) then
    Result := TlsGetFn(Index);
end;

procedure LocalTlsFree(Index: Cardinal);
begin
  ResolveHeapTLSFunctions;
  if Assigned(TlsFreeFn) and (Index <> INVALID_LOCAL_SLOT) then
    TlsFreeFn(Index);
end;

function LocalFlsAlloc(Callback: Pointer): Cardinal;
begin
  ResolveHeapTLSFunctions;
  Result := INVALID_LOCAL_SLOT;
  if Assigned(FlsAllocFn) and Assigned(FlsFreeFn) and
     Assigned(FlsSetFn) and Assigned(FlsGetFn) then Result := FlsAllocFn(Callback);
end;

function LocalFlsSetValue(Index: Cardinal; Value: Pointer): Boolean;
begin
  ResolveHeapTLSFunctions;
  Result := False;
  if Assigned(FlsSetFn) and (Index <> INVALID_LOCAL_SLOT) then
    Result := FlsSetFn(Index, Value);
end;

function LocalFlsGetValue(Index: Cardinal): Pointer;
begin
  ResolveHeapTLSFunctions;
  Result := nil;
  if Assigned(FlsGetFn) and (Index <> INVALID_LOCAL_SLOT) then
    Result := FlsGetFn(Index);
end;

procedure LocalFlsFree(Index: Cardinal);
begin
  ResolveHeapTLSFunctions;
  if Assigned(FlsFreeFn) and (Index <> INVALID_LOCAL_SLOT) then
    FlsFreeFn(Index);
end;

function LocalHeapCreate: THandle;
begin
  ResolveHeapTLSFunctions;
  Result := 0;
  if Assigned(HeapCreateFn) and Assigned(HeapAllocFn) and
     Assigned(HeapFreeFn) and Assigned(HeapDestroyFn) then
    Result := HeapCreateFn(0, 4096, 0);
end;

function LocalHeapAlloc(Heap: THandle; Bytes: NativeUInt): Pointer;
begin
  ResolveHeapTLSFunctions;
  Result := nil;
  if (Heap <> 0) and (Heap <> INVALID_HANDLE_VALUE) and Assigned(HeapAllocFn) then
    Result := HeapAllocFn(Heap, 0, Bytes);
end;

procedure LocalHeapFree(Heap: THandle; Block: Pointer);
begin
  ResolveHeapTLSFunctions;
  if (Heap <> 0) and (Heap <> INVALID_HANDLE_VALUE) and (Block <> nil) and Assigned(HeapFreeFn) then
    HeapFreeFn(Heap, 0, Block);
end;

procedure LocalHeapDestroy(var Heap: THandle);
begin
  if (Heap = 0) or (Heap = INVALID_HANDLE_VALUE) then Exit;
  ResolveHeapTLSFunctions;
  // Retain the handle after failure instead of losing the owner's retry path.
  if Assigned(HeapDestroyFn) then
    if HeapDestroyFn(Heap) then Heap := 0;
end;


function ValidateAndSortHeapSnapshot(var Candidate: TArray<NativeUInt>): Boolean;
var
  I, J: Integer;
  Temp: NativeUInt;
begin
  Result := False;
  for I := 0 to High(Candidate) do
    if (Candidate[I] = 0) or (Candidate[I] = High(NativeUInt)) then Exit;
  for I := 1 to High(Candidate) do
  begin
    Temp := Candidate[I];
    J := I;
    while J > 0 do
    begin
      if Candidate[J - 1] <= Temp then Break;
      Candidate[J] := Candidate[J - 1];
      Dec(J);
    end;
    Candidate[J] := Temp;
  end;
  for I := 1 to High(Candidate) do
    if Candidate[I] = Candidate[I - 1] then Exit;
  Result := True;
end;

function LocalHeapSnapshot(out Heaps: TArray<NativeUInt>): Boolean;
const
  MAX_PROCESS_HEAPS = 512;
  MAX_HEAP_ATTEMPTS = 3;
var
  Count, Actual: Cardinal;
  Attempt: Integer;
  Candidate: TArray<NativeUInt>;
begin
  Result := False;
  Heaps := nil;
  ResolveHeapTLSFunctions;
  if not Assigned(ProcessHeapsFn) then Exit;
  Count := ProcessHeapsFn(0, nil);
  for Attempt := 1 to MAX_HEAP_ATTEMPTS do
  begin
    if (Count = 0) or (Count > MAX_PROCESS_HEAPS) then Exit;
    SetLength(Candidate, Integer(Count));
    FillChar(Candidate[0], Length(Candidate) * SizeOf(NativeUInt), 0);
    Actual := ProcessHeapsFn(Count, @Candidate[0]);
    if Actual = 0 then Exit;
    if Actual > Count then
    begin
      Count := Actual; // Array contents are not valid on this path.
      Continue;
    end;
    SetLength(Candidate, Integer(Actual));
    if not ValidateAndSortHeapSnapshot(Candidate) then Exit;
    Heaps := Candidate;
    Exit(True);
  end;
  // Bounded retries exhausted: UNKNOWN, not an empty/changed heap set.
end;

{$IFDEF NHW_NATIVE5B_TESTS}
  {$I Cozy.NHW.Native5B.HeapTLS.inc}
{$ENDIF}
initialization
  HeapTLSLock := TCriticalSection.Create;
finalization
  // The engine must have joined workers before Delphi unit finalization.
  HeapTLSLock.Free;
end.
