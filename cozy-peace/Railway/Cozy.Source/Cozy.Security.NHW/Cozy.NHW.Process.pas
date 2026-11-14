unit Cozy.NHW.Process;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Types,
  Cozy.NHW.Native,
  Cozy.NHW.WinPointers;

procedure QueryOwnerInfo(var Holder: TTargetHolder);
function FindTargetByName(const TargetName: string; out FoundPID: Cardinal;
  out MatchCount: Integer; out ErrorText: string): Boolean;

{$IFDEF NHW_HARDENING_TESTS}
function TestProcessHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.Generics.Collections,
  Cozy.NHW.NativeSafety,
  Cozy.NHW.ProcessList.Decoder;

function FileTimeValue(const V: TFileTime): UInt64; inline;
begin
  Result := (UInt64(V.dwHighDateTime) shl 32) or UInt64(V.dwLowDateTime);
end;

function SameProcessEpoch(Expected, Actual: UInt64): Boolean; inline;
begin
  Result := (Expected <> 0) and (Actual <> 0) and (Expected = Actual);
end;

function ReadProcessPath(H: THandle; out Path: string): Boolean;
var
  Buf: array[0..32767] of WideChar;
  N: Cardinal;
begin
  Result := False;
  Path := '';
  N := Cardinal(Length(Buf));
  if not QueryProcessImageName(H, @Buf[0], N) then Exit;
  if (N = 0) or (N >= Cardinal(Length(Buf))) then Exit;
  SetString(Path, PWideChar(@Buf[0]), Integer(N));
  if Pos(#0, Path) <> 0 then
  begin
    Path := '';
    Exit;
  end;
  Result := True;
end;

procedure QueryOwnerInfo(var Holder: TTargetHolder);
var
  H: THandle;
  C, E, K, U: TFileTime;
  ExpectedCreated, Created: UInt64;
  Path: string;
  CanWait, TimeKnown: Boolean;
begin
  ExpectedCreated := Holder.CreateTime;
  Holder.ImagePath := '<path unavailable>';
  Holder.CreateTime := 0;
  if Holder.PID = 0 then Exit;
  // SYNCHRONIZE is optional. Keep metadata collection possible for callers
  // allowed QUERY_LIMITED_INFORMATION but not SYNCHRONIZE.
  H := OpenNativeProcess(Holder.PID,
    NATIVE_PROCESS_QUERY_LIMITED_INFORMATION or ACCESS_SYNCHRONIZE);
  CanWait := H <> 0;
  if H = 0 then H := OpenNativeProcess(Holder.PID, NATIVE_PROCESS_QUERY_LIMITED_INFORMATION);
  if H = 0 then Exit;
  try
    if CanWait then
      if WinWaitForSingleObject(H, 0) <> WAIT_TIMEOUT then Exit;
    TimeKnown := WinGetProcessTimes(H, C, E, K, U);
    Created := 0;
    if TimeKnown then Created := FileTimeValue(C);
    if ExpectedCreated <> 0 then
      if not SameProcessEpoch(ExpectedCreated, Created) then Exit;
    Path := '';
    ReadProcessPath(H, Path);
    // Do not examine lpExitTime: its contents are undefined for a live process.
    if CanWait then
      if WinWaitForSingleObject(H, 0) <> WAIT_TIMEOUT then Exit;
    Holder.CreateTime := Created;
    if Path <> '' then Holder.ImagePath := Path;
  finally
    CloseNativeProcess(H);
  end;
end;

function FindTargetByName(const TargetName: string; out FoundPID: Cardinal;
  out MatchCount: Integer; out ErrorText: string): Boolean;
var
  Data: TBytes;
  Failure: TNTStatus;
  Candidates: TList<TProcessCandidate>;
  Cnd: TProcessCandidate;
  H: THandle;
  Wow64: BOOL;
  C, E, K, U: TFileTime;
  Path, Leaf: string;
  Sep: Integer;
  LocalPID: Cardinal;
  LocalMatches: Integer;
begin
  Result := False;
  ErrorText := '';
  FoundPID := 0;
  MatchCount := 0;
  if (TargetName = '') or (Pos(#0, TargetName) <> 0) then
  begin
    ErrorText := 'Invalid process target name.';
    Exit;
  end;
  if not FetchSystemData(SYSTEM_PROCESS_INFORMATION_CLASS,
    1024 * 1024, MAX_PROCESS_BYTES, Data, Failure) then
  begin
    ErrorText := 'Native process enumeration failed NTSTATUS=0x' +
      IntToHex(Cardinal(Failure), 8);
    Exit;
  end;
  Candidates := TList<TProcessCandidate>.Create;
  try
    // Finish validating the entire list before exposing any candidate PID.
    if not CollectNameCandidates(Data, TargetName, Candidates, ErrorText) then Exit;
    LocalPID := 0;
    LocalMatches := 0;
    for Cnd in Candidates do
    begin
      H := OpenNativeProcess(Cnd.PID,
        NATIVE_PROCESS_QUERY_LIMITED_INFORMATION or ACCESS_SYNCHRONIZE);
      if H = 0 then Continue;
      try
        Wow64 := False;
        if not WinIsWow64Process(H, Wow64) then Continue;
        if Wow64 then Continue;
        if WinWaitForSingleObject(H, 0) <> WAIT_TIMEOUT then Continue;
        if not WinGetProcessTimes(H, C, E, K, U) then Continue;
        if not SameProcessEpoch(Cnd.Created, FileTimeValue(C)) then Continue;
        // Best-effort independent name check on the same handle. Query
        // failure alone does not invalidate the creation-time identity.
        if ReadProcessPath(H, Path) then
        begin
          Sep := LastDelimiter('\/', Path);
          Leaf := Copy(Path, Sep + 1, MaxInt);
          if not SameText(Leaf, TargetName) then Continue;
        end;
        if WinWaitForSingleObject(H, 0) <> WAIT_TIMEOUT then Continue;
        Inc(LocalMatches);
        if (LocalPID = 0) or (Cnd.PID < LocalPID) then LocalPID := Cnd.PID;
      finally
        CloseNativeProcess(H);
      end;
    end;
    FoundPID := LocalPID;
    MatchCount := LocalMatches;
    Result := True;
  finally
    Candidates.Free;
    if not Result then
    begin
      FoundPID := 0;
      MatchCount := 0;
    end;
  end;
end;

{$IFDEF NHW_HARDENING_TESTS}
function TestProcessHardening(out Failure: string; out Checks: Integer): Boolean;
var
  Data: TBytes;
  P: TProcessPrefix;
  C: TList<TProcessCandidate>;
  Name, Why: string;
  Created: Int64;
  OK: Boolean;

  procedure Check(Condition: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Text);
  end;

  procedure Fixture;
  begin
    Name := 'test.exe';
    SetLength(Data, 256);
    FillChar(Data[0], Length(Data), 0);
    P := Default(TProcessPrefix);
    P.UniqueProcessId := 100;
    P.ImageName.Length := Word(Length(Name) * SizeOf(WideChar));
    P.ImageName.MaximumLength := P.ImageName.Length;
    P.ImageName.Buffer := PWideChar(@Data[104]);
    Created := 12345;
    Move(Created, P.Reserved1[24], SizeOf(Created));
    Move(P, Data[0], SizeOf(P));
    Move(PWideChar(Name)^, Data[104], P.ImageName.Length);
  end;

  function Parse: Boolean;
  begin
    Result := CollectNameCandidates(Data, 'test.exe', C, Why);
  end;

begin
  Result := False; Failure := ''; Checks := 0;
  C := TList<TProcessCandidate>.Create;
  try
    try
      Fixture;
      OK := Parse;
      Check(OK and (C.Count = 1), 'valid process snapshot');
      Check((C[0].PID = 100) and (C[0].Created = 12345), 'process epoch read');
      Check(SameProcessEpoch(123, 123) and not SameProcessEpoch(123, 124) and
        not SameProcessEpoch(0, 0), 'PID reuse/unknown epoch rejected');
      P.NextEntryOffset := 256; Move(P, Data[0], SizeOf(P));
      Check(not Parse and (C.Count = 0), 'next offset cannot point to end of buffer');
      Fixture;
      P.NextEntryOffset := 128; Move(P, Data[0], SizeOf(P));
      P := Default(TProcessPrefix); P.NextEntryOffset := 7;
      Move(P, Data[128], SizeOf(P));
      Check(not Parse and (C.Count = 0), 'malformed later record discards earlier candidate');
      Fixture;
      P.ImageName.Length := 3; Move(P, Data[0], SizeOf(P));
      Check(not Parse, 'odd UTF-16 byte length');
      Fixture;
      P.ImageName.MaximumLength := 2; Move(P, Data[0], SizeOf(P));
      Check(not Parse, 'name length exceeds maximum');
      Fixture;
      P.ImageName.Buffer := PWideChar(@Data[8]); Move(P, Data[0], SizeOf(P));
      Check(not Parse, 'name overlaps record prefix');
      Fixture;
      P.NextEntryOffset := 128;
      P.ImageName.Buffer := PWideChar(@Data[160]); Move(P, Data[0], SizeOf(P));
      Check(not Parse, 'name cannot refer to another record');
      Data := nil;
      Check(not Parse and (C.Count = 0), 'empty process list rejected');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    C.Free;
  end;
end;
{$ENDIF}

end.
