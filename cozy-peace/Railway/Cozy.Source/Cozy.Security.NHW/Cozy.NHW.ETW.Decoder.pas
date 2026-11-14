unit Cozy.NHW.ETW.Decoder;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, Cozy.NHW.ETWTypes, Cozy.NHW.ETWNative;

const
  // Classic kernel tracing provider GUIDs from Microsoft ETW MOF classes.
  GUID_PROCESS: TGUID = '{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}';
  GUID_THREAD: TGUID = '{3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}';
  GUID_IMAGE: TGUID = '{2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}';
  GUID_FILEIO: TGUID = '{90CBDC39-4A3E-11D1-84F4-0000F80464E3}';
  GUID_REGISTRY: TGUID = '{AE53722E-C863-11D2-8659-00C04FA321A1}';

function SameGuid(const A, B: TGUID): Boolean;
function NormalPath(const S: string): string;
function PathEndsWith(const Path, Suffix: string): Boolean;
function RegistryRelevant(const S, UserPath: string): Boolean;
function TryDecodeKernelEvent(Rec: PEtwEventRecord; TargetPID: Cardinal;
  const ExeSuffix, UserRegistryPath: string; out E: TKernelEvent): Boolean;

implementation

uses
  Cozy.NHW.WinPointers;

function SameGuid(const A, B: TGUID): Boolean;
begin
  Result := CompareMem(@A, @B, SizeOf(TGUID));
end;

function NormalPath(const S: string): string;
begin
  Result := UpperCase(StringReplace(Trim(S), '/', '\', [rfReplaceAll]));
end;

function PathEndsWith(const Path, Suffix: string): Boolean;
var
  P: string;
begin
  P := NormalPath(Path);
  Result := (Suffix <> '') and (Length(P) >= Length(Suffix)) and
    (Copy(P, Length(P) - Length(Suffix) + 1, Length(Suffix)) = Suffix);
end;

function RegistryRelevant(const S, UserPath: string): Boolean;
var
  K: string;
  function StartsAt(const Prefix: string): Boolean;
  begin
    Result := Copy(K, 1, Length(Prefix)) = Prefix;
  end;
begin
  K := NormalPath(S);
  Result := StartsAt('\REGISTRY\MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\') or
    StartsAt('\REGISTRY\MACHINE\SOFTWARE\POLICIES\MICROSOFT\WINDOWS\') or
    (StartsAt('\REGISTRY\MACHINE\SYSTEM\CONTROLSET') and
     (Pos('\CONTROL\SESSION MANAGER\', K) > 0)) or
    ((UserPath <> '') and
     (StartsAt(UserPath + '\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\') or
      StartsAt(UserPath + '\SOFTWARE\POLICIES\MICROSOFT\WINDOWS\')));
end;

function TryDecodeKernelEvent(Rec: PEtwEventRecord; TargetPID: Cardinal;
  const ExeSuffix, UserRegistryPath: string; out E: TKernelEvent): Boolean;
var
  Kind: TKernelEventKind;
  PID, TID, ParentPID: Cardinal;
  Op: Byte;
  FilePath: string;
begin
  Result := False;
  E := Default(TKernelEvent);
  if TargetPID = 0 then Exit;
  Op := Rec^.Header.Descriptor.Opcode;
  PID := 0;
  TID := 0;
  ParentPID := 0;
  if SameGuid(Rec^.Header.ProviderId, GUID_THREAD) then
  begin
    if (Op <> 1) and (Op <> 2) then Exit;
    // Classic thread payload begins with ProcessId and TThreadId.
    if not ReadEtwUInt(Rec, 'ProcessId', PID) then
    begin
      if (Rec^.UserData = nil) or (Rec^.UserDataLength < 8) then Exit;
      Move(PByte(Rec^.UserData)^, PID, 4);
    end;
    if PID <> TargetPID then Exit;
    if not ReadEtwUInt(Rec, 'TThreadId', TID) then
    begin
      if (Rec^.UserData = nil) or (Rec^.UserDataLength < 8) then Exit;
      Move(PByte(NativeUInt(Rec^.UserData) + 4)^, TID, 4);
    end;
    if TID = 0 then Exit;
    if Op = 1 then Kind := keThreadStart else Kind := keThreadEnd;
  end
  else if SameGuid(Rec^.Header.ProviderId, GUID_PROCESS) then
  begin
    if (Op <> 1) and (Op <> 2) then Exit;
    if not ReadEtwUInt(Rec, 'ProcessId', PID) then Exit;
    if Op = 1 then
    begin
      if not ReadEtwUInt(Rec, 'ParentId', ParentPID) then Exit;
      if ParentPID <> TargetPID then Exit;
      Kind := keProcessStart;
    end
    else
      Kind := keProcessEnd; // Start correlation filters unrelated PID later.
  end
  else if SameGuid(Rec^.Header.ProviderId, GUID_IMAGE) then
  begin
    // Classic Image_Load: opcode 10 is a real load. DCStart (3) is only
    // a snapshot of modules that were already loaded: ignore it.
    if (Op <> 10) and (Op <> 2) then Exit;
    // Typed TDH field required; process header PID can be a kernel context
    // and must not be used as fallback attribution.
    if not ReadEtwUInt(Rec, 'ProcessId', PID) then Exit;
    if PID <> TargetPID then Exit;
    if Op = 10 then Kind := keImageLoad else Kind := keImageUnload;
  end
  else if SameGuid(Rec^.Header.ProviderId, GUID_FILEIO) then
  begin
    if not (Op in [64, 67, 68, 69, 70, 71, 74, 75]) then Exit;
    if not ReadEtwText(Rec, 'OpenPath', FilePath) then
      if not ReadEtwText(Rec, 'FileName', FilePath) then Exit;
    if not PathEndsWith(FilePath, ExeSuffix) then Exit;
    PID := Rec^.Header.ProcessId; // issuing context, not always the owner
    // Self activity and the system PID alone are not evidence of external I/O.
    if (PID = TargetPID) or (PID <= 4) then Exit;
    Kind := keFileIO;
  end
  else if SameGuid(Rec^.Header.ProviderId, GUID_REGISTRY) then
  begin
    // Only mutation-related opcodes. Read-only queries are not changes.
    if not (Op in [10, 12, 14, 15, 20, 22, 23]) then Exit;
    if not ReadEtwText(Rec, 'KeyName', FilePath) then Exit;
    if not RegistryRelevant(FilePath, UserRegistryPath) then Exit;
    PID := Rec^.Header.ProcessId;
    Kind := keRegistryActivity;
  end
  else Exit;

  E := Default(TKernelEvent);
  E.Kind := Kind;
  E.PID := PID;
  E.ThreadID := TID;
  E.ParentPID := ParentPID;
  E.Tick := WinTick64;
  Result := True;
end;

end.
