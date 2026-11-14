program Cozy_CrcPeProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF GAME_CRC_PE_PROBE}
  {$MESSAGE FATAL 'CRC PE probe requires its isolated test build define.'}
{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsIntegrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIntegrity.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  Winapi.Windows, System.SysUtils, System.JSON, Cozy.CodeIntegrity;
var
  Handle: THandle;
  Plan: TCodeIntegrity;
  Obj: TJSONObject;
  FileMode: Boolean;
  FileName: string;
begin
  Handle := INVALID_HANDLE_VALUE; Plan := nil; Obj := nil;
  try
    try
      FileMode := (ParamCount = 2) and (ParamStr(1) = CozyText_CrcPeProbe_file_42e0ecc4);
      if FileMode then FileName := ParamStr(2)
      else if (ParamCount = 1) and (ParamStr(1) = CozyText_CrcPeProbe_own_7aee0c72) then
        FileName := ParamStr(0)
      else raise Exception.Create(CozyText_CrcPeProbe_Usage_Cozy_CrcPeProbe_file_PE_own_91b13a38);
      Handle := CreateFile(PChar(FileName), GENERIC_READ, FILE_SHARE_READ, nil,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
      if Handle = INVALID_HANDLE_VALUE then RaiseLastOSError;
      if FileMode then
        { Disk mode never maps/executes fixture input or weakens MEM_IMAGE. }
        Plan := TCodeIntegrity.Create(Handle, GetModuleHandle(nil))
      else Plan := TCodeIntegrity.Create(Handle);
      Obj := Plan.CaptureCrcProbeSnapshot(FileMode);
    except
      on E: Exception do
      begin
        Obj.Free; Obj := TJSONObject.Create;
        Obj.AddPair(CozyText_CrcPeProbe_accepted_8e7be485, TJSONBool.Create(False));
        Obj.AddPair(CozyText_CrcPeProbe_errorClass_35f0c55c, E.ClassName);
      end;
    end;
    WriteLn(Obj.ToJSON);
  finally
    Obj.Free; Plan.Free;
    if Handle <> INVALID_HANDLE_VALUE then CloseHandle(Handle);
  end;
end.
