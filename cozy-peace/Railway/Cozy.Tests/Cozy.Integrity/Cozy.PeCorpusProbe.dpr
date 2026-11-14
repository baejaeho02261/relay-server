program Cozy_PeCorpusProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
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
 Winapi.Windows, System.SysUtils, System.JSON, Cozy.CodeIntegrity, Cozy.Integrity;
var Handle: THandle; Plan: TCodeIntegrity; Obj: TJSONObject; Digest: TImageDigest;
begin
  Handle := INVALID_HANDLE_VALUE; Plan := nil; Obj := TJSONObject.Create;
  try
    try
      if ParamCount <> 1 then raise Exception.Create(CozyText_PeCorpusProbe_PE_CORPUS_ARGUMENT_4c60a888);
      Handle := CreateFile(PChar(ParamStr(1)), GENERIC_READ, FILE_SHARE_READ, nil,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
      if Handle = INVALID_HANDLE_VALUE then RaiseLastOSError;
      { Explicit nonzero module disables own-image mapped-header checks. Only
        FileMeasurement is read; no LoadLibrary and no MeasureNow call. }
      Plan := TCodeIntegrity.Create(Handle, GetModuleHandle(nil));
      Digest := IntegrityHashHandle(Handle);
      Obj.AddPair(CozyText_PeCorpusProbe_accepted_a6ba011a, TJSONBool.Create(True));
      Obj.AddPair(CozyText_PeCorpusProbe_codeSha512_57a151cb, Plan.FileMeasurement.SHA512);
      Obj.AddPair(CozyText_PeCorpusProbe_codeCrc64_180fcd5f, Plan.FileMeasurement.CRC64);
      Obj.AddPair(CozyText_PeCorpusProbe_fileSha512_cf9f293a, Digest.SHA512); Obj.AddPair(CozyText_PeCorpusProbe_fileCrc64_3c3631d8, Digest.CRC64);
      Obj.AddPair(CozyText_PeCorpusProbe_codeXxh3_128_4bf23bc1, Plan.FileMeasurement.XXH3_128);
      Obj.AddPair(CozyText_PeCorpusProbe_codeBlake3_febe7447, Plan.FileMeasurement.Blake3);
      Obj.AddPair(CozyText_PeCorpusProbe_exportStatus_c4caaa28, Plan.ExportTableStatus);
      if Plan.ExportTableStatus = CozyText_PeCorpusProbe_MEASURED_ef61ae10 then
      begin
        Obj.AddPair(CozyText_PeCorpusProbe_exportSha512_ab815f58, Plan.FileExportMeasurement.SHA512);
        Obj.AddPair(CozyText_PeCorpusProbe_exportCrc64_c27d1ea5, Plan.FileExportMeasurement.CRC64);
        Obj.AddPair(CozyText_PeCorpusProbe_exportXxh3_128_5b3d774f, Plan.FileExportMeasurement.XXH3_128);
        Obj.AddPair(CozyText_PeCorpusProbe_exportBlake3_ca8c00ca, Plan.FileExportMeasurement.Blake3);
      end;
    except
      on E: Exception do begin
        Obj.Free; Obj := TJSONObject.Create;
        Obj.AddPair(CozyText_PeCorpusProbe_accepted_a6ba011a, TJSONBool.Create(False));
        Obj.AddPair(CozyText_PeCorpusProbe_errorClass_da829fc6, E.ClassName);
      end;
    end;
    WriteLn(Obj.ToJSON);
  finally
    Obj.Free; Plan.Free;
    if Handle <> INVALID_HANDLE_VALUE then CloseHandle(Handle);
  end;
end.
