program CozyNHW_SelfNative_Smoke;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.SelfNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfNative.pas';

var
  Hash: UInt64;
  Count: Cardinal;
  ValidTargets: Boolean;
begin
  ResolveWinPointers;
  ResolveNativeAPIs;
  if not CaptureSelfIAT(Hash, Count) then
    raise Exception.Create('IAT snapshot unavailable');
  if Count = 0 then raise Exception.Create('No import thunks');
  if not CaptureLiveFunctionPointers(Hash, ValidTargets) then
    raise Exception.Create('Function pointer snapshot unavailable');
  if not ValidTargets then
    raise Exception.Create('Unexpected system function pointer region');
  // PEB layouts differ; an unsupported layout is UNKNOWN, not a detection.
  CaptureProcessParameters(Hash);
  Writeln('PASS');
end.
