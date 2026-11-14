program CozyNHW_ETWAbi_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.ETWNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWNative.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas';

begin
  if not EtwAbiValid then
    raise Exception.Create('ETW x64 structure ABI mismatch');
end.
