program CozyNHW_HeapTLSSmoke;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Windows 64-bit (dcc64).'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.HeapTLSNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HeapTLSNative.pas',
  Cozy.NHW.HeapTLSRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HeapTLSRules.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.HeapTLS in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HeapTLS.pas';

var
  Monitor: THeapTLSMonitor;
  Alerts: TDetectionKinds;
begin
  ResolveWinPointers;
  Monitor := THeapTLSMonitor.Create;
  try
    Alerts := [];
    Monitor.Examine(True, 1000, False, Alerts);
    Monitor.Examine(False, 5000, False, Alerts);
    Monitor.Examine(False, 7500, False, Alerts);
    if Alerts <> [] then
      raise Exception.Create('Unexpected alert in idle self-test');
    Writeln('PASS');
  finally
    Monitor.Free;
  end;
end.
