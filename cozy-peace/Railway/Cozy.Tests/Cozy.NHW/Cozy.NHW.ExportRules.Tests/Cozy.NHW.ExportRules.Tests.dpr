program CozyNHWExportRulesTests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.ExportRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExportRules.pas',
  Cozy.NHW.PERules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PERules.pas',
  Cozy.NHW.SelfRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfRules.pas',
  Cozy.NHW.ExceptionRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionRules.pas';
procedure Check(B: Boolean);
begin
  if not B then raise Exception.Create('Export rules test failed');
end;
var
  Watch: TExportWatch;
  F: TPEFeature;
begin
  Check(IsValidForwarder('NTDLL.RtlAllocateHeap'));
  Check(IsValidForwarder('KERNELBASE.#21'));
  Check(not IsValidForwarder('no-point'));
  Check(not IsValidForwarder('api-ms-win-core-synch-l1-2-0.'));
  Check(IsApiSetContract('api-ms-win-core-test-l1-1-0.Method'));
  Check(IsApiSetContract('ext-ms-win-test-l1-1-0.Method'));
  Check(not IsApiSetContract('KERNELBASE.Sleep'));
  Watch := Default(TExportWatch);
  F := Default(TPEFeature);
  F.Available := True;
  F.Valid := True;
  F.Digest := 100;
  Check(not ObserveDelayImport(Watch, F, 0, True));
  F.Digest := 200;
  // The first newly resolved delay-load slot updates a baseline silently.
  Check(not ObserveDelayImport(Watch, F, 1, False));
  F.Digest := 300;
  Check(not ObserveDelayImport(Watch, F, 1, False));
  Check(ObserveDelayImport(Watch, F, 1, False));
  Check(not ObserveDelayImport(Watch, F, 1, False));
end.
