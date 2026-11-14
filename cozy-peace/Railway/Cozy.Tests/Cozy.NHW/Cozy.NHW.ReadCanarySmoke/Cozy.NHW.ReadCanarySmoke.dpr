program CozyNHW_ReadCanarySmoke;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Win64 (dcc64).'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.ReadCanaryNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReadCanaryNative.pas';
var
  Page: Pointer;
  Guarded: Boolean;
begin
  Page := nil;
  try
    ResolveWinPointers;
    if not CreateReadCanary(Page) then Halt(2);
    if (not QueryReadCanary(Page, Guarded)) or (not Guarded) then Halt(3);
  finally
    ReleaseReadCanary(Page);
  end;
end.
