program CozyNHW_WriteWatchSmoke;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 target required'}
{$ENDIF}

uses
  System.SysUtils,
  Winapi.Windows,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.WriteWatchNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WriteWatchNative.pas';

var
  P: Pointer;
  Bytes: NativeUInt;
  PageSize: Cardinal;
  Mask: Cardinal;
begin
  P := nil;
  try
    ResolveWinPointers;
    if not CreateWriteWatchRegion(P, Bytes, PageSize) then
      raise Exception.Create('Write-watch unavailable');
    if not QueryAndResetWriteWatch(P, Bytes, PageSize, Mask) then
      raise Exception.Create('Reset failed');
    PByte(NativeUInt(P) + NativeUInt(PageSize) * 1)^ := $5A;
    PByte(NativeUInt(P) + NativeUInt(PageSize) * 3)^ := $A5;
    if not QueryAndResetWriteWatch(P, Bytes, PageSize, Mask) then
      raise Exception.Create('Query failed');
    if (Mask and $A) <> $A then
      raise Exception.Create('Expected pages 1 and 3');
    if not QueryAndResetWriteWatch(P, Bytes, PageSize, Mask) then
      raise Exception.Create('Second query failed');
    if Mask <> 0 then
      raise Exception.Create('Reset failed to clear write history');
    Writeln('PASS');
  finally
    ReleaseWriteWatchRegion(P);
  end;
end.
