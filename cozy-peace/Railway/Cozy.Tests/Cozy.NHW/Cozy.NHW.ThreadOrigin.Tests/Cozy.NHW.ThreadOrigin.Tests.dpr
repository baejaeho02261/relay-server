program CozyNHW_ThreadOrigin_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build for Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.ThreadOriginNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadOriginNative.pas';

procedure Require(Condition: Boolean);
begin
  if not Condition then Halt(1);
end;

var
  A, B: TThreadOriginRegion;
begin
  A := Default(TThreadOriginRegion);
  A.Known := True;
  A.StartAddress := $100000;
  A.RegionType := $20000; // MEM_PRIVATE
  A.State := $1000; // MEM_COMMIT
  A.Protect := $20; // PAGE_EXECUTE_READ
  Require(IsPrivateExecutableStart(A));
  Require(IsNonImageExecutableStart(A));

  B := A;
  B.RegionType := $1000000; // MEM_IMAGE
  Require(not IsNonImageExecutableStart(B));
  Require(IsThreadRegionChanged(A, B));

  B := A;
  B.Protect := $04; // PAGE_READWRITE
  Require(not IsPrivateExecutableStart(B));
  Require(IsThreadRegionChanged(A, B));

  B.Known := False;
  Require(not IsThreadRegionChanged(A, B));
  B := A;
  B.StartAddress := $200000;
  Require(not IsThreadRegionChanged(A, B));

  B := A;
  B.Protect := $120; // guard + EXECUTE_READ
  Require(not IsPrivateExecutableStart(B));
  Require(not IsThreadRegionChanged(A, A));
end.
