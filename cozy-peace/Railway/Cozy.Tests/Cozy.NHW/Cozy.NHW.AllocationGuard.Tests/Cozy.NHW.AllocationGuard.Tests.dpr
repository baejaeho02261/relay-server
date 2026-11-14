program CozyNHW_AllocationGuard_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.AllocationGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationGuard.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas';

procedure Require(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('Allocation transition regression');
end;

var
  A, B: TAllocationSample;
  Changes: TAllocationSignals;
begin
  A := Default(TAllocationSample);
  A.Base := $10000000;
  A.ReservedBytes := 2 * 1024 * 1024;
  A.CommittedBytes := 65536;
  A.RegionSignature := 1;
  Changes := AnalyzeAllocationTransition(Default(TAllocationSample), A, False);
  Require(asAllocation in Changes);
  B := A;
  B.CommittedBytes := 131072;
  B.RegionSignature := 2;
  Changes := AnalyzeAllocationTransition(A, B, True);
  Require(asCommit in Changes);
  Require(not (asExecute in Changes));
  A := B;
  B.ExecutableBytes := 65536;
  B.RegionSignature := 3;
  Changes := AnalyzeAllocationTransition(A, B, True);
  Require(asExecute in Changes);
  A := B;
  B.RWXBytes := 4096;
  B.RegionSignature := 4;
  Changes := AnalyzeAllocationTransition(A, B, True);
  Require(asRWX in Changes);
  A := B;
  B.CommittedBytes := B.CommittedBytes - 65536;
  B.RegionSignature := 5;
  Changes := AnalyzeAllocationTransition(A, B, True);
  Require(asRelease in Changes);
  // No output on success, like the main silent monitor.
end.
