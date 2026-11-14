program CozyNHW_MappingGuard_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.MappingGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MappingGuard.pas',
  Cozy.NHW.MappingNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MappingNative.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas';

procedure Check(OK: Boolean);
begin
  if not OK then raise Exception.Create('MappingGuard regression');
end;

var
  A, B: TMappingSample;
  Sig: TMappingSignals;
begin
  A := Default(TMappingSample);
  A.Base := $0000000030000000;
  A.RegionType := $01000000; // MEM_IMAGE
  A.ProbePage := A.Base;
  A.MappedBytes := 65536;
  A.ExecutableBytes := 4096;
  A.SharedKnown := True;
  A.Shared := True;
  A.BackingKnown := True;
  A.Backing := '\Device\HarddiskVolume1\sample.dll';

  Sig := AnalyzeMappingTransition(Default(TMappingSample), A, False);
  Check(msNewView in Sig);
  Check(msExecutable in Sig);

  B := A;
  B.Shared := False;
  Sig := AnalyzeMappingTransition(A, B, True);
  Check(msCOW in Sig);
  Check(msPageSharing in Sig);
  Check(not (msBacking in Sig));

  B := A;
  B.SharedKnown := False;
  Check(not (msCOW in AnalyzeMappingTransition(A, B, True)));

  B := A;
  B.ProbePage := B.ProbePage + 4096;
  B.Shared := False;
  Check(not (msCOW in AnalyzeMappingTransition(A, B, True)));

  B := A;
  B.Backing := '\Device\HarddiskVolume2\sample.dll';
  Sig := AnalyzeMappingTransition(A, B, True);
  Check(msBacking in Sig);

  B := A;
  B.ExecutableBytes := 8192;
  Sig := AnalyzeMappingTransition(A, B, True);
  Check(msExecutable in Sig);

  B := A;
  B.RegionType := $00040000; // MEM_MAPPED
  Check(AnalyzeMappingTransition(A, B, True) = []);
  // Silent test on success.
end.
