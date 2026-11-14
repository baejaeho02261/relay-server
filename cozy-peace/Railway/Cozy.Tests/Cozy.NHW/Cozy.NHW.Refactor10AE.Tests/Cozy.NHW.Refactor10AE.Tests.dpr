program CozyNHW_Refactor10AE_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}{$MESSAGE FATAL 'Win64 only.'}{$ENDIF}
{$IFNDEF NHW_REFACTOR10AE_TESTS}{$MESSAGE FATAL 'Use Cozy.NHW.Refactor10AE.Tests.dproj.'}{$ENDIF}
uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.APCStyleEvidence, Cozy.NHW.AdaptiveInspector, Cozy.NHW.AllocationNative,
  Cozy.NHW.Job, Cozy.NHW.PERules, Cozy.NHW.PEView, Cozy.NHW.ResourceController,
  Cozy.NHW.SelfRules, Cozy.NHW.SensorDisagreement, Cozy.NHW.TriggeredSnapshot;
type TFixture = function(out Failure: string; out Checks: Integer): Boolean;
var DirectChecks, FixtureChecks, Groups: Integer;
procedure Check(V: Boolean; const Why: string);
begin
  Inc(DirectChecks);
  if not V then raise Exception.Create(Why);
end;
procedure Existing(const N: string; T: TFixture);
var F: string; C: Integer;
begin
  F := ''; C := 0;
  if not T(F, C) then raise Exception.Create(N + ': ' + F);
  Check(C > 0, N + ': no checks');
  Inc(FixtureChecks, C);
  Inc(Groups);
end;
procedure AllocationContract;
var R: TVirtualRegion;
begin
  R := Default(TVirtualRegion);
  R.State := ALLOC_MEM_COMMIT;
  R.RegionType := ALLOC_MEM_PRIVATE;
  R.Protect := ALLOC_PAGE_EXECUTE_READWRITE;
  Check(RegionIsPrivate(R), 'AllocationNative: committed private region');
  Check(RegionIsExecutable(R), 'AllocationNative: RWX is executable');
  Check(RegionIsRWX(R), 'AllocationNative: RWX classification');
  R.Protect := $04;
  Check(not RegionIsExecutable(R), 'AllocationNative: RW is not executable');
  Inc(Groups);
end;
procedure PEViewContract;
var V: TPEView; Address: NativeUInt; Bytes: Cardinal;
begin
  V := Default(TPEView);
  V.Base := $10000;
  V.ImageSize := $3000;
  V.Directory[1].RVA := $200;
  V.Directory[1].Size := $40;
  Check(PEAddress(V, $100, 16, Address) and (Address = $10100),
    'PEView: bounded RVA');
  Check(not PEAddress(V, $3000, 1, Address),
    'PEView: end RVA excluded');
  Check(PEDataAddress(V, 1, 8, Address, Bytes) and
    (Address = $10200) and (Bytes = $40), 'PEView: data directory');
  Check(not PEDataAddress(V, 16, 1, Address, Bytes),
    'PEView: invalid directory index');
  Inc(Groups);
end;
begin
  DirectChecks := 0; FixtureChecks := 0; Groups := 0;
  try
    Existing('APCStyleEvidence', TestAPC5J);
    Existing('AdaptiveInspector', TestAdaptiveInspector10P);
    AllocationContract;
    Existing('Job', TestJob10N);
    Existing('PERules', TestPERules10N);
    PEViewContract;
    Existing('ResourceController', TestResourceController10O);
    Existing('SelfRules', TestSelfRules10P);
    Existing('SensorDisagreement', TestSensorDisagreement10O);
    Existing('TriggeredSnapshot', TestTriggeredSnapshot10P);
    Check(Groups = 10, 'group count');
    Writeln('PASS: Refactor10AE groups=', Groups,
      ' direct=', DirectChecks, ' fixture=', FixtureChecks);
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
