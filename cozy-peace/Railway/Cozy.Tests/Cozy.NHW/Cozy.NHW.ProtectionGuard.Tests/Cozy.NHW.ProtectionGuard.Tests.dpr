program CozyNHW_ProtectionGuard_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.ProtectionGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ProtectionGuard.pas';

procedure Ensure(Condition: Boolean);
begin
  if not Condition then Halt(1);
end;

function Sample(AProtection, AType: Cardinal): TProtectionSample;
begin
  Result := Default(TProtectionSample);
  Result.Page := $140000;
  Result.AllocationBase := $100000;
  Result.RegionType := AType;
  Result.State := ALLOC_MEM_COMMIT;
  Result.Protect := AProtection;
end;

function Region(AProtection, AType: Cardinal): TVirtualRegion;
begin
  Result := Default(TVirtualRegion);
  Result.BaseAddress := $140000;
  Result.AllocationBase := $100000;
  Result.Size := $1000;
  Result.State := ALLOC_MEM_COMMIT;
  Result.Protect := AProtection;
  Result.RegionType := AType;
end;

function Sweep(Guard: TProtectionGuard; AProtection, AType: Cardinal;
  Tick: UInt64): TDetectionKinds;
var
  Item: TVirtualRegion;
begin
  Result := [];
  Item := Region(AProtection, AType);
  Guard.BeginSweep;
  Guard.ObserveRegion(Item);
  Guard.EndSweep(Tick, Result);
end;

var
  A, B: TProtectionSample;
  Signals: TProtectionSignals;
  Guard: TProtectionGuard;
  Detected: TDetectionKinds;
begin
  A := Sample($04, ALLOC_MEM_PRIVATE);
  B := Sample($20, ALLOC_MEM_PRIVATE);
  Signals := AnalyzeProtectionTransition(A, B);
  Ensure(psTransition in Signals);
  Ensure(not (psGuard in Signals));
  A := Sample($20, ALLOC_MEM_IMAGE);
  B := Sample($40, ALLOC_MEM_IMAGE);
  Signals := AnalyzeProtectionTransition(A, B);
  Ensure(psImage in Signals);
  A := Sample($04, ALLOC_MEM_PRIVATE);
  B := Sample($104, ALLOC_MEM_PRIVATE);
  Signals := AnalyzeProtectionTransition(A, B);
  Ensure(psGuard in Signals);
  A := Sample($04, ALLOC_MEM_PRIVATE);
  B := Sample($01, ALLOC_MEM_PRIVATE);
  Signals := AnalyzeProtectionTransition(A, B);
  Ensure(psNoAccess in Signals);
  A := Sample($04, ALLOC_MEM_PRIVATE);
  B := Sample($20, ALLOC_MEM_IMAGE);
  Ensure(AnalyzeProtectionTransition(A, B) = []);

  Guard := TProtectionGuard.Create;
  try
    // First two full scans establish the baseline, not detections.
    Ensure(Sweep(Guard, $04, ALLOC_MEM_PRIVATE, 1000) = []);
    Ensure(Sweep(Guard, $04, ALLOC_MEM_PRIVATE, 2000) = []);
    Ensure(Sweep(Guard, $20, ALLOC_MEM_PRIVATE, 3000) = []);
    Detected := Sweep(Guard, $20, ALLOC_MEM_PRIVATE, 4000);
    Ensure(dkProtectTransition in Detected);
    // Two consecutive confirmed transitions: RW -> RX -> RW.
    Ensure(Sweep(Guard, $04, ALLOC_MEM_PRIVATE, 5000) = []);
    Detected := Sweep(Guard, $04, ALLOC_MEM_PRIVATE, 6000);
    Ensure(dkProtectionCycle in Detected);
    Ensure(Sweep(Guard, $104, ALLOC_MEM_PRIVATE, 7000) = []);
    Detected := Sweep(Guard, $104, ALLOC_MEM_PRIVATE, 8000);
    Ensure(dkGuardTransition in Detected);
    Ensure(Sweep(Guard, $01, ALLOC_MEM_PRIVATE, 9000) = []);
    Detected := Sweep(Guard, $01, ALLOC_MEM_PRIVATE, 10000);
    Ensure(dkNoAccess in Detected);
    Guard.Reset;
    Ensure(Sweep(Guard, $20, ALLOC_MEM_IMAGE, 11000) = []);
    Ensure(Sweep(Guard, $20, ALLOC_MEM_IMAGE, 12000) = []);
    Ensure(Sweep(Guard, $40, ALLOC_MEM_IMAGE, 13000) = []);
    Detected := Sweep(Guard, $40, ALLOC_MEM_IMAGE, 14000);
    Ensure(dkImageProtection in Detected);
  finally
    Guard.Free;
  end;
  Writeln('PASS');
end.
