unit Cozy.NHW.FalsePositiveControl;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TNewSignalSuppressor = class
  private
    FReported: array[TDetectionKind] of Boolean;
    FLastReport: array[TDetectionKind] of UInt64;
  public
    constructor Create;
    procedure Reset;
    // Apply is retained for callers already holding an OUTPUT-ONLY copy.
    function FilterForOutput(const Observed: TDetectionKinds;
      Baseline: Boolean; Tick: UInt64): TDetectionKinds;
    procedure Apply(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function IsV60Signal(Kind: TDetectionKind): Boolean;
function ShouldSuppressNewSignal(WasReported: Boolean;
  LastTick, CurrentTick, CooldownMS: UInt64): Boolean;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestFalsePositiveControl10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10O_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  V60_NEW_EVENT_COOLDOWN_MS = 60000;

function IsV60Signal(Kind: TDetectionKind): Boolean;
begin
  Result := Kind in [dkImportRedirect, dkTLSCallbackIntegrity,
    dkUnwindStructural, dkExecutableLifecycle, dkSectionBacking,
    dkThreadStackOrigin];
end;

function ShouldSuppressNewSignal(WasReported: Boolean;
  LastTick, CurrentTick, CooldownMS: UInt64): Boolean;
begin
  Result := WasReported and (CurrentTick >= LastTick) and
    (CurrentTick - LastTick < CooldownMS);
end;

constructor TNewSignalSuppressor.Create;
begin inherited Create; Reset; end;

procedure TNewSignalSuppressor.Reset;
begin
  FillChar(FReported, SizeOf(FReported), 0);
  FillChar(FLastReport, SizeOf(FLastReport), 0);
end;

function TNewSignalSuppressor.FilterForOutput(const Observed: TDetectionKinds;
  Baseline: Boolean; Tick: UInt64): TDetectionKinds;
begin
  Result := Observed;
  Apply(Baseline, Tick, Result);
end;

procedure TNewSignalSuppressor.Apply(Baseline: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var K: TDetectionKind;
begin
  // Output-only filtering. Never pass the internal evidence set by reference.
  // Never suppress or alter a detection inherited from v1-v50.
  for K := Low(TDetectionKind) to High(TDetectionKind) do
  begin
    if not IsV60Signal(K) or not (K in Detected) then Continue;
    if Baseline or ShouldSuppressNewSignal(FReported[K],
       FLastReport[K], Tick, V60_NEW_EVENT_COOLDOWN_MS) then
      Exclude(Detected, K)
    else
    begin
      FReported[K] := True;
      FLastReport[K] := Tick;
    end;
  end;
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.FalsePositiveControl.inc}
{$ENDIF}

end.
