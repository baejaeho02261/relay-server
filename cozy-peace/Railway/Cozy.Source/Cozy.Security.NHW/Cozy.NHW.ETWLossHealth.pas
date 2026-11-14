unit Cozy.NHW.ETWLossHealth;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging, Cozy.NHW.ETW;

type
  TETWLossSnapshot = record
    Available: Boolean;
    EventsLost: Cardinal;
    LogBuffersLost: Cardinal;
    RealTimeBuffersLost: Cardinal;
  end;

  // Optional ETW unavailable != attack. A failed query != a new session.
  TETWLossHealth = class
  private
    FPrevious: TETWLossSnapshot;
    FPrimed, FHasQuery, FReported, FHaveTick: Boolean;
    FSourceOwner: NativeUInt;
    FSourceThread: Cardinal;
    FSourceReady, FQueryGap, FCounterDiscontinuity: Boolean;
    FLastQuery, FLastReport, FLastTick: UInt64;
    procedure SelectSource(Owner: NativeUInt; ConsumerID: Cardinal;
      IsReady: Boolean);
    procedure AcceptSample(const Cur: TETWLossSnapshot; Tick: UInt64;
      var Loss: Boolean);
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Trace: TETWMonitor; QueueGap: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
    property QueryGap: Boolean read FQueryGap;
    property CounterDiscontinuity: Boolean read FCounterDiscontinuity;
  end;

function TraceCountersAdvanced(const Before, After: TETWLossSnapshot): Boolean;
{$IFDEF NHW_NATIVE5J_TESTS}
function TestETWLoss5J(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation
{$IFDEF NHW_NATIVE5J_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  HEALTH_QUERY_PERIOD_MS = 5000;
  HEALTH_REPORT_COOLDOWN_MS = 30000;

function CountersDecreased(const Before, After: TETWLossSnapshot): Boolean;
begin
  Result := (After.EventsLost < Before.EventsLost) or
    (After.LogBuffersLost < Before.LogBuffersLost) or
    (After.RealTimeBuffersLost < Before.RealTimeBuffersLost);
end;

function TraceCountersAdvanced(const Before, After: TETWLossSnapshot): Boolean;
begin
  Result := Before.Available and After.Available and
    not CountersDecreased(Before, After) and
    ((After.EventsLost > Before.EventsLost) or
     (After.LogBuffersLost > Before.LogBuffersLost) or
     (After.RealTimeBuffersLost > Before.RealTimeBuffersLost));
end;

constructor TETWLossHealth.Create;
begin inherited Create; Reset; end;

procedure TETWLossHealth.Reset;
begin
  FPrevious := Default(TETWLossSnapshot);
  FPrimed := False; FHasQuery := False; FReported := False; FHaveTick := False;
  FSourceOwner := 0; FSourceThread := 0; FSourceReady := False;
  FQueryGap := False; FCounterDiscontinuity := False;
  FLastQuery := 0; FLastReport := 0; FLastTick := 0;
end;

procedure TETWLossHealth.SelectSource(Owner: NativeUInt; ConsumerID: Cardinal;
  IsReady: Boolean);
begin
  if not IsReady or (Owner = 0) or (Owner <> FSourceOwner) or
     (ConsumerID <> FSourceThread) or not FSourceReady then
  begin
    FPrevious := Default(TETWLossSnapshot);
    FPrimed := False;
    FHasQuery := False;
    FQueryGap := False;
    FCounterDiscontinuity := False;
  end;
  FSourceOwner := Owner;
  FSourceThread := ConsumerID;
  FSourceReady := IsReady and (Owner <> 0);
end;

procedure TETWLossHealth.AcceptSample(const Cur: TETWLossSnapshot;
  Tick: UInt64; var Loss: Boolean);
begin
  FLastQuery := Tick;
  FHasQuery := True;
  if not Cur.Available then
  begin
    FQueryGap := True;
    // Preserve the last successful counters in the same observed source.
    // Do not manufacture zero counters or discard unobserved increases.
    Exit;
  end;
  FCounterDiscontinuity := FPrimed and CountersDecreased(FPrevious, Cur);
  if FPrimed and not FCounterDiscontinuity and
     TraceCountersAdvanced(FPrevious, Cur) then Loss := True;
  // A decrease could be reset, rollover or a different lifetime. There is
  // insufficient generation metadata here to choose one or count its loss.
  FPrevious := Cur;
  FPrimed := True;
  FQueryGap := False;
end;

procedure TETWLossHealth.Examine(Trace: TETWMonitor; QueueGap: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Loss, IsReady: Boolean;
  Owner: NativeUInt;
  ConsumerID: Cardinal;

  procedure ApplyClockBoundary;
  begin
    if FHaveTick and (Tick < FLastTick) then
    begin
      FPrimed := False;
      FHasQuery := False;
      FPrevious := Default(TETWLossSnapshot);
      FQueryGap := True;
    end;
    FLastTick := Tick;
    FHaveTick := True;
  end;

  procedure CaptureSourceIdentity;
  begin
    Owner := 0;
    ConsumerID := 0;
    IsReady := False;
    if Trace <> nil then
    begin
      Owner := NativeUInt(Trace);
      IsReady := Trace.Ready;
      if IsReady then ConsumerID := Trace.ConsumerThreadID;
    end;
  end;

  procedure QueryCountersIfDue;
  var
    Cur: TETWLossSnapshot;
  begin
    if not FSourceReady or (FHasQuery and (Tick >= FLastQuery) and
       (Tick - FLastQuery < HEALTH_QUERY_PERIOD_MS)) then Exit;
    Cur := Default(TETWLossSnapshot);
    try
      Cur.Available := Trace.QueryLossCounters(Cur.EventsLost,
        Cur.LogBuffersLost, Cur.RealTimeBuffersLost);
    except
      FQueryGap := True;
      FLastQuery := Tick;
      FHasQuery := True;
      raise;
    end;
    if Trace.Ready and (Trace.ConsumerThreadID = ConsumerID) then
      AcceptSample(Cur, Tick, Loss)
    else
      SelectSource(Owner, 0, False);
  end;

  procedure ReportLossIfDue;
  begin
    if Loss and ((not FReported) or (Tick < FLastReport) or
       (Tick - FLastReport >= HEALTH_REPORT_COOLDOWN_MS)) then
    begin
      Include(Detected, dkETWLoss);
      FLastReport := Tick;
      FReported := True;
    end;
  end;
begin
  Loss := QueueGap;
  ApplyClockBoundary;
  CaptureSourceIdentity;
  SelectSource(Owner, ConsumerID, IsReady);
  QueryCountersIfDue;
  ReportLossIfDue;
end;

{$IFDEF NHW_NATIVE5J_TESTS}
{$I Cozy.NHW.Native5J.ETWLoss.inc}
{$ENDIF}
end.
