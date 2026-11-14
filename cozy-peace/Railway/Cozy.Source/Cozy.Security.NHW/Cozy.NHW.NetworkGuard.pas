unit Cozy.NHW.NetworkGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  System.Classes,
  Cozy.NHW.Logging,
  Cozy.NHW.NetworkRules;

type
  TNetworkGuard = class
  private
    FFilters, FCallouts, FProviders: TChangeGate;
    FRoutes, FProxy: TChangeGate;
    FNextPoll: UInt64;
    FLastFilterTick, FLastPathTick, FLastCorrelatedTick: UInt64;
    procedure CheckCorrelation(Tick: UInt64; var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5L_TESTS}
function TestNetworkGuard5L(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.NetworkNative;

const
  POLL_INTERVAL_MS = 12000;
  CORRELATION_WINDOW_MS = 30000;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.NetworkGuard.Hooks.inc}
{$ENDIF}

function NewKeyList: TStringList;
begin
{$IFDEF NHW_NATIVE5L_TESTS}
  Result := NewNetworkKeyList5L;
{$ELSE}
  Result := TStringList.Create;
{$ENDIF}
  try
    Result.Sorted := True;
    Result.Duplicates := dupIgnore;
    Result.CaseSensitive := True;
  except
    Result.Free;
    raise;
  end;
end;

constructor TNetworkGuard.Create;
begin
  inherited Create;
  FFilters := TChangeGate.Create;
  FCallouts := TChangeGate.Create;
  FProviders := TChangeGate.Create;
  FRoutes := TChangeGate.Create;
  FProxy := TChangeGate.Create;
  Reset;
end;

destructor TNetworkGuard.Destroy;
begin
  FProxy.Free;
  FRoutes.Free;
  FProviders.Free;
  FCallouts.Free;
  FFilters.Free;
  inherited Destroy;
end;

procedure TNetworkGuard.Reset;
begin
  FFilters.Reset;
  FCallouts.Reset;
  FProviders.Reset;
  FRoutes.Reset;
  FProxy.Reset;
  FNextPoll := 0;
  FLastFilterTick := 0;
  FLastPathTick := 0;
  FLastCorrelatedTick := 0;
end;

procedure TNetworkGuard.CheckCorrelation(Tick: UInt64;
  var Detected: TDetectionKinds);
var Later: UInt64;
begin
  // Correlation means multiple *environment changes*, not packet capture.
  if (FLastFilterTick = 0) or (FLastPathTick = 0) then Exit;
  if FLastFilterTick > FLastPathTick then Later := FLastFilterTick
  else Later := FLastPathTick;
  if (Tick - Later > CORRELATION_WINDOW_MS) then Exit;
  if (FLastFilterTick > FLastPathTick) and
     (FLastFilterTick - FLastPathTick > CORRELATION_WINDOW_MS) then Exit;
  if (FLastPathTick > FLastFilterTick) and
     (FLastPathTick - FLastFilterTick > CORRELATION_WINDOW_MS) then Exit;
  if Later <= FLastCorrelatedTick then Exit;
  Include(Detected, dkNetworkCorrelation);
  FLastCorrelatedTick := Later;
end;

procedure TNetworkGuard.Examine(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  F, C, P, R, Proxy: TStringList;
  FilterChanged, PathChanged: Boolean;

  procedure CollectFilterChanges;
  begin
    if TakeWFPSnapshots(F, C, P) then
    begin
      if FFilters.Observe(F) then
      begin
        Include(Detected, dkNetworkFilter);
        FilterChanged := True;
      end;
      if FCallouts.Observe(C) then
      begin
        Include(Detected, dkWFPCallout);
        FilterChanged := True;
      end;
      if FProviders.Observe(P) then
      begin
        Include(Detected, dkWFPProvider);
        FilterChanged := True;
      end;
    end;
  end;

  procedure CollectPathChanges;
  begin
    if TakeDefaultRouteSnapshot(R) and FRoutes.Observe(R) then
    begin
      Include(Detected, dkRouteChange);
      PathChanged := True;
    end;
    if TakeProxySnapshot(Proxy) and FProxy.Observe(Proxy) then
    begin
      Include(Detected, dkProxyChange);
      PathChanged := True;
    end;
  end;

  procedure ReflectCorrelationTimes;
  begin
    if FilterChanged then FLastFilterTick := Tick;
    if PathChanged then FLastPathTick := Tick;
    CheckCorrelation(Tick, Detected);
  end;

begin
  if Tick < FNextPoll then Exit;
  FNextPoll := Tick + POLL_INTERVAL_MS;
  F := nil;
  C := nil;
  P := nil;
  R := nil;
  Proxy := nil;
  try
    // Every successful allocation is owned by this cleanup, even when
    // a later allocation or native snapshot raises.
    F := NewKeyList;
    C := NewKeyList;
    P := NewKeyList;
    R := NewKeyList;
    Proxy := NewKeyList;
    FilterChanged := False;
    PathChanged := False;
    CollectFilterChanges;
    CollectPathChanges;
    ReflectCorrelationTimes;
  finally
    Proxy.Free;
    R.Free;
    P.Free;
    C.Free;
    F.Free;
  end;
end;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.NetworkGuard.inc}
{$ENDIF}

end.
