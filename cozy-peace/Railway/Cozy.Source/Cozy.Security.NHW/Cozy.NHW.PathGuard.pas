unit Cozy.NHW.PathGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  System.Classes,
  Cozy.NHW.Logging,
  Cozy.NHW.NetworkRules,
  Cozy.NHW.PathRules;

type
  TPathGuard = class
  private
    FDNSServers, FPolicies, FProviders, FInterfaces: TChangeGate;
    FRules: TPathSignalRules;
    FNextPoll: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestPathGuard10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.PathNative;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.PathGuard.Hooks.inc}
{$ENDIF}

const
  POLL_INTERVAL_MS = 12000;

function NewSortedList: TStringList;
begin
  {$IFDEF NHW_NATIVE10M_TESTS}Result := TPath10MList.Create;{$ELSE}Result := TStringList.Create;{$ENDIF}
  try
    Result.Sorted := True;
    Result.Duplicates := dupIgnore;
    Result.CaseSensitive := True;
  except
    Result.Free;
    raise;
  end;
end;

constructor TPathGuard.Create;
begin
  inherited Create;
  FDNSServers := TChangeGate.Create;
  FPolicies := TChangeGate.Create;
  FProviders := TChangeGate.Create;
  FInterfaces := TChangeGate.Create;
  FRules := TPathSignalRules.Create;
  Reset;
end;

destructor TPathGuard.Destroy;
begin
  FRules.Free;
  FInterfaces.Free;
  FProviders.Free;
  FPolicies.Free;
  FDNSServers.Free;
  inherited Destroy;
end;

procedure TPathGuard.Reset;
begin
  FDNSServers.Reset;
  FPolicies.Reset;
  FProviders.Reset;
  FInterfaces.Reset;
  FRules.Reset;
  FNextPoll := 0;
end;

procedure TPathGuard.Examine(Tick: UInt64; var Detected: TDetectionKinds);
var
  DNS, Interfaces, Policies, Providers: TStringList;
  AdapterValid: Boolean;
begin
  // NetworkGuard.Examine must run first on the same iteration. A route
  // event contributes to correlation, not a claim of interception.
  if dkRouteChange in Detected then
    FRules.Signal(pcRoute, Tick, Detected);
  if Tick < FNextPoll then Exit;
  FNextPoll := Tick + POLL_INTERVAL_MS;
  DNS := nil;
  Interfaces := nil;
  Policies := nil;
  Providers := nil;
  try
    DNS := NewSortedList;
    Interfaces := NewSortedList;
    Policies := NewSortedList;
    Providers := NewSortedList;
    AdapterValid := TakeAdapterSnapshots(DNS, Interfaces);
    if AdapterValid then
    begin
      if FDNSServers.Observe(DNS) then
      begin
        Include(Detected, dkDNSServer);
        FRules.Signal(pcDNSServer, Tick, Detected);
      end;
      if FInterfaces.Observe(Interfaces) then
      begin
        Include(Detected, dkInterfaceChange);
        FRules.Signal(pcInterface, Tick, Detected);
      end;
    end;
    if TakeNRPTSnapshot(Policies) and FPolicies.Observe(Policies) then
    begin
      Include(Detected, dkDNSPolicy);
      FRules.Signal(pcDNSPolicy, Tick, Detected);
    end;
    if TakeWinsockCatalogSnapshot(Providers) and FProviders.Observe(Providers) then
    begin
      Include(Detected, dkWinsockProvider);
      FRules.Signal(pcWinsock, Tick, Detected);
    end;
  finally
    Providers.Free;
    Policies.Free;
    Interfaces.Free;
    DNS.Free;
  end;
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.PathGuard.inc}
{$ENDIF}

end.
