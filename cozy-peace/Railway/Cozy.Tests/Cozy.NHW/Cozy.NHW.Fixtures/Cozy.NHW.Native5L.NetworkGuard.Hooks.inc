type
  TNetworkList5L = class(TStringList)
  public
    Counted: Boolean;
    destructor Destroy; override;
  end;
var
  Network5LAlive, Network5LAllocations, Network5LFailAllocation: Integer;
  Network5LCalls, Network5LFailProbe, Network5LRound: Integer;
destructor TNetworkList5L.Destroy;
begin if Counted then Dec(Network5LAlive); inherited Destroy; end;
function NewNetworkKeyList5L: TStringList;
var L: TNetworkList5L;
begin
  Inc(Network5LAllocations);
  if Network5LAllocations = Network5LFailAllocation then
    raise EOutOfMemory.Create('synthetic network-list allocation failure');
  L := TNetworkList5L.Create; L.Counted := True; Inc(Network5LAlive); Result := L;
end;
function TakeWFPSnapshots(Filters, Callouts, Providers: TStrings): Boolean;
begin
  Inc(Network5LCalls);
  if Network5LFailProbe = 1 then raise Exception.Create('synthetic WFP failure');
  Filters.Add('F' + IntToStr(Network5LRound)); Callouts.Add('C' + IntToStr(Network5LRound));
  Providers.Add('P' + IntToStr(Network5LRound)); Result := True;
end;
function TakeDefaultRouteSnapshot(Routes: TStrings): Boolean;
begin
  Inc(Network5LCalls);
  if Network5LFailProbe = 2 then raise Exception.Create('synthetic route failure');
  Routes.Add('R' + IntToStr(Network5LRound)); Result := True;
end;
function TakeProxySnapshot(Proxy: TStrings): Boolean;
begin
  Inc(Network5LCalls);
  if Network5LFailProbe = 3 then raise Exception.Create('synthetic proxy failure');
  Proxy.Add('P' + IntToStr(Network5LRound)); Result := True;
end;
