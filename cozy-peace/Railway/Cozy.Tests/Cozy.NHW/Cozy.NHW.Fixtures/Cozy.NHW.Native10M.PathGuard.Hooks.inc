type
  TPath10MList = class(TStringList)
  private FCounted: Boolean;
  public constructor Create; destructor Destroy; override; end;
var Path10MLive, Path10MCall, Path10MFail: Integer;
    Path10MQueryRaises: Boolean;
constructor TPath10MList.Create;
begin
  inherited Create; FCounted := True; Inc(Path10MLive);
  Inc(Path10MCall);
  if Path10MCall = Path10MFail then raise EOutOfMemory.Create('injected path list allocation');
end;
destructor TPath10MList.Destroy;
begin if FCounted then Dec(Path10MLive); inherited Destroy; end;
function TakeAdapterSnapshots(DNS, Interfaces: TStringList): Boolean;
begin
  if Path10MQueryRaises then raise Exception.Create('injected adapter query failure');
  Result := False;
end;
function TakeNRPTSnapshot(Policies: TStringList): Boolean;
begin Result := False; end;
function TakeWinsockCatalogSnapshot(Providers: TStringList): Boolean;
begin Result := False; end;
