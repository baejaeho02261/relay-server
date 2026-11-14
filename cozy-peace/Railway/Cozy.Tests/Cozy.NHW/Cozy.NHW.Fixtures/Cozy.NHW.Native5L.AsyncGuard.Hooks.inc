type
  TAsyncMap5L = class(TDictionary<Cardinal, Byte>)
  public
    Counted: Boolean;
    destructor Destroy; override;
  end;
  TAsyncIDs5L = class(TList<Cardinal>)
  public
    Counted: Boolean;
    destructor Destroy; override;
  end;
var
  Async5LData: TBytes;
  Async5LFetchOK: Boolean;
  Async5LFailAllocation, Async5LAllocation, Async5LAlive: Integer;
destructor TAsyncMap5L.Destroy;
begin if Counted then Dec(Async5LAlive); inherited Destroy; end;
destructor TAsyncIDs5L.Destroy;
begin if Counted then Dec(Async5LAlive); inherited Destroy; end;
function NewAsyncOwnerMap5L: TDictionary<Cardinal, Byte>;
var M: TAsyncMap5L;
begin
  Inc(Async5LAllocation);
  if Async5LAllocation = Async5LFailAllocation then
    raise EOutOfMemory.Create('synthetic owner-map allocation failure');
  M := TAsyncMap5L.Create; M.Counted := True; Inc(Async5LAlive); Result := M;
end;
function NewAsyncOwnerIDs5L: TList<Cardinal>;
var L: TAsyncIDs5L;
begin
  Inc(Async5LAllocation);
  if Async5LAllocation = Async5LFailAllocation then
    raise EOutOfMemory.Create('synthetic owner-list allocation failure');
  L := TAsyncIDs5L.Create; L.Counted := True; Inc(Async5LAlive); Result := L;
end;
function FetchSnapshot(out Buffer: TBytes; out Failure: TNTStatus): Boolean;
begin
  Buffer := Copy(Async5LData, 0, Length(Async5LData));
  Result := Async5LFetchOK; Failure := 0;
  if not Result then Failure := -1;
end;
function WinCurrentProcessId: Cardinal;
begin Result := 4242; end;
