type
  TIPC10MCurrent = class(TDictionary<string, TIPCObservation>)
  private FCounted: Boolean;
  public constructor Create; destructor Destroy; override; end;
  TIPC10MKeys = class(TList<string>)
  private FCounted: Boolean;
  public constructor Create; destructor Destroy; override; end;
  TIPC10MRecent = class(TList<Cardinal>)
  private FCounted: Boolean;
  public constructor Create; destructor Destroy; override; end;
var IPC10MLive, IPC10MCall, IPC10MFail: Integer;
procedure IPC10MAlloc;
begin Inc(IPC10MCall); if IPC10MCall = IPC10MFail then raise EOutOfMemory.Create('injected IPC allocation'); end;
constructor TIPC10MCurrent.Create;
begin inherited Create; FCounted := True; Inc(IPC10MLive); IPC10MAlloc; end;
destructor TIPC10MCurrent.Destroy;
begin if FCounted then Dec(IPC10MLive); inherited Destroy; end;
constructor TIPC10MKeys.Create;
begin inherited Create; FCounted := True; Inc(IPC10MLive); IPC10MAlloc; end;
destructor TIPC10MKeys.Destroy;
begin if FCounted then Dec(IPC10MLive); inherited Destroy; end;
constructor TIPC10MRecent.Create;
begin inherited Create; FCounted := True; Inc(IPC10MLive); IPC10MAlloc; end;
destructor TIPC10MRecent.Destroy;
begin if FCounted then Dec(IPC10MLive); inherited Destroy; end;
