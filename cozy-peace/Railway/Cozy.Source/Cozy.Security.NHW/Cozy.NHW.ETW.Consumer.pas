unit Cozy.NHW.ETW.Consumer;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.Classes, System.SyncObjs, Cozy.NHW.ETWNative;

type
  TETWConsumerThread = class(TThread)
  private
    FTrace: UInt64;
    FWorkerFinished: LongInt;
  protected
    procedure Execute; override;
  public
    constructor Create(Handle: UInt64);
    function ProcessingStopped: Boolean;
  end;

implementation

constructor TETWConsumerThread.Create(Handle: UInt64);
begin
  { Execute reads only these POD fields. Initialize before the RTL starts the
    owned thread; no separately started suspended thread can escape failure. }
  FTrace := Handle;
  FWorkerFinished := 0;
  inherited Create(False);
  FreeOnTerminate := False;
end;

function TETWConsumerThread.ProcessingStopped: Boolean;
begin
  Result := TInterlocked.CompareExchange(FWorkerFinished, 0, 0) <> 0;
end;

procedure TETWConsumerThread.Execute;
begin
  try
    try
      if Assigned(EtwProcessTrace) then
        EtwProcessTrace(@FTrace, 1, nil, nil);
    except
      // No console output; process tracing may fail independently.
    end;
  finally
    TInterlocked.Exchange(FWorkerFinished, 1);
  end;
end;

end.
