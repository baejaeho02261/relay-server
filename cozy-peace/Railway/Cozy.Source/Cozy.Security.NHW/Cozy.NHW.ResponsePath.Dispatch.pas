unit Cozy.NHW.ResponsePath.Dispatch;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

type
  TResponsePathChannel = (rpcTrust, rpcDriver, rpcIntegrity);

  TResponsePathEvent = record
    Channel: TResponsePathChannel;
    Sequence: UInt64;
    Tick: UInt64;
    Digest: UInt64;
  end;

  TResponsePathSink = procedure(const Event: TResponsePathEvent) of object;

implementation

end.
