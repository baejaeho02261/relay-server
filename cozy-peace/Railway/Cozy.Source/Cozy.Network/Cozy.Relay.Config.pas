unit Cozy.Relay.Config;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

interface

const
  RELAY_HOST = ''; { Endpoint comes from the administrator's verified profile. }
  RELAY_PORT = 0;
  RELAY_BACKUP_HOST = '';
  RELAY_BACKUP_PORT = 0;

  PROTOCOL_VERSION = 2;

  RECONNECT_1 = 500;
  RECONNECT_2 = 1000;
  RECONNECT_3 = 2000;
  RECONNECT_4 = 3000;
  RECONNECT_5 = 5000;

  MAX_INPUT_BUFFER = 1024 * 1024;
  MAX_REQUEST_CACHE = 10000;
  REQUEST_CACHE_TIMEOUT_MS = 10 * 60 * 1000;

implementation

end.
