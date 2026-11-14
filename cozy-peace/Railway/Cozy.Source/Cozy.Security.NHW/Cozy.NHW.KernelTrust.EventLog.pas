unit Cozy.NHW.KernelTrust.EventLog;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

type
  TCodeIntegrityEventSummary = record
    Valid: Boolean;
    LatestRecordId: UInt64;
    NewRecordCount: Cardinal;
    StrongMask: Cardinal;
    Fingerprint: UInt64;
  end;

const
  CIE_DRIVER_SIGNATURE = $00000001;
  CIE_HVCI_INTEGRITY   = $00000002;
  CIE_POLICY_FAILURE   = $00000004;

function CaptureCodeIntegrityEventSummary(AfterRecordId: UInt64;
  out Summary: TCodeIntegrityEventSummary): Boolean;
function ClassifyCodeIntegrityEvent(EventId: Cardinal): Cardinal;

implementation

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.WinPointers;

const
  EVT_QUERY_CHANNEL_PATH = $00000001;
  EVT_QUERY_REVERSE_DIRECTION = $00000200;
  EVT_RENDER_EVENT_XML = 1;
  ERROR_NO_MORE_ITEMS_LOCAL = 259;
  MAX_CI_EVENTS_PER_SCAN = 64;
  CODE_INTEGRITY_CHANNEL = 'Microsoft-Windows-CodeIntegrity/Operational';
  CODE_INTEGRITY_QUERY = '*[System[(EventID=3004 or EventID=3023 or '
    + 'EventID=3074 or EventID=3095 or EventID=3097 or EventID=3100 or '
    + 'EventID=3111)]]';

type
  TEvtQuery = function(Session: THandle; Path, Query: PWideChar;
    Flags: Cardinal): THandle; stdcall;
  TEvtNext = function(ResultSet: THandle; EventArraySize: Cardinal;
    EventArray: Pointer; Timeout, Flags: Cardinal;
    out Returned: Cardinal): BOOL; stdcall;
  TEvtRender = function(Context, Fragment: THandle; Flags, BufferSize: Cardinal;
    Buffer: Pointer; out BufferUsed, PropertyCount: Cardinal): BOOL; stdcall;
  TEvtClose = function(ObjectHandle: THandle): BOOL; stdcall;

var
  EvtQueryPtr: TEvtQuery = nil;
  EvtNextPtr: TEvtNext = nil;
  EvtRenderPtr: TEvtRender = nil;
  EvtClosePtr: TEvtClose = nil;
  EvtResolved: Boolean = False;

procedure ResolveEventLog;
var M: HMODULE;
begin
  if EvtResolved then Exit;
  M := WinLoadLibrary('wevtapi.dll');
  if M = 0 then Exit;
  EvtQueryPtr := TEvtQuery(WinExport(M, 'EvtQuery'));
  EvtNextPtr := TEvtNext(WinExport(M, 'EvtNext'));
  EvtRenderPtr := TEvtRender(WinExport(M, 'EvtRender'));
  EvtClosePtr := TEvtClose(WinExport(M, 'EvtClose'));
  EvtResolved := Assigned(EvtQueryPtr) and Assigned(EvtNextPtr) and
    Assigned(EvtRenderPtr) and Assigned(EvtClosePtr);
end;

function RenderEventXml(EventHandle: THandle; out Xml: string): Boolean;
var
  Needed, Props, CharCount: Cardinal;
  Buffer: TBytes;
begin
  Result := False;
  Xml := '';
  Needed := 0;
  Props := 0;
  if EvtRenderPtr(0, EventHandle, EVT_RENDER_EVENT_XML, 0, nil,
       Needed, Props) then Exit;
  if (GetLastError <> ERROR_INSUFFICIENT_BUFFER) or
     (Needed < SizeOf(WideChar)) or (Needed > 4 * 1024 * 1024) then Exit;
  SetLength(Buffer, Needed);
  if not EvtRenderPtr(0, EventHandle, EVT_RENDER_EVENT_XML, Needed,
       @Buffer[0], Needed, Props) then Exit;
  CharCount := Needed div SizeOf(WideChar);
  if (CharCount > 0) and (PWideChar(@Buffer[0])[CharCount - 1] = #0) then
    Dec(CharCount);
  SetString(Xml, PWideChar(@Buffer[0]), CharCount);
  Result := Xml <> '';
end;

function ExtractTagUInt64(const Xml, Tag: string; out Value: UInt64): Boolean;
var
  P, G, E: Integer;
  S: string;
begin
  Result := False;
  Value := 0;
  P := Pos('<' + Tag, Xml);
  if P = 0 then Exit;
  G := Pos('>', Copy(Xml, P, MaxInt));
  if G = 0 then Exit;
  G := P + G - 1;
  E := Pos('</' + Tag + '>', Copy(Xml, G + 1, MaxInt));
  if E = 0 then Exit;
  E := G + E;
  S := Trim(Copy(Xml, G + 1, E - G - 1));
  if S = '' then Exit;
  try
    Value := StrToUInt64(S);
    Result := True;
  except
    Result := False;
  end;
end;

function HashEventFingerprint(Current: UInt64; RecordId: UInt64;
  EventId: Cardinal): UInt64; inline;
begin
  Result := Current xor RecordId;
  Result := Result * UInt64($100000001B3);
  Result := Result xor UInt64(EventId);
  Result := Result * UInt64($100000001B3);
end;

function ClassifyCodeIntegrityEvent(EventId: Cardinal): Cardinal;
begin
  case EventId of
    3004, 3023:
      Result := CIE_DRIVER_SIGNATURE;
    3074, 3111:
      Result := CIE_HVCI_INTEGRITY;
    3095, 3097, 3100:
      Result := CIE_POLICY_FAILURE;
  else
    Result := 0;
  end;
end;

function CaptureCodeIntegrityEventSummary(AfterRecordId: UInt64;
  out Summary: TCodeIntegrityEventSummary): Boolean;
var
  QueryHandle, EventHandle: THandle;
  Returned, I: Cardinal;
  Xml: string;
  RecordId, EventId64: UInt64;
  Mask: Cardinal;
  LastErrorCode: Cardinal;
begin
  Summary := Default(TCodeIntegrityEventSummary);
  Result := False;
  ResolveEventLog;
  if not EvtResolved then Exit;
  QueryHandle := EvtQueryPtr(0, PWideChar(CODE_INTEGRITY_CHANNEL),
    PWideChar(CODE_INTEGRITY_QUERY), EVT_QUERY_CHANNEL_PATH or
    EVT_QUERY_REVERSE_DIRECTION);
  if QueryHandle = 0 then Exit;
  Summary.Fingerprint := UInt64($CBF29CE484222325);
  try
    for I := 0 to MAX_CI_EVENTS_PER_SCAN - 1 do
    begin
      EventHandle := 0;
      Returned := 0;
      if not EvtNextPtr(QueryHandle, 1, @EventHandle, 0, 0, Returned) then
      begin
        LastErrorCode := GetLastError;
        if LastErrorCode = ERROR_NO_MORE_ITEMS_LOCAL then Break;
        Exit;
      end;
      if (Returned = 0) or (EventHandle = 0) then Break;
      try
        if not RenderEventXml(EventHandle, Xml) then Continue;
        if not ExtractTagUInt64(Xml, 'EventRecordID', RecordId) then Continue;
        if RecordId > Summary.LatestRecordId then
          Summary.LatestRecordId := RecordId;
        if (AfterRecordId <> 0) and (RecordId <= AfterRecordId) then Break;
        if not ExtractTagUInt64(Xml, 'EventID', EventId64) or
           (EventId64 > High(Cardinal)) then Continue;
        Mask := ClassifyCodeIntegrityEvent(Cardinal(EventId64));
        if Mask = 0 then Continue;
        Inc(Summary.NewRecordCount);
        Summary.StrongMask := Summary.StrongMask or Mask;
        Summary.Fingerprint := HashEventFingerprint(Summary.Fingerprint,
          RecordId, Cardinal(EventId64));
      finally
        EvtClosePtr(EventHandle);
      end;
    end;
    Summary.Valid := True;
    Result := True;
  finally
    EvtClosePtr(QueryHandle);
  end;
end;

end.
