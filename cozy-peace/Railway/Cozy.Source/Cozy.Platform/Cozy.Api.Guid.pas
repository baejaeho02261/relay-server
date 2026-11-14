unit Cozy.Api.Guid;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$IFNDEF MSWINDOWS}
  {$MESSAGE FATAL 'Cozy.Api.Guid requires Windows.'}
{$ENDIF}
{$IFNDEF CPUX64}
  {$MESSAGE FATAL 'Cozy.Api.Guid requires the Delphi x64 compiler.'}
{$ENDIF}
{$B-}
{$IF SizeOf(TGUID) <> 16}
  {$MESSAGE FATAL 'GUID must use the 16-byte Windows ABI.'}
{$ENDIF}
{$IF SizeOf(LongInt) <> 4}
  {$MESSAGE FATAL 'HRESULT must be a signed 32-bit value.'}
{$ENDIF}

interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Platform;


{ Windows GUID creation only. Keep the signed 32-bit HRESULT and out GUID.
  The caller still owns the existing success check and string formatting. }
function WindowsApiCreateGUID(out Guid: TGUID): LongInt;

implementation

uses
  Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver;

type
  TApiCoCreateGuid = function(out Guid: TGUID): LongInt; stdcall;

var
  ApiSlot_CoCreateGuid: TEncodedApiPointer;

function WindowsApiCreateGUID(out Guid: TGUID): LongInt;
var
  ApiTarget: TApiCoCreateGuid;
  Candidate: TGUID;
begin
  FillChar(Guid, SizeOf(Guid), 0);
  FillChar(Candidate, SizeOf(Candidate), 0);
  if (NativeUInt(@Candidate.D2) - NativeUInt(@Candidate) <> 4) or
     (NativeUInt(@Candidate.D3) - NativeUInt(@Candidate) <> 6) or
     (NativeUInt(@Candidate.D4) - NativeUInt(@Candidate) <> 8) then
    Exit(-2147418113); // E_UNEXPECTED: invalid ABI, no OS call.
  try
    ApiTarget := TApiCoCreateGuid(DecodeApiPointer(ApiSlot_CoCreateGuid));
    Result := ApiTarget(Candidate);
    { Only S_OK publishes the output. Failed calls cannot expose a previous
      GUID or a partially written candidate as a usable identifier. }
    if Result = 0 then Guid := Candidate;
  finally
    FillChar(Candidate, SizeOf(Candidate), 0);
  end;
end;

initialization
  { Cozy.Platform.ExportResolver initializes the loader and pointer codec first.
    No independent loader, name-string lookup, or PE-header write is added. }
  BindApiPointer(ApiSlot_CoCreateGuid,
    RequireProcAddressHash64(CozyText_Api_Guid_ole32_dll_32775c3b, HASH_CoCreateGuid));

end.
