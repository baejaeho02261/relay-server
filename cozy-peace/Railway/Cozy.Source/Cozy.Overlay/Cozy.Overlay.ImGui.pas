unit Cozy.Overlay.ImGui;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF MSWINDOWS}
  {$MESSAGE FATAL 'Cozy.Overlay.ImGui requires Windows.'}
{$ENDIF}
{$IFNDEF CPUX64}
  {$MESSAGE FATAL 'Cozy.Overlay.ImGui requires the classic Delphi Win64 compiler.'}
{$ENDIF}
{$ALIGN 8}
{$B-}

interface
{ Cozy central text imports. }
uses
{ Cozy central text imports. }
  Cozy.Strings.Overlay,

  System.SysUtils;


type
  { Opaque handle: no version-dependent ImGui/C++ structures cross this ABI. }
  TImGuiContext = Pointer;
  { Only this closed stage set and numeric native code may enter diagnostics.
    Exception text remains a fixed internal code; font paths, OS messages and
    driver-provided strings must never cross the reporting boundary. A zero
    NativeCode means that no reliable native status was available. }
  TOverlayImGuiFailureStage = (igfsBinding, igfsFontRead, igfsFontData,
    igfsCreate, igfsResize);
  EOverlayImGuiFailure = class(Exception)
  private
    FStage: TOverlayImGuiFailureStage;
    FNativeCode: Integer;
  public
    constructor Create(FailureStage: TOverlayImGuiFailureStage; NativeStatus: Integer;
      const SafeMessage: string); reintroduce;
    property Stage: TOverlayImGuiFailureStage read FStage;
    property NativeCode: Integer read FNativeCode;
  end;
  TImGuiTextInputAction = (itiaCommit, itiaPreedit, itiaBegin, itiaEnd,
    itiaCancel);

const
  IMGUI_PRESENT_FAILED = -1;
  IMGUI_PRESENT_OCCLUDED = 0;
  IMGUI_PRESENT_VISIBLE = 1;
  IMGUI_SCENE_PREVIOUS = 2;
  IMGUI_SCENE_NEXT = 4;
  IMGUI_SCENE_RUN = 8;
  IMGUI_SCENE_SELECT_FIRST = 128;
  IMGUI_SCENE_SELECT_SECOND = 256;
  IMGUI_SCENE_SELECT_THIRD = 512;
  IMGUI_SCENE_SELECT_FOURTH = 1024;
  IMGUI_SCENE_SELECT_FIFTH = 2048;
  IMGUI_SCENE_SELECT_SIXTH = 4096;
  IMGUI_SCENE_TAB_CLEANNER = 8192;
  IMGUI_SCENE_TAB_MOBILE = 16384;
  IMGUI_SCENE_TAB_SPOOFER = 32768;
  IMGUI_SCENE_REDUCED_MOTION = 2;
  IMGUI_SCENE_RUN_AVAILABLE = 4;

{ The supplied Dear ImGui core and D3D11 backend are linked into O itself.
  Window ownership, authorization, presentation state and input stay in Delphi.
  The native bridge constructs one bounded reviewed product scene.
  Call all functions on the owning UI thread. Strings are temporary UTF-8;
  the bridge consumes them synchronously and does not retain their pointers. }
function ImGuiCreate(Window: NativeUInt; LicenseOnly: Boolean = False): TImGuiContext;
procedure ImGuiDestroy(var Context: TImGuiContext);
function ImGuiResize(Context: TImGuiContext; Width, Height: Integer): Boolean;
function ImGuiSetDpi(Context: TImGuiContext; Scale: Single): Boolean;
function ImGuiNewFrame(Context: TImGuiContext; Width, Height: Integer;
  DeltaSeconds: Single): Boolean;
procedure ImGuiBeginCanvas(Context: TImGuiContext);
procedure ImGuiSetCursorPos(Context: TImGuiContext; X, Y: Single);
function ImGuiButton(Context: TImGuiContext; LabelText: PAnsiChar;
  Width, Height: Single; Enabled: Boolean = True): Boolean;
procedure ImGuiText(Context: TImGuiContext; Text: PAnsiChar);
{ Compatibility gallery denies START without a product-bound authorization. }
function ImGuiScene(Context: TImGuiContext; Phase, Selected: Integer;
  Flags: Cardinal; AnimationSeconds, CarouselPosition: Single): Integer;
{ ABI v3: final scene floats are normalized progress, not elapsed time.
  O begins presentation only after authorization; B reports real worker steps. }
function ImGuiProductScene(Context: TImGuiContext; Phase, Selected: Integer;
  Flags: Cardinal; AnimationSeconds, CarouselPosition: Single;
  LicensedCard: Integer; RunProgress: Single): Integer;
function ImGuiLicenseScene(Context: TImGuiContext; Phase, KeyCharacters: Integer;
  Progress: Single): Integer;
procedure ImGuiEndCanvas(Context: TImGuiContext);
function ImGuiPresent(Context: TImGuiContext): Integer;
procedure ImGuiMousePos(Context: TImGuiContext; X, Y: Single);
procedure ImGuiMouseButton(Context: TImGuiContext; Button: Integer; Down: Boolean);
procedure ImGuiMouseWheel(Context: TImGuiContext; Horizontal, Vertical: Single);
{ Key is a Win32 VK_* value. The bridge privately maps it to its own version. }
procedure ImGuiKey(Context: TImGuiContext; Key: Integer; Down: Boolean);
procedure ImGuiFocus(Context: TImGuiContext; Focused: Boolean);
procedure ImGuiClearInput(Context: TImGuiContext);
{ Explicit application-local input only. A display-only context has no input
  allocation. Focus loss, cancellation, disable and destroy wipe queued bytes.
  Korean v1 accepts printable ASCII and Hangul/Jamo; at most 512 UTF-8 bytes.
  The caller owns any returned string and must not log sensitive input. }
function ImGuiTextInputEnable(Context: TImGuiContext; Enabled: Boolean): Boolean;
function ImGuiTextInputEvent(Context: TImGuiContext; Action: TImGuiTextInputAction;
  const Text: UTF8String): Boolean;
function ImGuiTextInputUtf16(Context: TImGuiContext; CodeUnit: Cardinal): Boolean;
function ImGuiTextInputRead(Context: TImGuiContext; Preedit: Boolean;
  out Text: UTF8String): Boolean;
function ImGuiTextInputStatus(Context: TImGuiContext): Cardinal;
function ImGuiTextInputDisplay(Context: TImGuiContext; const Text: UTF8String): Boolean;
function ImGuiGpuIdentity(Context: TImGuiContext): string;
function ImGuiLastError(Context: TImGuiContext): Integer;

implementation

uses System.Classes, Cozy.Hashes.SHA512, Cozy.Overlay.State, Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver;

{ Register the native object before external declarations are checked.
  Do not move this link block into initialization or to the unit tail.
  Native static symbols are referenced by C++, not by Pascal source. }
{$HINTS OFF}
{ Build Cozy.Overlay.dproj: native preparation creates and audits this object.
  Prepare_ImGui.bat also publishes it in Cozy.BuildOutputs\Cozy.ImGui.
  The production $L path explicitly selects that one central object; it does not
  depend on IDE object-search options or source-adjacent copies. The unit and
  production project directories are both two levels below the native root.
  Run preparation successfully before a direct dcc64 build from the project directory.
  This is an ELF object produced by classic bcc64, never a deployed DLL. }
{$IFDEF GAME_IMGUI_FAULT_TESTS}
  {$L 'Cozy.game_imgui_fault_test.o'}
{$ELSE}
  {$L '..\..\Cozy.BuildOutputs\Cozy.ImGui\Cozy.game_imgui_bridge.o'}
{$ENDIF}
{$HINTS ON}

const
  ImGuiHostABIVersion = 3;
  ImGuiHostBytes = 32;
  ImGuiProcFirst = 1;
  ImGuiProcLast = 18;

type
  TImGuiGetProc = function(ID: Integer): Pointer; cdecl;
  TImGuiAlloc = function(Bytes: NativeUInt): Pointer; cdecl;
  TImGuiFree = procedure(Memory: Pointer); cdecl;
  TImGuiHost = record
    ABIVersion, StructSize: Cardinal;
    GetProc: TImGuiGetProc;
    Alloc: TImGuiAlloc;
    Free: TImGuiFree;
  end;
  PImGuiHost = ^TImGuiHost;

{ Only versioned C entry points are linked. No native C++ object or exception
  crosses the language boundary; every Boolean is an explicit 32-bit integer. }
function game_imgui_create(Window: Pointer; Host: PImGuiHost;
  out Context: TImGuiContext): Integer; cdecl; external name 'game_imgui_create';
function game_imgui_create_korean_v1(Window: Pointer; Host: PImGuiHost;
  FontData: Pointer; FontBytes: Cardinal; out Context: TImGuiContext): Integer;
  cdecl; external name 'game_imgui_create_korean_v1';
function game_imgui_create_license_korean_v1(Window: Pointer; Host: PImGuiHost;
  FontData: Pointer; FontBytes: Cardinal; out Context: TImGuiContext): Integer;
  cdecl; external name 'game_imgui_create_license_korean_v1';
function game_imgui_destroy(Context: TImGuiContext): Integer; cdecl;
  external name 'game_imgui_destroy';
function game_imgui_resize(Context: TImGuiContext; Width, Height: Integer): Integer;
  cdecl; external name 'game_imgui_resize';
function game_imgui_set_dpi(Context: TImGuiContext; Scale: Single): Integer;
  cdecl; external name 'game_imgui_set_dpi';
function game_imgui_new_frame(Context: TImGuiContext; Width, Height: Integer;
  DeltaSeconds: Single): Integer; cdecl; external name 'game_imgui_new_frame';
procedure game_imgui_mouse_pos(Context: TImGuiContext; X, Y: Single);
  cdecl; external name 'game_imgui_mouse_pos';
procedure game_imgui_mouse_button(Context: TImGuiContext; Button, Down: Integer);
  cdecl; external name 'game_imgui_mouse_button';
procedure game_imgui_mouse_wheel(Context: TImGuiContext; Horizontal, Vertical: Single);
  cdecl; external name 'game_imgui_mouse_wheel';
procedure game_imgui_key(Context: TImGuiContext; Key, Down: Integer);
  cdecl; external name 'game_imgui_key';
procedure game_imgui_focus(Context: TImGuiContext; Focused: Integer);
  cdecl; external name 'game_imgui_focus';
procedure game_imgui_clear_input(Context: TImGuiContext);
  cdecl; external name 'game_imgui_clear_input';
procedure game_imgui_begin_canvas(Context: TImGuiContext);
  cdecl; external name 'game_imgui_begin_canvas';
procedure game_imgui_set_cursor_pos(Context: TImGuiContext; X, Y: Single);
  cdecl; external name 'game_imgui_set_cursor_pos';
function game_imgui_button(Context: TImGuiContext; LabelText: PAnsiChar;
  Width, Height: Single; Enabled: Integer): Integer;
  cdecl; external name 'game_imgui_button';
procedure game_imgui_text(Context: TImGuiContext; Text: PAnsiChar);
  cdecl; external name 'game_imgui_text';
function game_imgui_scene_v2(Context: TImGuiContext; Phase, Selected: Integer;
  Flags: Cardinal; AnimationSeconds, CarouselPosition: Single): Integer;
  cdecl; external name 'game_imgui_scene_v2';
function game_imgui_scene_v3(Context: TImGuiContext; Phase, Selected: Integer;
  Flags: Cardinal; AnimationSeconds, CarouselPosition: Single;
  LicensedCard: Integer; RunProgress: Single): Integer;
  cdecl; external name 'game_imgui_scene_v3';
function game_imgui_license_scene_v1(Context: TImGuiContext; Phase, KeyCharacters: Integer;
  Progress: Single): Integer;
  cdecl; external name 'game_imgui_license_scene_v1';

procedure game_imgui_end_canvas(Context: TImGuiContext);
  cdecl; external name 'game_imgui_end_canvas';
function game_imgui_render_present(Context: TImGuiContext): Integer;
  cdecl; external name 'game_imgui_render_present';
function game_imgui_gpu_identity(Handle: TImGuiContext; Output: Pointer;
  Bytes: Cardinal): Integer; cdecl; external name 'game_imgui_gpu_identity';
function game_imgui_last_error(Context: TImGuiContext): Integer;
  cdecl; external name 'game_imgui_last_error';
function game_imgui_text_input_version: Cardinal;
  cdecl; external name 'game_imgui_text_input_version';
function game_imgui_text_input_enable_v1(Context: TImGuiContext;
  Enabled: Integer): Integer; cdecl; external name 'game_imgui_text_input_enable_v1';
function game_imgui_text_input_utf8_v1(Context: TImGuiContext; Text: PAnsiChar;
  Bytes: Cardinal; Action: Integer): Integer;
  cdecl; external name 'game_imgui_text_input_utf8_v1';
function game_imgui_text_input_utf16_v1(Context: TImGuiContext;
  CodeUnit: Cardinal): Integer; cdecl; external name 'game_imgui_text_input_utf16_v1';
function game_imgui_text_input_read_v1(Context: TImGuiContext; Output: Pointer;
  Bytes, Kind: Cardinal): Integer; cdecl; external name 'game_imgui_text_input_read_v1';
function game_imgui_text_input_status_v1(Context: TImGuiContext): Cardinal;
  cdecl; external name 'game_imgui_text_input_status_v1';
function game_imgui_text_input_display_v1(Context: TImGuiContext; Text: PAnsiChar;
  Bytes: Cardinal): Integer; cdecl; external name 'game_imgui_text_input_display_v1';
function game_imgui_abi_version: Cardinal;
  cdecl; external name 'game_imgui_abi_version';

var
  Slot_GetSystemDirectoryW: TEncodedApiPointer;
  { Stable, never copied: the pointer arena binds ownership to each slot. }
  ImGuiApiSlots: array[ImGuiProcFirst..ImGuiProcLast] of TEncodedApiPointer;

constructor EOverlayImGuiFailure.Create(FailureStage: TOverlayImGuiFailureStage;
  NativeStatus: Integer; const SafeMessage: string);
begin
  inherited Create(SafeMessage);
  FStage := FailureStage;
  FNativeCode := NativeStatus;
end;

function HostGetProc(ID: Integer): Pointer; cdecl;
begin
  Result := nil;
  try
    if (ID >= ImGuiProcFirst) and (ID <= ImGuiProcLast) then
      Result := DecodeApiPointer(ImGuiApiSlots[ID]);
  except
    { The native bridge treats a missing callback address as render failure.
      Never unwind a Delphi exception across a C++ frame. }
    Result := nil;
  end;
end;

function HostAlloc(Bytes: NativeUInt): Pointer; cdecl;
begin
  Result := nil;
  try
    if Bytes > NativeUInt(High(NativeInt)) then Exit;
    if Bytes = 0 then Bytes := 1;
    GetMem(Result, NativeInt(Bytes));
  except
    Result := nil;
  end;
end;

procedure HostFree(Memory: Pointer); cdecl;
begin
  try
    if Memory <> nil then FreeMem(Memory);
  except
    { A callback must never propagate a language-specific exception. }
  end;
end;

function ReadKoreanSystemFont: TBytes;
type TGetSystemDirectoryW = function(Buffer: PWideChar; Size: Cardinal): Cardinal; stdcall;
var Buffer: array[0..32767] of WideChar; Count: Cardinal;
  Directory: string; Stream: TFileStream; Target: TGetSystemDirectoryW;
begin
  Result := nil;
  try
    Target := TGetSystemDirectoryW(DecodeApiPointer(Slot_GetSystemDirectoryW));
    Count := Target(@Buffer[0], Length(Buffer));
    if (Count = 0) or (Count >= Cardinal(Length(Buffer))) then
      raise EOverlayImGuiFailure.Create(igfsFontRead, 0,
        CozyText_Overlay_ImGui_OVERLAY_KOREAN_FONT_UNAVAILABLE_5bdc5ed7);
    SetString(Directory, PWideChar(@Buffer[0]), Count);
    { Exact OS-owned path only. Never accept a font path from environment,
      current directory, server, registry override, download or command line. }
    Directory := IncludeTrailingPathDelimiter(ExtractFileDir(Directory)) + CozyText_Overlay_ImGui_Fonts_malgun_ttf_39f362de;
    Stream := TFileStream.Create(Directory, fmOpenRead or fmShareDenyWrite);
    try
      if (Stream.Size < 256) or (Stream.Size > 16 * 1024 * 1024) then
        raise EOverlayImGuiFailure.Create(igfsFontData, Integer($8007000D),
          CozyText_Overlay_ImGui_OVERLAY_KOREAN_FONT_INVALID_7e9430f5);
      SetLength(Result, NativeInt(Stream.Size));
      Stream.ReadBuffer(Result[0], Length(Result));
    finally Stream.Free; end;
  except
    on E: Exception do
    begin
      if Length(Result) <> 0 then FillChar(Result[0], Length(Result), 0);
      Result := nil;
      if E is EOverlayImGuiFailure then raise;
      { Internal paths and operating-system messages are never surfaced. }
      raise EOverlayImGuiFailure.Create(igfsFontRead, 0,
        CozyText_Overlay_ImGui_OVERLAY_KOREAN_FONT_UNAVAILABLE_5bdc5ed7);
    end;
  end;
end;

function ImGuiCreate(Window: NativeUInt; LicenseOnly: Boolean): TImGuiContext;
var Host: TImGuiHost; CreateResult: Integer; FontBytes: TBytes;
begin
  Result := nil;
  if (Window = 0) or (SizeOf(TImGuiHost) <> ImGuiHostBytes) or
    { Runtime Delphi layout evidence. @@ addresses procedural-variable storage,
      while @ would read the callback address stored in that field. }
    ((NativeUInt(@Host.ABIVersion) - NativeUInt(@Host)) <> 0) or
    ((NativeUInt(@Host.StructSize) - NativeUInt(@Host)) <> 4) or
    ((NativeUInt(@@Host.GetProc) - NativeUInt(@Host)) <> 8) or
    ((NativeUInt(@@Host.Alloc) - NativeUInt(@Host)) <> 16) or
    ((NativeUInt(@@Host.Free) - NativeUInt(@Host)) <> 24) or
    (game_imgui_abi_version <> ImGuiHostABIVersion) or
    (game_imgui_text_input_version <> 1) or
    not ApiPointerStorageIsSealed then
    raise EOverlayImGuiFailure.Create(igfsBinding, 0,
      CozyText_Overlay_ImGui_OVERLAY_IMGUI_BINDING_FAILED_b5e95cc9);
  FillChar(Host, SizeOf(Host), 0);
  Host.ABIVersion := ImGuiHostABIVersion;
  Host.StructSize := SizeOf(Host);
  Host.GetProc := HostGetProc;
  Host.Alloc := HostAlloc;
  Host.Free := HostFree;
  { The bridge copies this callback-only record; no stack pointer is retained. }
  FontBytes := ReadKoreanSystemFont;
  try
    if LicenseOnly then
      CreateResult := game_imgui_create_license_korean_v1(Pointer(Window), @Host,
        @FontBytes[0], Length(FontBytes), Result)
    else
      CreateResult := game_imgui_create_korean_v1(Pointer(Window), @Host,
        @FontBytes[0], Length(FontBytes), Result);
  finally
    if Length(FontBytes) <> 0 then FillChar(FontBytes[0], Length(FontBytes), 0);
    FontBytes := nil;
  end;
  if CreateResult <> 1 then
  begin
    if Result <> nil then game_imgui_destroy(Result);
    if Cardinal(CreateResult) = $8007000D then
      raise EOverlayImGuiFailure.Create(igfsFontData, CreateResult,
        CozyText_Overlay_ImGui_OVERLAY_KOREAN_FONT_INVALID_7e9430f5);
    raise EOverlayImGuiFailure.Create(igfsCreate, CreateResult,
      OverlayGraphicsFailure(CreateResult, CozyText_Overlay_ImGui_CREATE_76936d65));
  end;
  if Result = nil then raise EOverlayImGuiFailure.Create(igfsCreate, 0,
    CozyText_Overlay_ImGui_OVERLAY_RENDER_FAILED_692329f0);
end;

procedure ImGuiDestroy(var Context: TImGuiContext);
begin
  if Context = nil then Exit;
  { A wrong-thread or reentrant destroy must not discard the live owner handle. }
  if game_imgui_destroy(Context) <> 1 then
    raise EInvalidOpException.Create(CozyText_Overlay_ImGui_OVERLAY_IMGUI_OWNER_INVALID_12fc9529);
  Context := nil;
end;

function ImGuiResize(Context: TImGuiContext; Width, Height: Integer): Boolean;
begin
  Result := (Context <> nil) and
    (game_imgui_resize(Context, Width, Height) = 1);
end;

function ImGuiSetDpi(Context: TImGuiContext; Scale: Single): Boolean;
begin
  Result := (Context <> nil) and (game_imgui_set_dpi(Context, Scale) = 1);
end;

function ImGuiNewFrame(Context: TImGuiContext; Width, Height: Integer;
  DeltaSeconds: Single): Boolean;
begin
  Result := (Context <> nil) and
    (game_imgui_new_frame(Context, Width, Height, DeltaSeconds) = 1);
end;

procedure ImGuiBeginCanvas(Context: TImGuiContext);
begin
  if Context <> nil then game_imgui_begin_canvas(Context);
end;

procedure ImGuiSetCursorPos(Context: TImGuiContext; X, Y: Single);
begin
  if Context <> nil then game_imgui_set_cursor_pos(Context, X, Y);
end;

function ImGuiButton(Context: TImGuiContext; LabelText: PAnsiChar;
  Width, Height: Single; Enabled: Boolean): Boolean;
begin
  Result := (Context <> nil) and (LabelText <> nil) and
    (game_imgui_button(Context, LabelText, Width, Height, Ord(Enabled)) = 1);
end;

procedure ImGuiText(Context: TImGuiContext; Text: PAnsiChar);
begin
  if (Context <> nil) and (Text <> nil) then game_imgui_text(Context, Text);
end;

function ImGuiScene(Context: TImGuiContext; Phase, Selected: Integer;
  Flags: Cardinal; AnimationSeconds, CarouselPosition: Single): Integer;
begin
  if Context = nil then Exit(-1);
  Result := game_imgui_scene_v2(Context, Phase, Selected, Flags,
    AnimationSeconds, CarouselPosition);
end;

function ImGuiProductScene(Context: TImGuiContext; Phase, Selected: Integer;
  Flags: Cardinal; AnimationSeconds, CarouselPosition: Single;
  LicensedCard: Integer; RunProgress: Single): Integer;
begin
  if Context = nil then Exit(-1);
  Result := game_imgui_scene_v3(Context, Phase, Selected, Flags,
    AnimationSeconds, CarouselPosition, LicensedCard, RunProgress);
end;

function ImGuiLicenseScene(Context: TImGuiContext; Phase, KeyCharacters: Integer;
  Progress: Single): Integer;
begin
  if Context = nil then Exit(-1);
  Result := game_imgui_license_scene_v1(Context, Phase, KeyCharacters, Progress);
end;

procedure ImGuiEndCanvas(Context: TImGuiContext);
begin
  if Context <> nil then game_imgui_end_canvas(Context);
end;

function ImGuiPresent(Context: TImGuiContext): Integer;
begin
  if Context = nil then Exit(IMGUI_PRESENT_FAILED);
  Result := game_imgui_render_present(Context);
  if (Result < IMGUI_PRESENT_FAILED) or (Result > IMGUI_PRESENT_VISIBLE) then
    Result := IMGUI_PRESENT_FAILED;
end;

procedure ImGuiMousePos(Context: TImGuiContext; X, Y: Single);
begin
  if Context <> nil then game_imgui_mouse_pos(Context, X, Y);
end;

procedure ImGuiMouseButton(Context: TImGuiContext; Button: Integer; Down: Boolean);
begin
  if Context <> nil then game_imgui_mouse_button(Context, Button, Ord(Down));
end;

procedure ImGuiMouseWheel(Context: TImGuiContext; Horizontal, Vertical: Single);
begin
  if Context <> nil then game_imgui_mouse_wheel(Context, Horizontal, Vertical);
end;

procedure ImGuiKey(Context: TImGuiContext; Key: Integer; Down: Boolean);
begin
  if Context <> nil then game_imgui_key(Context, Key, Ord(Down));
end;

procedure ImGuiFocus(Context: TImGuiContext; Focused: Boolean);
begin
  if Context <> nil then game_imgui_focus(Context, Ord(Focused));
end;

procedure ImGuiClearInput(Context: TImGuiContext);
begin
  if Context <> nil then game_imgui_clear_input(Context);
end;

function ImGuiTextInputEnable(Context: TImGuiContext; Enabled: Boolean): Boolean;
begin
  Result := game_imgui_text_input_enable_v1(Context, Ord(Enabled)) = 1;
end;

function ImGuiTextInputEvent(Context: TImGuiContext; Action: TImGuiTextInputAction;
  const Text: UTF8String): Boolean;
begin
  Result := False;
  if Length(Text) > 512 then Exit;
  Result := game_imgui_text_input_utf8_v1(Context, PAnsiChar(Text),
    Cardinal(Length(Text)), Ord(Action)) = 1;
end;

function ImGuiTextInputUtf16(Context: TImGuiContext; CodeUnit: Cardinal): Boolean;
begin
  Result := game_imgui_text_input_utf16_v1(Context, CodeUnit) = 1;
end;

function ImGuiTextInputRead(Context: TImGuiContext; Preedit: Boolean;
  out Text: UTF8String): Boolean;
var Bytes: array[0..512] of AnsiChar; Count: Integer;
begin
  Text := ''; Result := False;
  FillChar(Bytes, SizeOf(Bytes), 0);
  try
    Count := game_imgui_text_input_read_v1(Context, @Bytes[0], SizeOf(Bytes),
      Ord(Preedit));
    if (Count < 0) or (Count > 512) then Exit;
    SetString(Text, PAnsiChar(@Bytes[0]), Count);
    Result := True;
  finally
    FillChar(Bytes, SizeOf(Bytes), 0);
  end;
end;

function ImGuiTextInputStatus(Context: TImGuiContext): Cardinal;
begin
  { Bits: 1 enabled; 2 focused; 4 composing; 8 pending UTF-16 high surrogate. }
  Result := game_imgui_text_input_status_v1(Context);
end;

function ImGuiTextInputDisplay(Context: TImGuiContext; const Text: UTF8String): Boolean;
begin
  Result := False;
  if Length(Text) > 512 then Exit;
  Result := game_imgui_text_input_display_v1(Context, PAnsiChar(Text),
    Cardinal(Length(Text))) = 1;
end;

function ImGuiGpuIdentity(Context: TImGuiContext): string;
type TGPUIdentity = packed record
  Version, Bytes, VendorID, DeviceID, SubSysID, Revision: Cardinal;
  DriverVersion: UInt64;
end;
const Domain: AnsiString = CozyText_Overlay_ImGui_GAME_GPU_IDENTITY_V1_939c70ca;
var Identity: TGPUIdentity; Hash: TSHA512Hasher;
begin
  Result := '';
  FillChar(Identity,SizeOf(Identity),0);
  if (SizeOf(Identity) <> 32) or (Context = nil) or
    (game_imgui_gpu_identity(Context,@Identity,SizeOf(Identity)) <> 1) then Exit;
  if (Identity.Version <> 1) or (Identity.Bytes <> SizeOf(Identity)) or
    (Identity.DriverVersion = 0) then Exit;
  { Stable PCI + UMD package identity from the actual rendering device.
    No adapter LUID, ordinal, HWND or process-specific value enters the hash. }
  Hash := TSHA512Hasher.Create;
  try
    Hash.Update(Domain[1],Length(Domain)); Hash.Update(Identity,SizeOf(Identity));
    Result := Hash.FinishHex;
  finally Hash.Free; FillChar(Identity,SizeOf(Identity),0); end;
end;

function ImGuiLastError(Context: TImGuiContext): Integer;
begin
  Result := game_imgui_last_error(Context);
end;

initialization
  { IDs and hashes mirror Cozy.imgui/Cozy.bridge/Cozy.game_imgui_bridge.h. Only system DLLs
    are resolved, held by the existing resolver until process exit. Every
    native call obtains a freshly decoded pointer through HostGetProc. }
  BindApiPointer(Slot_GetSystemDirectoryW, RequireProcAddressHash64(CozyText_Overlay_ImGui_kernel32_dll_531eb720, HASH_GetSystemDirectoryW));
  BindApiPointer(ImGuiApiSlots[1], RequireProcAddressHash64(CozyText_Overlay_ImGui_d3d11_dll_9c95a0c7, HASH_D3D11CreateDevice));
  BindApiPointer(ImGuiApiSlots[2], RequireProcAddressHash64(CozyText_Overlay_ImGui_d3dcompiler_47_dll_6af98d48, HASH_D3DCompile));
  BindApiPointer(ImGuiApiSlots[3], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH___stdio_common_vsprintf));
  BindApiPointer(ImGuiApiSlots[4], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH___stdio_common_vsscanf));
  BindApiPointer(ImGuiApiSlots[5], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_strtod));
  BindApiPointer(ImGuiApiSlots[6], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_acos));
  BindApiPointer(ImGuiApiSlots[7], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_atan2));
  BindApiPointer(ImGuiApiSlots[8], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_ceil));
  BindApiPointer(ImGuiApiSlots[9], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_cos));
  BindApiPointer(ImGuiApiSlots[10], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_fabs));
  BindApiPointer(ImGuiApiSlots[11], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_floor));
  BindApiPointer(ImGuiApiSlots[12], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_fmod));
  BindApiPointer(ImGuiApiSlots[13], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_log));
  BindApiPointer(ImGuiApiSlots[14], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_pow));
  BindApiPointer(ImGuiApiSlots[15], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_sin));
  BindApiPointer(ImGuiApiSlots[16], RequireProcAddressHash64(CozyText_Overlay_ImGui_ucrtbase_dll_87ed8511, HASH_sqrt));
  BindApiPointer(ImGuiApiSlots[18], RequireProcAddressHash64(CozyText_Overlay_ImGui_dcomp_dll_773afbf2, HASH_DCompositionCreateDevice));
  BindApiPointer(ImGuiApiSlots[17], RequireProcAddressHash64(CozyText_Overlay_ImGui_kernel32_dll_531eb720, HASH_GetCurrentThreadId));

{ Keep hints off through unit end for deferred native-symbol diagnostics.
  This also covers other unused implementation symbols diagnosed at unit end.
  Object linking must stay above external declarations, outside initialization.
  Other units retain their hint mode. }
{$HINTS OFF}
end.
