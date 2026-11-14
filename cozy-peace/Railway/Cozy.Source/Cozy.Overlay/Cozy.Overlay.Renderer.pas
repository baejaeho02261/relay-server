unit Cozy.Overlay.Renderer;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Overlay,
 System.SysUtils, System.Types;

type
  TOverlayTextInputEvent = (otieCommitted, otieCompositionBegin,
    otieCompositionEnd, otieCompositionCancelled, otieFocusLost,
    otieBackspace, otieSubmit);
  TOverlayTextInputCallback = reference to procedure(Event: TOverlayTextInputEvent;
    const Text: UTF8String);

{ Text input is opt-in only when BOTH callbacks are assigned and TextInputActive
  returns True for a visible application editor. No global input is read. The
  default IME window owns preedit/candidate UI; WM_CHAR alone commits text,
  avoiding a second commit from WM_IME_CHAR/GCS_RESULTSTR. Callbacks run on the
  UI thread, must be bounded and must not perform I/O or keep sensitive text.
  The normal display-only product passes neither callback. }
{ Authenticated top-level window only, with genuine Dear ImGui + Direct3D 11.
  Pascal owns the window, input, presentation state and authority checks.
  The bounded native scene builds the matching Dear ImGui visuals.
  No VCL/FMX, OS child controls, hooks or process injection.
  Tick is called only after a visible successful swap-chain Present.
  Tick/ShouldClose run on the UI thread and must not perform network I/O.
  AuthorizeBeforeShow is a one-time hidden-device startup phase; it must finish
  initial server authorization before any visible window, Present or READY. }
function RunOverlayUI(const Tick: TProc;
  const ShouldClose: TFunc<Boolean>; const OnClosing: TProc = nil; const AuthorizeBeforeShow: TProc = nil;
  const CapturePrivacy: TFunc<Boolean> = nil; const OnHidden: TProc = nil;
  const StartupPhase: TProc<string> = nil;
  const TextInputActive: TFunc<Boolean> = nil;
  const OnTextInput: TOverlayTextInputCallback = nil;
  const RequestRun: TProc = nil; const RunState: TFunc<Integer> = nil;
  const StartupFailure: TProc<string,Integer> = nil;
  const RuntimeFailure: TProc<Integer> = nil;
  const LicensedCard: TFunc<Integer> = nil;
  const RequestProductRun: TFunc<Integer,Boolean> = nil;
  const ProductRunState: TFunc<Integer> = nil): Integer;

{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
type
  TOverlayEnvironmentSnapshot = record
    Window: NativeUInt;
    Dpi, InputClearCount, DpiChanges, FocusLosses, SessionConnects,
      SessionDisconnects: Cardinal;
    Dragging, ButtonTracking, CaptureOwned, SessionPaused,
      SessionNotificationsRegistered, DpiSuggestedMatches: Boolean;
    WindowRect: TRect;
    ScenePhase, SceneSelected, SceneCategory, LicensedCard: Integer;
    ReceiptOnly, RevealComplete: Boolean;
  end;
  TOverlayEnvironmentObserver = reference to procedure(Msg: Cardinal;
    WParam: NativeUInt; LParam: NativeInt; InputClearsBefore: Cardinal);
procedure SetOverlayEnvironmentObserver(const Observer: TOverlayEnvironmentObserver);
function OverlayTestEnvironment: TOverlayEnvironmentSnapshot;
function OverlayTestButtonHit(X, Y: Integer): Boolean;
procedure SetOverlayTestHooks(const BeforePresent, BeforeReady: TProc);
function OverlayTestWindow: NativeUInt;
function OverlayTestCapturePrivacyStatus: string;
{$ENDIF}

implementation

uses Cozy.Clock, Winapi.Windows, Winapi.Messages, System.SyncObjs, Cozy.Api.Pointer, Cozy.Platform.ExportResolver,
  Cozy.Api.ROR13, Cozy.Overlay.State, Cozy.Overlay.ImGui, Cozy.ProcessMitigations
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  , Cozy.ProductFaults
{$ENDIF}
  ;

{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  {$IFNDEF GAME_IMGUI_FAULT_TESTS}
    {$MESSAGE FATAL 'Product GPU fixtures require the isolated ImGui fault object.'}
  {$ENDIF}
procedure game_imgui_test_fault(Stage, Error: Integer); cdecl;
  external name 'game_imgui_test_fault';
const
  ProductGpuOutOfMemory = -2147024882; { E_OUTOFMEMORY }
  ProductGpuDeviceRemoved = -2005270523; { DXGI_ERROR_DEVICE_REMOVED }
  ProductGpuDeviceReset = -2005270521; { DXGI_ERROR_DEVICE_RESET }
{$ENDIF}

const
  DpiChangedMessage = $02E0; { WM_DPICHANGED }
  SessionChangedMessage = $02B1; { WM_WTSSESSION_CHANGE }
  SessionConsoleConnect = 1;
  SessionConsoleDisconnect = 2;
  SessionRemoteConnect = 3;
  SessionRemoteDisconnect = 4;
  SessionLogoff = 6;
  SessionLock = 7;
  SessionUnlock = 8;
  OverlayClass: PWideChar = CozyText_Overlay_Renderer_GameOverlayImGuiV1_f79be695;
  SceneWidth = 680;
  SceneHeight = 440;
  InitialWidth = 680;
  InitialHeight = 440;
  SceneHeaderHeight = 64;
  SceneRevealSeconds = 0.45;
  OverlayNoRedirectionBitmap = $00200000;
  OverlayWaitInputAvailable = $0004;
  SessionRegistrationLimit = 30;
  SessionRegistrationIntervalMS = 1000;

type
  TCall_RegisterClassExW = function(const WndClass: TWndClassExW): ATOM; stdcall;
  TCall_UnregisterClassW = function(ClassName: PWideChar; Instance: HINST): BOOL; stdcall;
  TCall_CreateWindowExW = function(ExStyle: DWORD; ClassName, WindowName: PWideChar; Style: DWORD; X, Y, Width, Height: Integer; Parent: HWND; Menu: HMENU; Instance: HINST; Param: Pointer): HWND; stdcall;
  TCall_DefWindowProcW = function(Wnd: HWND; Msg: UINT; WParam: WPARAM; LParam: LPARAM): LRESULT; stdcall;
  TCall_DestroyWindow = function(Wnd: HWND): BOOL; stdcall;
  TCall_ShowWindow = function(Wnd: HWND; Show: Integer): BOOL; stdcall;
  TCall_PeekMessageW = function(var Msg: TMsg; Wnd: HWND; Min, Max, Remove: UINT): BOOL; stdcall;
  TCall_MsgWaitForMultipleObjectsEx = function(Count: DWORD; Handles: Pointer; Milliseconds, WakeMask, Flags: DWORD): DWORD; stdcall;
  TCall_SetCursor = function(Cursor: HCURSOR): HCURSOR; stdcall;
  TCall_TranslateMessage = function(const Msg: TMsg): BOOL; stdcall;
  TCall_DispatchMessageW = function(const Msg: TMsg): LRESULT; stdcall;
  TCall_PostQuitMessage = procedure(Code: Integer); stdcall;
  TCall_BeginPaint = function(Wnd: HWND; var Paint: TPaintStruct): HDC; stdcall;
  TCall_EndPaint = function(Wnd: HWND; const Paint: TPaintStruct): BOOL; stdcall;
  TCall_GetClientRect = function(Wnd: HWND; var Rect: TRect): BOOL; stdcall;
  TCall_InvalidateRect = function(Wnd: HWND; Rect: PRect; Erase: BOOL): BOOL; stdcall;
  TCall_LoadCursorW = function(Instance: HINST; Name: PWideChar): HCURSOR; stdcall;
  TCall_SetCapture = function(Wnd: HWND): HWND; stdcall;
  TCall_GetCapture = function: HWND; stdcall;
  TCall_ReleaseCapture = function: BOOL; stdcall;
  TCall_GetCursorPos = function(var Point: TPoint): BOOL; stdcall;
  TCall_IsWindowVisible = function(Wnd: HWND): BOOL; stdcall;
  TCall_GetWindowRect = function(Wnd: HWND; var Rect: TRect): BOOL; stdcall;
  TCall_SetWindowPos = function(Wnd, InsertAfter: HWND; X, Y, Width, Height: Integer; Flags: UINT): BOOL; stdcall;
  TCall_SetWindowDisplayAffinity = function(Wnd: HWND; Affinity: DWORD): BOOL; stdcall;
  TCall_GetWindowDisplayAffinity = function(Wnd: HWND; out Affinity: DWORD): BOOL; stdcall;
  TCall_GetDpiForWindow = function(Wnd: HWND): UINT; stdcall;
  TCall_WTSRegisterSessionNotification = function(Wnd: HWND; Flags: DWORD): BOOL; stdcall;
  TCall_WTSUnRegisterSessionNotification = function(Wnd: HWND): BOOL; stdcall;
  TCall_MonitorFromWindow = function(Wnd: HWND; Flags: DWORD): THandle; stdcall;
  TCall_GetMonitorInfoW = function(Monitor: THandle; Info: Pointer): BOOL; stdcall;
  TOverlayMonitorInfo = record
    Size: DWORD;
    Monitor, Work: TRect;
    Flags: DWORD;
  end;
  TCall_GetCurrentThreadId = function: DWORD; stdcall;
  TMouseTracking = record
    cbSize, Flags: DWORD;
    Window: HWND;
    HoverTime: DWORD;
  end;
  TCall_TrackMouseEvent = function(var Tracking: TMouseTracking): BOOL; stdcall;

  TOverlayWindow = class
  private
    FWindow: HWND;
    FOwnerThread: DWORD;
    FScale: Single;
    FSessionRegistered, FSessionPaused: Boolean;
    FSessionRegistrationAttempts: Cardinal;
    FSessionRegistrationTick: UInt64;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
    FInputClearCount, FDpiChanges, FFocusLosses, FSessionConnects,
      FSessionDisconnects: Cardinal;
    FDpiSuggestedMatches: Boolean;
{$ENDIF}
    FClosing, FPainting, FResizePending, FAuthorizing: Boolean;
    FContext: TImGuiContext;
    FFocused: Boolean;
    FTextInputActive: TFunc<Boolean>;
    FOnTextInput: TOverlayTextInputCallback;
    FDragging, FButtonTracking, FReleasingCapture, FTrackingMouse: Boolean;
    FDragAnchor, FDragOrigin: TPoint;
    FFailed, FRendered: Boolean;
    FScenePhase, FSceneSelected, FSceneCategory, FLicensedCard: Integer;
    FMinimized, FWindowShown, FRuntimeFailureSent: Boolean;
    FRunStarted, FRunDeadline: UInt64;
    FRunDuration: Cardinal;
    FGetLicensedCard, FProductRunState: TFunc<Integer>;
    FRequestProductRun: TFunc<Integer,Boolean>;
    FNormalCursor, FBusyCursor: HCURSOR;
    FRuntimeFailure: TProc<Integer>;
    FSceneSeconds, FCarouselPosition: Single;
    FSceneRevealComplete: Boolean;
    FSceneKeyActions: Cardinal;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
    FProductFaultReady: Boolean;
{$ENDIF}
    FCapturePrivacy: TFunc<Boolean>;
    FPrivacyRequested, FPrivacyInitialized: Boolean;
    FPrivacyCheckTick: UInt64;
    FPrivacyStatus: string;
    FLastFrameSeconds: Double;
    FShouldClose: TFunc<Boolean>;
    FOnClosing, FOnHidden: TProc;
    FClosingNotified, FHiddenNotified: Boolean;
    function SyncTextInput: Boolean;
    procedure NotifyTextInput(Event: TOverlayTextInputEvent);
    procedure ApplyCapturePrivacy;
    procedure TryRegisterSession;
    procedure UnregisterSession;
    procedure SessionChanged(Reason: NativeUInt);
    procedure FitToWorkArea;
    procedure ReconcileDisplay;
    procedure BeginClosing;
    procedure ObserveHidden;
    procedure SetDpi(Dpi: Cardinal; Suggested: PRect);
    procedure RequireOwner;
    function AuthorityValid: Boolean;
    procedure Paint;
    procedure UpdateCursor;
    procedure RecordRuntimeFailure;
    function ReadRunState: Integer;
    procedure Resize;
    function ButtonHit(X, Y: Integer): Boolean;
    procedure ApplySceneActions(Actions: Cardinal);
    function SceneKey(Key: NativeUInt; Repeated: Boolean): Boolean;
    procedure ReleaseOwnCapture;
    procedure CancelInteraction;
    procedure PointerDown(X, Y: Integer);
    procedure PointerMove(X, Y: Integer);
    procedure PointerUp(X, Y: Integer);
    function Handle(Wnd: HWND; Msg: UINT; WParam: WPARAM;
      LParam: LPARAM): LRESULT;
  public
    constructor Create;
    destructor Destroy; override;
    function Run(const Tick: TProc; const ShouldClose: TFunc<Boolean>; const OnClosing: TProc; const AuthorizeBeforeShow: TProc; const CapturePrivacy: TFunc<Boolean>; const OnHidden: TProc; const StartupPhase: TProc<string>; const TextInputActive: TFunc<Boolean>; const OnTextInput: TOverlayTextInputCallback; const RequestRun: TProc; const RunState: TFunc<Integer>; const StartupFailure: TProc<string,Integer>; const RuntimeFailure: TProc<Integer>; const LicensedCard: TFunc<Integer>; const RequestProductRun: TFunc<Integer,Boolean>; const ProductRunState: TFunc<Integer>): Integer;
  end;

var
  ActiveWindow: TOverlayWindow;
  RendererRunning: Integer;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
  TestBeforePresent, TestBeforeReady: TProc;
  TestEnvironmentObserver: TOverlayEnvironmentObserver;
{$ENDIF}
  Slot_SetWindowDisplayAffinity, Slot_GetWindowDisplayAffinity: TEncodedApiPointer;
  Slot_GetDpiForWindow: TEncodedApiPointer;
  Slot_WTSRegisterSessionNotification, Slot_WTSUnRegisterSessionNotification,
    Slot_MonitorFromWindow, Slot_GetMonitorInfoW: TEncodedApiPointer;
  Slot_GetCurrentThreadId: TEncodedApiPointer;
  Slot_RegisterClassExW: TEncodedApiPointer;
  Slot_UnregisterClassW: TEncodedApiPointer;
  Slot_CreateWindowExW: TEncodedApiPointer;
  Slot_DefWindowProcW: TEncodedApiPointer;
  Slot_DestroyWindow: TEncodedApiPointer;
  Slot_ShowWindow: TEncodedApiPointer;
  Slot_PeekMessageW, Slot_MsgWaitForMultipleObjectsEx, Slot_SetCursor: TEncodedApiPointer;
  Slot_TranslateMessage: TEncodedApiPointer;
  Slot_DispatchMessageW: TEncodedApiPointer;
  Slot_PostQuitMessage: TEncodedApiPointer;
  Slot_BeginPaint: TEncodedApiPointer;
  Slot_EndPaint: TEncodedApiPointer;
  Slot_GetClientRect: TEncodedApiPointer;
  Slot_InvalidateRect: TEncodedApiPointer;
  Slot_LoadCursorW: TEncodedApiPointer;
  Slot_SetCapture: TEncodedApiPointer;
  Slot_GetCapture: TEncodedApiPointer;
  Slot_ReleaseCapture: TEncodedApiPointer;
  Slot_GetCursorPos: TEncodedApiPointer;
  Slot_GetWindowRect, Slot_IsWindowVisible: TEncodedApiPointer;
  Slot_SetWindowPos: TEncodedApiPointer;

  Slot_TrackMouseEvent: TEncodedApiPointer;

function ApiSetWindowDisplayAffinity(Wnd: HWND; Affinity: DWORD): BOOL;
var Target: TCall_SetWindowDisplayAffinity;
begin
  Target := TCall_SetWindowDisplayAffinity(DecodeApiPointer(Slot_SetWindowDisplayAffinity));
  Result := Target(Wnd, Affinity);
end;
function ApiGetWindowDisplayAffinity(Wnd: HWND; out Affinity: DWORD): BOOL;
var Target: TCall_GetWindowDisplayAffinity;
begin
  Affinity := 0;
  Target := TCall_GetWindowDisplayAffinity(DecodeApiPointer(Slot_GetWindowDisplayAffinity));
  Result := Target(Wnd, Affinity);
end;

function ApiCurrentThreadID: DWORD;
var Target: TCall_GetCurrentThreadId;
begin
  Target := TCall_GetCurrentThreadId(DecodeApiPointer(Slot_GetCurrentThreadId));
  Result := Target();
end;

function ApiRegisterClassExW(const WndClass: TWndClassExW): ATOM;
var Target: TCall_RegisterClassExW;
begin
  Target := TCall_RegisterClassExW(DecodeApiPointer(Slot_RegisterClassExW));
  Result := Target(WndClass);
end;

function ApiUnregisterClassW(ClassName: PWideChar; Instance: HINST): BOOL;
var Target: TCall_UnregisterClassW;
begin
  Target := TCall_UnregisterClassW(DecodeApiPointer(Slot_UnregisterClassW));
  Result := Target(ClassName, Instance);
end;

function ApiCreateWindowExW(ExStyle: DWORD; ClassName, WindowName: PWideChar; Style: DWORD; X, Y, Width, Height: Integer; Parent: HWND; Menu: HMENU; Instance: HINST; Param: Pointer): HWND;
var Target: TCall_CreateWindowExW;
begin
  Target := TCall_CreateWindowExW(DecodeApiPointer(Slot_CreateWindowExW));
  Result := Target(ExStyle, ClassName, WindowName, Style, X, Y, Width, Height, Parent, Menu, Instance, Param);
end;

function ApiDefWindowProcW(Wnd: HWND; Msg: UINT; WParam: WPARAM; LParam: LPARAM): LRESULT;
var Target: TCall_DefWindowProcW;
begin
  Target := TCall_DefWindowProcW(DecodeApiPointer(Slot_DefWindowProcW));
  Result := Target(Wnd, Msg, WParam, LParam);
end;

function ApiDestroyWindow(Wnd: HWND): BOOL;
var Target: TCall_DestroyWindow;
begin
  Target := TCall_DestroyWindow(DecodeApiPointer(Slot_DestroyWindow));
  Result := Target(Wnd);
end;

function ApiShowWindow(Wnd: HWND; Show: Integer): BOOL;
var Target: TCall_ShowWindow;
begin
  Target := TCall_ShowWindow(DecodeApiPointer(Slot_ShowWindow));
  Result := Target(Wnd, Show);
end;

function ApiPeekMessageW(var Msg: TMsg; Wnd: HWND; Min, Max, Remove: UINT): BOOL;
var Target: TCall_PeekMessageW;
begin
  Target := TCall_PeekMessageW(DecodeApiPointer(Slot_PeekMessageW));
  Result := Target(Msg, Wnd, Min, Max, Remove);
end;
function ApiWaitForInput: DWORD;
var Target: TCall_MsgWaitForMultipleObjectsEx;
begin
  Target := TCall_MsgWaitForMultipleObjectsEx(DecodeApiPointer(Slot_MsgWaitForMultipleObjectsEx));
  Result := Target(0,nil,50,QS_ALLINPUT,OverlayWaitInputAvailable);
end;
function ApiSetCursor(Cursor: HCURSOR): HCURSOR;
var Target: TCall_SetCursor;
begin
  Target := TCall_SetCursor(DecodeApiPointer(Slot_SetCursor));
  Result := Target(Cursor);
end;

function ApiTranslateMessage(const Msg: TMsg): BOOL;
var Target: TCall_TranslateMessage;
begin
  Target := TCall_TranslateMessage(DecodeApiPointer(Slot_TranslateMessage));
  Result := Target(Msg);
end;

function ApiDispatchMessageW(const Msg: TMsg): LRESULT;
var Target: TCall_DispatchMessageW;
begin
  Target := TCall_DispatchMessageW(DecodeApiPointer(Slot_DispatchMessageW));
  Result := Target(Msg);
end;

procedure ApiPostQuitMessage(Code: Integer);
var Target: TCall_PostQuitMessage;
begin
  Target := TCall_PostQuitMessage(DecodeApiPointer(Slot_PostQuitMessage));
  Target(Code);
end;

function ApiBeginPaint(Wnd: HWND; var Paint: TPaintStruct): HDC;
var Target: TCall_BeginPaint;
begin
  Target := TCall_BeginPaint(DecodeApiPointer(Slot_BeginPaint));
  Result := Target(Wnd, Paint);
end;

function ApiEndPaint(Wnd: HWND; const Paint: TPaintStruct): BOOL;
var Target: TCall_EndPaint;
begin
  Target := TCall_EndPaint(DecodeApiPointer(Slot_EndPaint));
  Result := Target(Wnd, Paint);
end;

function ApiGetClientRect(Wnd: HWND; var Rect: TRect): BOOL;
var Target: TCall_GetClientRect;
begin
  Target := TCall_GetClientRect(DecodeApiPointer(Slot_GetClientRect));
  Result := Target(Wnd, Rect);
end;

function ApiInvalidateRect(Wnd: HWND; Rect: PRect; Erase: BOOL): BOOL;
var Target: TCall_InvalidateRect;
begin
  Target := TCall_InvalidateRect(DecodeApiPointer(Slot_InvalidateRect));
  Result := Target(Wnd, Rect, Erase);
end;

function ApiLoadCursorW(Instance: HINST; Name: PWideChar): HCURSOR;
var Target: TCall_LoadCursorW;
begin
  Target := TCall_LoadCursorW(DecodeApiPointer(Slot_LoadCursorW));
  Result := Target(Instance, Name);
end;

function ApiSetCapture(Wnd: HWND): HWND;
var Target: TCall_SetCapture;
begin
  Target := TCall_SetCapture(DecodeApiPointer(Slot_SetCapture));
  Result := Target(Wnd);
end;

function ApiGetCapture: HWND;
var Target: TCall_GetCapture;
begin
  Target := TCall_GetCapture(DecodeApiPointer(Slot_GetCapture));
  Result := Target();
end;

function ApiReleaseCapture: BOOL;
var Target: TCall_ReleaseCapture;
begin
  Target := TCall_ReleaseCapture(DecodeApiPointer(Slot_ReleaseCapture));
  Result := Target();
end;

function ApiGetCursorPos(var Point: TPoint): BOOL;
var Target: TCall_GetCursorPos;
begin
  Target := TCall_GetCursorPos(DecodeApiPointer(Slot_GetCursorPos));
  Result := Target(Point);
end;

function ApiIsWindowVisible(Wnd: HWND): BOOL;
var Target: TCall_IsWindowVisible;
begin
  Target := TCall_IsWindowVisible(DecodeApiPointer(Slot_IsWindowVisible));
  Result := Target(Wnd);
end;

function ApiGetWindowRect(Wnd: HWND; var Rect: TRect): BOOL;
var Target: TCall_GetWindowRect;
begin
  Target := TCall_GetWindowRect(DecodeApiPointer(Slot_GetWindowRect));
  Result := Target(Wnd, Rect);
end;

function ApiSetWindowPos(Wnd, InsertAfter: HWND; X, Y, Width, Height: Integer; Flags: UINT): BOOL;
var Target: TCall_SetWindowPos;
begin
  Target := TCall_SetWindowPos(DecodeApiPointer(Slot_SetWindowPos));
  Result := Target(Wnd, InsertAfter, X, Y, Width, Height, Flags);
end;


function ApiTrackMouseEvent(var Tracking: TMouseTracking): BOOL;
var Target: TCall_TrackMouseEvent;
begin
  Target := TCall_TrackMouseEvent(DecodeApiPointer(Slot_TrackMouseEvent));
  Result := Target(Tracking);
end;

function WindowProc(Wnd: HWND; Msg: UINT; WParam: WPARAM;
  LParam: LPARAM): LRESULT; stdcall;
begin
  { Never allow Delphi exceptions to escape a native window callback. }
  try
    if ActiveWindow <> nil then
      Exit(ActiveWindow.Handle(Wnd, Msg, WParam, LParam));
    Result := ApiDefWindowProcW(Wnd, Msg, WParam, LParam);
  except
    if ActiveWindow <> nil then
    begin
      ActiveWindow.RecordRuntimeFailure;
      ActiveWindow.FFailed := True;
      try ActiveWindow.BeginClosing; except end;
      try
        if ActiveWindow.FWindow <> 0 then
          ApiShowWindow(ActiveWindow.FWindow, SW_HIDE);
      except end;
    end;
    try ApiPostQuitMessage(1); except end;
    Result := 0;
  end;
end;

constructor TOverlayWindow.Create;
begin
  inherited Create;
  FOwnerThread := ApiCurrentThreadID; FScale := 1;
  FSceneSelected := 1; FCarouselPosition := 1; FLicensedCard := -1;
  if FOwnerThread = 0 then raise EInvalidOpException.Create(CozyText_Overlay_Renderer_OVERLAY_IMGUI_OWNER_INVALID_e5fe9b66);
end;

procedure TOverlayWindow.RequireOwner;
begin
  if (FOwnerThread = 0) or (ApiCurrentThreadID <> FOwnerThread) then
    raise EInvalidOpException.Create(CozyText_Overlay_Renderer_OVERLAY_IMGUI_OWNER_INVALID_e5fe9b66);
end;

procedure TOverlayWindow.BeginClosing;
begin
  if FOwnerThread <> 0 then RequireOwner;
  if FClosingNotified then Exit;
  FClosingNotified := True;
  FClosing := True;
  if Assigned(FOnClosing) then
  try FOnClosing();
  except FFailed := True; end;
  FOnClosing := nil;
  if FWindow <> 0 then
  begin
    ApiShowWindow(FWindow, SW_HIDE);
    ObserveHidden;
  end;
end;

procedure TOverlayWindow.ObserveHidden;
begin
  if FHiddenNotified or (FWindow = 0) or ApiIsWindowVisible(FWindow) then Exit;
  FHiddenNotified := True;
  if Assigned(FOnHidden) then
    try FOnHidden(); except FFailed := True; end;
  FOnHidden := nil;
end;

destructor TOverlayWindow.Destroy;
begin
  { Only the UI owner can release HWND, D3D context and callbacks. Run has
    already stopped message dispatch; the outer owner joins its worker. }
  if FOwnerThread <> 0 then RequireOwner;
  BeginClosing;
  try
    CancelInteraction;
    if FWindow <> 0 then
    begin

      ApiDestroyWindow(FWindow);
      FWindow := 0;
    end;
  finally
    try ImGuiDestroy(FContext);
    finally
      FCapturePrivacy := nil;
      FShouldClose := nil;
      FRuntimeFailure := nil;
      FGetLicensedCard := nil; FRequestProductRun := nil; FProductRunState := nil;
      FTextInputActive := nil;
      FOnTextInput := nil;
      inherited;
    end;
  end;
end;

procedure TOverlayWindow.TryRegisterSession;
var Target: TCall_WTSRegisterSessionNotification; At: UInt64;
begin
  RequireOwner;
  { WTS can return RPC_S_INVALID_BINDING before TermSrv is ready. Notifications
    are optional compatibility telemetry, never a server authority decision.
    Keep normal focus cancellation and visible operation, and retry only on
    later UI dispatch; no sleep, waiting, timer thread or message-loop block. }
  if FClosing or (FWindow = 0) or FSessionRegistered or
    (FSessionRegistrationAttempts >= SessionRegistrationLimit) or
    not Slot_WTSRegisterSessionNotification.IsBound or
    not Slot_WTSUnRegisterSessionNotification.IsBound then Exit;
  At := CozyTick;
  if (FSessionRegistrationAttempts <> 0) and
    ((At < FSessionRegistrationTick) or
      (At - FSessionRegistrationTick < SessionRegistrationIntervalMS)) then Exit;
  FSessionRegistrationTick := At;
  Inc(FSessionRegistrationAttempts);
  Target := TCall_WTSRegisterSessionNotification(DecodeApiPointer(Slot_WTSRegisterSessionNotification));
  FSessionRegistered := Target(FWindow, 0); { NOTIFY_FOR_THIS_SESSION }
end;

procedure TOverlayWindow.UnregisterSession;
var Target: TCall_WTSUnRegisterSessionNotification;
begin
  if not FSessionRegistered then Exit;
  FSessionRegistered := False;
  Target := TCall_WTSUnRegisterSessionNotification(DecodeApiPointer(Slot_WTSUnRegisterSessionNotification));
  if (FWindow <> 0) and not Target(FWindow) then FFailed := True;
end;

procedure TOverlayWindow.FitToWorkArea;
var Target: TCall_MonitorFromWindow; ReadInfo: TCall_GetMonitorInfoW;
  Monitor: THandle; Info: TOverlayMonitorInfo;
  Area: TRect; X, Y, Width, Height: Integer;
begin
  RequireOwner;
  if FWindow = 0 then Exit;
  { Fit the current physical rectangle without changing DPI or asking Windows
    for another suggested rectangle. This also serves WM_DPICHANGED directly. }
  Target := TCall_MonitorFromWindow(DecodeApiPointer(Slot_MonitorFromWindow));
  ReadInfo := TCall_GetMonitorInfoW(DecodeApiPointer(Slot_GetMonitorInfoW));
  Monitor := Target(FWindow, 2); { MONITOR_DEFAULTTONEAREST }
  FillChar(Info, SizeOf(Info), 0); Info.Size := SizeOf(Info);
  if (Monitor = 0) or not ReadInfo(Monitor, @Info) or
    not ApiGetWindowRect(FWindow, Area) then raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_MONITOR_QUERY_FAILED_8585f695);
  Width := Area.Right - Area.Left; Height := Area.Bottom - Area.Top;
  { A larger presentation window must remain inside the selected work area.
    The native scene uniformly fits the resulting client size. }
  if Width > Info.Work.Right - Info.Work.Left then Width := Info.Work.Right - Info.Work.Left;
  if Height > Info.Work.Bottom - Info.Work.Top then Height := Info.Work.Bottom - Info.Work.Top;
  if (Width <= 0) or (Height <= 0) then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_MONITOR_QUERY_FAILED_8585f695);
  X := Area.Left; Y := Area.Top;
  if X + Width > Info.Work.Right then X := Info.Work.Right - Width;
  if Y + Height > Info.Work.Bottom then Y := Info.Work.Bottom - Height;
  if X < Info.Work.Left then X := Info.Work.Left;
  if Y < Info.Work.Top then Y := Info.Work.Top;
  if not ApiSetWindowPos(FWindow, 0, X, Y, Width, Height,
    SWP_NOZORDER or SWP_NOACTIVATE) then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_MONITOR_POSITION_FAILED_22e4caca);
  FResizePending := True; FPrivacyInitialized := False; FLastFrameSeconds := 0;
end;

procedure TOverlayWindow.ReconcileDisplay;
var Dpi: TCall_GetDpiForWindow;
begin
  RequireOwner;
  if FWindow = 0 then Exit;
  CancelInteraction;
  Dpi := TCall_GetDpiForWindow(DecodeApiPointer(Slot_GetDpiForWindow));
  SetDpi(Dpi(FWindow), nil);
  FitToWorkArea;
end;

procedure TOverlayWindow.SessionChanged(Reason: NativeUInt);
begin
  CancelInteraction;
  if FContext <> nil then ImGuiFocus(FContext, False);
  case Reason of
    SessionConsoleDisconnect, SessionRemoteDisconnect, SessionLogoff, SessionLock:
      begin
        FSessionPaused := True; FRendered := False;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
        Inc(FSessionDisconnects);
{$ENDIF}
      end;
    SessionConsoleConnect, SessionRemoteConnect, SessionUnlock:
      begin
        FSessionPaused := False;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
        Inc(FSessionConnects);
{$ENDIF}
        ReconcileDisplay;
        { Focus is restored only by the real focus/activation message. }
        ApiInvalidateRect(FWindow, nil, False);
      end;
  end;
end;

procedure TOverlayWindow.SetDpi(Dpi: Cardinal; Suggested: PRect);
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
var Observed: TRect;
{$ENDIF}
begin
  RequireOwner;
  if (Dpi < 48) or (Dpi > 768) then raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_DPI_INVALID_96a3e126);
  CancelInteraction;
  FScale := Dpi / 96;
  if Suggested <> nil then
  begin
    if not ApiSetWindowPos(FWindow, 0, Suggested^.Left, Suggested^.Top,
      Suggested^.Right - Suggested^.Left, Suggested^.Bottom - Suggested^.Top,
      SWP_NOZORDER or SWP_NOACTIVATE) then raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_DPI_RESIZE_FAILED_22c2ce51);
  end
  else if not ApiSetWindowPos(FWindow, 0, 0, 0, Round(InitialWidth * FScale), Round(InitialHeight * FScale),
    SWP_NOMOVE or SWP_NOZORDER or SWP_NOACTIVATE) then raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_DPI_RESIZE_FAILED_22c2ce51);
  FResizePending := True;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
  Inc(FDpiChanges);
  { Observe the OS suggestion at application time. WM_DPICHANGED subsequently
    fits the final physical rectangle; the probe checks those bounds separately. }
  if Suggested <> nil then
    FDpiSuggestedMatches := ApiGetWindowRect(FWindow, Observed) and
      (Observed.Left = Suggested^.Left) and (Observed.Top = Suggested^.Top) and
      (Observed.Right = Suggested^.Right) and (Observed.Bottom = Suggested^.Bottom);
{$ENDIF}
end;

function TOverlayWindow.SyncTextInput: Boolean;
var Enabled: Boolean;
begin
  RequireOwner;
  Result := False;
  if FContext = nil then Exit;
  Enabled := (ReadRunState=0) and FFocused and not FSessionPaused and not FClosing and
    Assigned(FTextInputActive) and Assigned(FOnTextInput);
  if Enabled then Enabled := FTextInputActive() and AuthorityValid;
  if Enabled <> ((ImGuiTextInputStatus(FContext) and 1) <> 0) then
    if not ImGuiTextInputEnable(FContext, Enabled) then
      raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_TEXT_INPUT_FAILED_878c6ece);
  Result := Enabled;
end;

procedure TOverlayWindow.NotifyTextInput(Event: TOverlayTextInputEvent);
var Text: UTF8String;
begin
  Text := '';
  if not Assigned(FOnTextInput) then Exit;
  try
    if Event = otieCommitted then
    begin
      if not ImGuiTextInputRead(FContext, False, Text) then
        raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_TEXT_INPUT_FAILED_878c6ece);
      if Text = '' then Exit; { pending high surrogate has no committed value }
    end;
    FOnTextInput(Event, Text);
  finally
    { Text is an owned callback value, never written to diagnostics or disk.
      SetLength detaches any retained alias before clearing our local bytes. }
    if Text <> '' then
    begin
      SetLength(Text, Length(Text));
      FillChar(PAnsiChar(Text)^, Length(Text), 0);
      Text := '';
    end;
  end;
end;

procedure TOverlayWindow.ApplyCapturePrivacy;
var Requested, SetOK, ReadOK: Boolean; Desired, Observed: DWORD; At: UInt64;
begin
  RequireOwner;
  if FClosing or (FWindow = 0) then Exit;
  Requested := Assigned(FCapturePrivacy) and FCapturePrivacy();
  At := CozyTick;
  if FPrivacyInitialized and (Requested = FPrivacyRequested) and
    (At >= FPrivacyCheckTick) and (At - FPrivacyCheckTick < 1000) then Exit;
  FPrivacyInitialized := True; FPrivacyRequested := Requested; FPrivacyCheckTick := At;
  Desired := 0; if Requested then Desired := $11;
  { Only our own top-level HWND. A successful setter is not proof that every
    capture method is blocked; failed readback remains explicitly unverified. }
  SetOK := ApiSetWindowDisplayAffinity(FWindow, Desired);
  ReadOK := ApiGetWindowDisplayAffinity(FWindow, Observed);
  FPrivacyStatus := OverlayCapturePrivacyStatus(Requested, SetOK, ReadOK, Observed);
end;

procedure TOverlayWindow.Paint;
var
  Area: TRect;
  NowSeconds, Elapsed: Double;
  Delta, RunProgress: Single;
  ProgressTick: UInt64;
  SceneFlags: Cardinal;
  SceneActions, PresentResult: Integer;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  ProductPresentFault: Boolean;
{$ENDIF}
begin
  RequireOwner;
  if FClosing or FPainting or FSessionPaused or FMinimized then Exit;
  { Hidden initialization must not consume the one-time appearance animation. }
  if not FWindowShown or (FWindow=0) or not ApiIsWindowVisible(FWindow) then
  begin FRendered:=False; Exit; end;
  if FResizePending then Resize;
  FPainting := True;
  try
  FRendered := False;
  if (FContext = nil) or not AuthorityValid then Exit;
  ApplyCapturePrivacy;
  if not ApiGetClientRect(FWindow, Area) then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_WINDOW_FAILED_9b7631a7);
  if (Area.Right <= 0) or (Area.Bottom <= 0) then Exit;
  NowSeconds := CozyFrameSeconds;
  Delta := 1 / 60;
  if FLastFrameSeconds > 0 then
  begin
    Elapsed := NowSeconds - FLastFrameSeconds;
    if Elapsed < 0.000001 then Elapsed := 0.000001;
    if Elapsed > 0.1 then Elapsed := 0.1;
    Delta := Elapsed;
  end;
  FLastFrameSeconds := NowSeconds;
  FScenePhase := ReadRunState;
  FLicensedCard := -1;
  if Assigned(FGetLicensedCard) then FLicensedCard := FGetLicensedCard();
  if (FLicensedCard < -1) or (FLicensedCard > 17) then FLicensedCard := -1;
  SyncTextInput;
  if not ImGuiSetDpi(FContext, FScale) then raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_DPI_FAILED_5328f32e);
  if not ImGuiNewFrame(FContext, Area.Right, Area.Bottom, Delta) then
    raise Exception.Create(OverlayGraphicsFailure(ImGuiLastError(FContext), CozyText_Overlay_Renderer_FRAME_2dc62da1));
  ImGuiBeginCanvas(FContext);
  try
    { Local animation is independent of mouse input and server work. }
    FSceneSeconds := FSceneSeconds + Delta;
    if FSceneSeconds > 3600 then FSceneSeconds := FSceneSeconds - 3600;
    { The native scene owns pointer-follow and easing; the host owns selection. }
    FCarouselPosition := FSceneSelected;
    SceneFlags := Cardinal(FSceneCategory) shl 4;
    if FScenePhase=0 then SceneFlags := SceneFlags or IMGUI_SCENE_RUN_AVAILABLE;
    RunProgress := 0;
    ProgressTick := CozyTick;
    if (FScenePhase=2) and (FRunDuration>0) and (ProgressTick>=FRunStarted) then
    begin
      RunProgress := (ProgressTick-FRunStarted)/FRunDuration;
      if RunProgress>1 then RunProgress:=1;
    end;
    SceneActions := ImGuiProductScene(FContext, FScenePhase, FSceneSelected, SceneFlags,
      FSceneSeconds, FCarouselPosition, FLicensedCard, RunProgress);
    if SceneActions < 0 then
      raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_RENDER_FAILED_04a464ef);
    SceneActions := SceneActions or Integer(FSceneKeyActions);
    FSceneKeyActions := 0;
  finally
    ImGuiEndCanvas(FContext);
  end;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
  if Assigned(TestBeforePresent) then TestBeforePresent();
{$ENDIF}
  if not AuthorityValid then Exit;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  ProductPresentFault := FProductFaultReady and
    ProductFaultTriggered(CozyText_Overlay_Renderer_gpu_present_device_reset_8edef579);
  if ProductPresentFault then
  begin
    ProductFaultPoint(CozyText_Overlay_Renderer_gpu_present_device_reset_8edef579);
    game_imgui_test_fault(3, ProductGpuDeviceReset);
  end;
  try
{$ENDIF}
  PresentResult := ImGuiPresent(FContext);
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  finally
    if ProductPresentFault then game_imgui_test_fault(0, 0);
  end;
  if ProductPresentFault and (PresentResult = IMGUI_PRESENT_FAILED) and
    (ImGuiLastError(FContext) = ProductGpuDeviceReset) then
    ProductFaultObserved(CozyText_Overlay_Renderer_gpu_present_device_reset_8edef579);
{$ENDIF}
  if PresentResult = IMGUI_PRESENT_FAILED then
    raise Exception.Create(OverlayGraphicsFailure(ImGuiLastError(FContext), CozyText_Overlay_Renderer_PRESENT_a97dcb06));
  { A composition Present can succeed for a hidden HWND. Keep the visible
    acknowledgement and scene actions gated by the actual window state. }
  FRendered := (PresentResult = IMGUI_PRESENT_VISIBLE) and
    ApiIsWindowVisible(FWindow) and not FMinimized and not FSessionPaused;
  { Input geometry remains inactive until the full-size scene was presented.
    This latch never resets on phase changes or the hourly animation clock wrap. }
  if FRendered and (FSceneSeconds>=SceneRevealSeconds) then FSceneRevealComplete:=True;
  { A hidden/failed frame cannot commit input into another presentation phase. }
  if FRendered and AuthorityValid then ApplySceneActions(Cardinal(SceneActions));
  finally
    FPainting := False;
  end;
end;

procedure TOverlayWindow.Resize;
var Area: TRect; NativeStatus: Integer;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  ProductResizeFault, ResizeSucceeded: Boolean;
{$ENDIF}
begin
  RequireOwner;
  if FClosing then Exit;
  if FPainting then begin FResizePending := True; Exit; end;
  FResizePending := False;
  FRendered := False;
  if (FContext = nil) or (FWindow = 0) then Exit;
  if not ApiGetClientRect(FWindow, Area) then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_WINDOW_FAILED_9b7631a7);
  if (Area.Right <= 0) or (Area.Bottom <= 0) then Exit;
  { The bridge unbinds/releases the old RTV before ResizeBuffers. }
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  ProductResizeFault := FProductFaultReady and
    ProductFaultTriggered(CozyText_Overlay_Renderer_gpu_resize_device_removed_973be046);
  if ProductResizeFault then
  begin
    ProductFaultPoint(CozyText_Overlay_Renderer_gpu_resize_device_removed_973be046);
    game_imgui_test_fault(2, ProductGpuDeviceRemoved);
  end;
  try
    ResizeSucceeded := ImGuiResize(FContext, Area.Right, Area.Bottom);
  finally
    if ProductResizeFault then game_imgui_test_fault(0, 0);
  end;
  if ProductResizeFault and not ResizeSucceeded and
    (ImGuiLastError(FContext) = ProductGpuDeviceRemoved) then
    ProductFaultObserved(CozyText_Overlay_Renderer_gpu_resize_device_removed_973be046);
  if not ResizeSucceeded then
{$ELSE}
  if not ImGuiResize(FContext, Area.Right, Area.Bottom) then
{$ENDIF}
  begin
    NativeStatus := ImGuiLastError(FContext);
    raise EOverlayImGuiFailure.Create(igfsResize, NativeStatus,
      OverlayGraphicsFailure(NativeStatus, CozyText_Overlay_Renderer_RESIZE_ca35695b));
  end;
end;

function TOverlayWindow.ButtonHit(X, Y: Integer): Boolean;
var Area: TRect; Scale, VerticalScale, OriginX, OriginY: Single;
begin
  { Header space alone drags the top-level window. Every card, field, footer,
    and header control must instead receive ordinary ImGui pointer events.
    Match the scene's uniform viewport fit, including non-square DPI sizes. }
  Result := False;
  if (FWindow = 0) or not ApiGetClientRect(FWindow, Area) then Exit;
  if (X < 0) or (Y < 0) or (X >= Area.Right) or (Y >= Area.Bottom) then Exit;
  Scale := Area.Right / SceneWidth;
  VerticalScale := Area.Bottom / SceneHeight;
  if VerticalScale < Scale then Scale := VerticalScale;
  if Scale <= 0 then Exit;
  OriginX := (Area.Right-SceneWidth*Scale)/2;
  OriginY := (Area.Bottom-SceneHeight*Scale)/2;
  Result := (Y >= OriginY+SceneHeaderHeight*Scale) or
    ((X >= OriginX+180*Scale) and (X < OriginX+500*Scale) and
     (Y >= OriginY+22*Scale) and (Y < OriginY+66*Scale));
end;

procedure TOverlayWindow.UpdateCursor;
var Point: TPoint; Bounds: TRect; Cursor: HCURSOR;
begin
  if FWindow=0 then Exit;
  Cursor:=FNormalCursor;
  if FScenePhase in [1,2] then Cursor:=FBusyCursor;
  if (Cursor<>0) and ApiGetCursorPos(Point) and ApiGetWindowRect(FWindow,Bounds) and
    (Point.X>=Bounds.Left) and (Point.X<Bounds.Right) and
    (Point.Y>=Bounds.Top) and (Point.Y<Bounds.Bottom) then ApiSetCursor(Cursor);
end;

procedure TOverlayWindow.RecordRuntimeFailure;
var Code: Integer;
begin
  if not FWindowShown or FRuntimeFailureSent then Exit;
  FRuntimeFailureSent:=True; Code:=0;
  try
    if FContext<>nil then Code:=ImGuiLastError(FContext);
    if Code>=0 then Code:=0;
    if Assigned(FRuntimeFailure) then FRuntimeFailure(Code);
  except end;
end;

function TOverlayWindow.ReadRunState: Integer;
var State: Integer;
begin
  if FScenePhase=1 then
  begin
    State := 3;
    if Assigned(FProductRunState) then State := FProductRunState();
    if State=2 then
    begin
      FScenePhase:=2; FRunStarted:=CozyTick;
      FRunDeadline:=FRunStarted+FRunDuration+OverlayRunSettleMilliseconds;
    end
    else if State<>1 then
    begin FScenePhase:=0; FRunStarted:=0; FRunDeadline:=0; FRunDuration:=0; UpdateCursor; end;
  end;
  if (FScenePhase=2) and (CozyTick>=FRunDeadline) then
  begin
    FScenePhase:=0; FRunStarted:=0; FRunDeadline:=0; FRunDuration:=0;
    CancelInteraction; UpdateCursor;
  end;
  Result:=FScenePhase;
end;

procedure TOverlayWindow.ApplySceneActions(Actions: Cardinal);
var Card: Integer;
begin
  RequireOwner;
  if (Actions=0) or not FSceneRevealComplete or FClosing or FSessionPaused or
    not AuthorityValid then Exit;
  FScenePhase := ReadRunState;
  if FScenePhase<>0 then Exit;
  if (Actions and IMGUI_SCENE_RUN)<>0 then
  begin
    Card := OverlayCategoryCard(FSceneCategory,FSceneSelected);
    if not OverlayProductCanStart(FLicensedCard,Card) or
      not Assigned(FRequestProductRun) or not Assigned(FProductRunState) then Exit;
    if not FRequestProductRun(Card) then Exit;
    FScenePhase:=1; FRunStarted:=0; FRunDeadline:=0;
    FRunDuration:=OverlayProductRunMilliseconds(Card);
    CancelInteraction; UpdateCursor;
    Exit;
  end;
  if (Actions and IMGUI_SCENE_TAB_CLEANNER)<>0 then FSceneCategory:=0
  else if (Actions and IMGUI_SCENE_TAB_MOBILE)<>0 then FSceneCategory:=1
  else if (Actions and IMGUI_SCENE_TAB_SPOOFER)<>0 then FSceneCategory:=2;
  if (Actions and IMGUI_SCENE_SELECT_FIRST)<>0 then FSceneSelected:=0
  else if (Actions and IMGUI_SCENE_SELECT_SECOND)<>0 then FSceneSelected:=1
  else if (Actions and IMGUI_SCENE_SELECT_THIRD)<>0 then FSceneSelected:=2
  else if (Actions and IMGUI_SCENE_SELECT_FOURTH)<>0 then FSceneSelected:=3
  else if (Actions and IMGUI_SCENE_SELECT_FIFTH)<>0 then FSceneSelected:=4
  else if (Actions and IMGUI_SCENE_SELECT_SIXTH)<>0 then FSceneSelected:=5
  else if (Actions and IMGUI_SCENE_PREVIOUS)<>0 then FSceneSelected:=(FSceneSelected+5) mod 6
  else if (Actions and IMGUI_SCENE_NEXT)<>0 then FSceneSelected:=(FSceneSelected+1) mod 6;
end;

function TOverlayWindow.SceneKey(Key: NativeUInt; Repeated: Boolean): Boolean;
var Action: Cardinal;
begin
  Result := False;
  if not FSceneRevealComplete or SyncTextInput or (ReadRunState<>0) then Exit;
  Action := 0;
  case Key of
    VK_LEFT, Ord('A'): Action := IMGUI_SCENE_PREVIOUS;
    VK_RIGHT, Ord('D'): Action := IMGUI_SCENE_NEXT;
  end;
  Result := Action<>0;
  if Result and not Repeated then FSceneKeyActions:=FSceneKeyActions or Action;
end;

procedure TOverlayWindow.ReleaseOwnCapture;
begin
  if (FWindow = 0) or (ApiGetCapture <> FWindow) then Exit;
  FReleasingCapture := True;
  try
    ApiReleaseCapture;
  finally
    FReleasingCapture := False;
  end;
end;

procedure TOverlayWindow.CancelInteraction;
begin
  FSceneKeyActions := 0;
  FDragging := False;
  FButtonTracking := False;
  if FContext <> nil then ImGuiClearInput(FContext);
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
  Inc(FInputClearCount);
{$ENDIF}
  ReleaseOwnCapture;
end;

procedure TOverlayWindow.PointerDown(X, Y: Integer);
var Area: TRect;
begin
  if (FContext = nil) or FSessionPaused then Exit;
  if FDragging or FButtonTracking then CancelInteraction;
  if not ApiGetCursorPos(FDragAnchor) or
    not ApiGetWindowRect(FWindow, Area) then Exit;
  FDragOrigin.X := Area.Left;
  FDragOrigin.Y := Area.Top;
  ApiSetCapture(FWindow);
  if ApiGetCapture <> FWindow then Exit;
  FButtonTracking := ButtonHit(X, Y);
  FDragging := not FButtonTracking;
  ImGuiMousePos(FContext, X, Y);
  if FButtonTracking then ImGuiMouseButton(FContext, 0, True);
end;

procedure TOverlayWindow.PointerMove(X, Y: Integer);
var Cursor: TPoint; Tracking: TMouseTracking;
begin
  if (FContext = nil) or FSessionPaused then Exit;
  if not FTrackingMouse then
  begin
    FillChar(Tracking, SizeOf(Tracking), 0);
    Tracking.cbSize := SizeOf(Tracking);
    Tracking.Flags := $00000002; { TME_LEAVE }
    Tracking.Window := FWindow;
    FTrackingMouse := ApiTrackMouseEvent(Tracking);
  end;
  if (FDragging or FButtonTracking) and (ApiGetCapture <> FWindow) then
  begin
    CancelInteraction;
    Exit;
  end;
  if FDragging then
  begin
    if ApiGetCursorPos(Cursor) then
      if not ApiSetWindowPos(FWindow, 0,
        FDragOrigin.X + Cursor.X - FDragAnchor.X,
        FDragOrigin.Y + Cursor.Y - FDragAnchor.Y, 0, 0,
        SWP_NOSIZE or SWP_NOZORDER or SWP_NOACTIVATE) then
        raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_DRAG_FAILED_2ea2f8a7);
  end
  else
    ImGuiMousePos(FContext, X, Y);
end;

procedure TOverlayWindow.PointerUp(X, Y: Integer);
begin
  if FContext = nil then Exit;
  if FButtonTracking and (ApiGetCapture = FWindow) then
  begin
    ImGuiMousePos(FContext, X, Y);
    ImGuiMouseButton(FContext, 0, False);
  end;
  FDragging := False;
  FButtonTracking := False;
  { Intentional ReleaseCapture synchronously sends WM_CAPTURECHANGED.
    Do not clear the queued ImGui mouse-up before NewFrame can consume it. }
  ReleaseOwnCapture;
end;

function TOverlayWindow.Handle(Wnd: HWND; Msg: UINT; WParam: WPARAM;
  LParam: LPARAM): LRESULT;
var
  PaintInfo: TPaintStruct;
  X, Y: Integer;
  TextWasEnabled: Boolean;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
  InputClearsBefore: Cardinal;
{$ENDIF}
begin
  RequireOwner;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
  InputClearsBefore := FInputClearCount;
{$ENDIF}
  Result := 0;
  try
  if not FSceneRevealComplete or (ReadRunState<>0) then
    case Msg of
      WM_LBUTTONDOWN,WM_LBUTTONUP,WM_RBUTTONDOWN,WM_RBUTTONUP,
      WM_MOUSEMOVE,WM_MOUSEWHEEL,WM_MOUSEHWHEEL,WM_KEYDOWN,WM_KEYUP,WM_CHAR,
      WM_IME_STARTCOMPOSITION,WM_IME_COMPOSITION,WM_IME_ENDCOMPOSITION,WM_IME_CHAR: Exit(0);
    end;
  case Msg of
    WM_NCCREATE: FWindow := Wnd;
    WM_ERASEBKGND: Exit(1);
    WM_PAINT:
      begin
        FillChar(PaintInfo, SizeOf(PaintInfo), 0);
        if ApiBeginPaint(Wnd, PaintInfo) = 0 then
          raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_PAINT_FAILED_eef36588);
        try
          if not FClosing and AuthorityValid then Paint;
        finally ApiEndPaint(Wnd, PaintInfo); end;
        Exit;
      end;
    WM_SETCURSOR:
      if LOWORD(LParam)=HTCLIENT then
      begin
        if FScenePhase in [1,2] then ApiSetCursor(FBusyCursor)
        else ApiSetCursor(FNormalCursor);
        Exit(1);
      end;
    DpiChangedMessage:
      begin
        if not AuthorityValid or (LParam = 0) then Exit;
        SetDpi(LOWORD(WParam), PRect(LParam));
        { The OS suggestion may exceed the destination work area. Preserve its
          DPI/initial placement, then fit without another SetDpi recursion. }
        FitToWorkArea; Exit;
      end;
    WM_DISPLAYCHANGE:
      begin ReconcileDisplay; Exit; end;
    SessionChangedMessage:
      begin SessionChanged(WParam); Exit; end;
    WM_SIZE:
      begin
        FMinimized:=WParam=SIZE_MINIMIZED;
        if not FMinimized then begin FLastFrameSeconds:=0; Resize; end
        else begin CancelInteraction; FRendered := False; end;
        ApiInvalidateRect(Wnd, nil, False);
        Exit;
      end;
    WM_LBUTTONDOWN:
      begin
        if not AuthorityValid then Exit;
        X := SmallInt(LOWORD(LParam)); Y := SmallInt(HIWORD(LParam));
        PointerDown(X, Y);
        Exit;
      end;
    WM_MOUSEMOVE:
      begin
        if not AuthorityValid then Exit;
        X := SmallInt(LOWORD(LParam)); Y := SmallInt(HIWORD(LParam));
        PointerMove(X, Y);
        Exit;
      end;
    WM_MOUSELEAVE:
      begin
        FTrackingMouse := False;
        if FContext <> nil then ImGuiMousePos(FContext, -1E30, -1E30);
        Exit;
      end;
    WM_LBUTTONUP:
      begin
        if not AuthorityValid then Exit;
        X := SmallInt(LOWORD(LParam)); Y := SmallInt(HIWORD(LParam));
        PointerUp(X, Y);
        Exit;
      end;
    WM_MOUSEWHEEL, WM_MOUSEHWHEEL:
      begin
        if not AuthorityValid or FSessionPaused or (FContext = nil) then Exit;
        if Msg = WM_MOUSEWHEEL then
          ImGuiMouseWheel(FContext, 0, SmallInt(HIWORD(WParam)) / 120)
        else ImGuiMouseWheel(FContext, SmallInt(HIWORD(WParam)) / 120, 0);
        Exit;
      end;
    WM_CAPTURECHANGED:
      begin
        if not FReleasingCapture then CancelInteraction;
        Exit;
      end;
    WM_CANCELMODE:
      begin CancelInteraction; Exit; end;
    WM_SETFOCUS:
      begin
        FFocused := True;
        if (FContext <> nil) and not FSessionPaused then ImGuiFocus(FContext, True);
        Exit;
      end;
    WM_KILLFOCUS:
      begin
        CancelInteraction;
        TextWasEnabled := (FContext <> nil) and
          ((ImGuiTextInputStatus(FContext) and 1) <> 0);
        FFocused := False;
        SyncTextInput;
        if TextWasEnabled then NotifyTextInput(otieFocusLost);
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
        Inc(FFocusLosses);
{$ENDIF}
        if FContext <> nil then ImGuiFocus(FContext, False);
        Exit;
      end;
    WM_ACTIVATE:
      if LOWORD(WParam) = WA_INACTIVE then CancelInteraction;
    WM_ACTIVATEAPP:
      begin
        if WParam = 0 then begin FFocused := False; CancelInteraction; SyncTextInput; end;
        if FContext <> nil then ImGuiFocus(FContext, (WParam <> 0) and not FSessionPaused);
      end;
    WM_IME_STARTCOMPOSITION:
      begin
        if not SyncTextInput then Exit;
        if not ImGuiTextInputEvent(FContext, itiaBegin, '') then
          raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_TEXT_INPUT_FAILED_878c6ece);
        NotifyTextInput(otieCompositionBegin);
        { Preserve normal Windows candidate/composition UI. }
        Exit(ApiDefWindowProcW(Wnd, Msg, WParam, LParam));
      end;
    WM_IME_COMPOSITION:
      begin
        if not SyncTextInput then Exit;
        { No GCS values means cancellation. We never read GCS_RESULTSTR:
          the default IME window later commits through WM_CHAR exactly once. }
        if (NativeUInt(LParam) and $1FFF) = 0 then
        begin
          ImGuiTextInputEvent(FContext, itiaCancel, '');
          NotifyTextInput(otieCompositionCancelled);
        end;
        Exit(ApiDefWindowProcW(Wnd, Msg, WParam, LParam));
      end;
    WM_IME_ENDCOMPOSITION:
      begin
        if not SyncTextInput then Exit;
        ImGuiTextInputEvent(FContext, itiaEnd, '');
        NotifyTextInput(otieCompositionEnd);
        Exit(ApiDefWindowProcW(Wnd, Msg, WParam, LParam));
      end;
    WM_IME_CHAR:
      begin
        if not SyncTextInput then Exit;
        { Do not feed text here as well as WM_CHAR. }
        Exit(ApiDefWindowProcW(Wnd, Msg, WParam, LParam));
      end;
    WM_CHAR:
      begin
        if not SyncTextInput then Exit;
        if (WParam = 8) or (WParam = 13) or (WParam > $FFFF) then
        begin
          { A control/rejected code point is a decoder boundary. Never retain
            an unmatched high surrogate and drop the next valid character. }
          ImGuiTextInputEvent(FContext, itiaCancel, '');
          if WParam = 8 then NotifyTextInput(otieBackspace)
          else if WParam = 13 then NotifyTextInput(otieSubmit);
        end
        else if ImGuiTextInputUtf16(FContext, Cardinal(WParam)) then
          NotifyTextInput(otieCommitted);
        Exit;
      end;
    WM_KEYDOWN, WM_KEYUP:
      begin
        if not AuthorityValid or FSessionPaused or not FFocused then Exit;
        if (Msg = WM_KEYDOWN) and SceneKey(WParam,
          (NativeUInt(LParam) and $40000000) <> 0) then Exit;
        { Enter activates the currently focused ImGui button, not a global
          Run shortcut. Do not inject repeated key-down events while held. }
        if (Msg = WM_KEYDOWN) and (WParam = VK_RETURN) and
          ((NativeUInt(LParam) and $40000000) <> 0) and not SyncTextInput then Exit;
        if (Msg = WM_KEYDOWN) and (WParam = VK_ESCAPE) then
        begin
          if SyncTextInput and ((ImGuiTextInputStatus(FContext) and 4) <> 0) then
          begin
            ImGuiTextInputEvent(FContext, itiaCancel, '');
            NotifyTextInput(otieCompositionCancelled);
            Exit(ApiDefWindowProcW(Wnd, Msg, WParam, LParam));
          end;
          BeginClosing; ApiDestroyWindow(Wnd);
        end
        else if FContext <> nil then ImGuiKey(FContext, Integer(WParam), Msg = WM_KEYDOWN);
        Exit;
      end;
    WM_CLOSE: begin BeginClosing; ApiDestroyWindow(Wnd); Exit; end;
    WM_DESTROY:
      begin
        BeginClosing;
        CancelInteraction;
        UnregisterSession;

        FWindow := 0;
        ApiPostQuitMessage(0);
        Exit;
      end;
  end;
  Result := ApiDefWindowProcW(Wnd, Msg, WParam, LParam);
  finally
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
    if Assigned(TestEnvironmentObserver) then TestEnvironmentObserver(Msg, WParam, LParam, InputClearsBefore);
{$ENDIF}
  end;
end;

function TOverlayWindow.AuthorityValid: Boolean;
begin
  RequireOwner;
  { Windows/graphics initialization can synchronously re-enter WindowProc.
    Pending initial authority means "do not paint", not "revoke a lease that
    has not been acquired yet". No window is shown in this phase. }
  if FAuthorizing then Exit(False);
  Result := not FClosing and not FFailed and Assigned(FShouldClose) and not FShouldClose();
  if not Result then
  begin
    FFailed := True;
    BeginClosing;
    CancelInteraction;
    if FWindow <> 0 then ApiShowWindow(FWindow, SW_HIDE);
    ApiPostQuitMessage(1);
  end;
end;

function TOverlayWindow.Run(const Tick: TProc;
  const ShouldClose: TFunc<Boolean>; const OnClosing: TProc; const AuthorizeBeforeShow: TProc; const CapturePrivacy: TFunc<Boolean>; const OnHidden: TProc; const StartupPhase: TProc<string>; const TextInputActive: TFunc<Boolean>; const OnTextInput: TOverlayTextInputCallback; const RequestRun: TProc; const RunState: TFunc<Integer>; const StartupFailure: TProc<string,Integer>; const RuntimeFailure: TProc<Integer>; const LicensedCard: TFunc<Integer>; const RequestProductRun: TFunc<Integer,Boolean>; const ProductRunState: TFunc<Integer>): Integer;
var
  WndClass: TWndClassExW;
  Msg: TMsg;
  MessageCount: Integer; QuitSeen: Boolean; DpiProc: TCall_GetDpiForWindow;
  WindowShowStarted: Boolean;
  ActiveStartupStage, FailureStage: string; FailureCode: Integer;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  ProductCreateFault: Boolean;
{$ENDIF}
begin
  RequireOwner;
  WindowShowStarted := False;
  ActiveStartupStage := CozyText_Overlay_Renderer_UNKNOWN_d68268a9;
  if FClosing then raise EInvalidOpException.Create(CozyText_Overlay_Renderer_OVERLAY_CLOSED_245f6c9e);
  Result := 1;
  if not Assigned(Tick) or not Assigned(ShouldClose) then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_AUTHORITY_REQUIRED_627ac906);
  {$IFDEF GAME_APPLICATION_BUILD}
  if not Assigned(AuthorizeBeforeShow) then raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_INITIAL_AUTHORITY_REQUIRED_3a6b58b3);
  {$ENDIF}
  FAuthorizing := Assigned(AuthorizeBeforeShow);
  FShouldClose := ShouldClose;
  FOnClosing := OnClosing;
  FOnHidden := OnHidden;
  FCapturePrivacy := CapturePrivacy;
  FTextInputActive := TextInputActive;
  FOnTextInput := OnTextInput;
  { Legacy callbacks remain unused; product START has a separate typed queue.
    No callback may block the UI thread or directly access the transport. }
  FGetLicensedCard:=LicensedCard;
  FRequestProductRun:=RequestProductRun;
  FProductRunState:=ProductRunState;
  FRuntimeFailure:=RuntimeFailure;
  if not Assigned(AuthorizeBeforeShow) then
    if not AuthorityValid then Exit;
  FillChar(WndClass, SizeOf(WndClass), 0);
  WndClass.cbSize := SizeOf(WndClass);
  WndClass.style := CS_HREDRAW or CS_VREDRAW;
  WndClass.lpfnWndProc := @WindowProc;
  WndClass.hInstance := HInstance;
  FNormalCursor:=ApiLoadCursorW(0,PWideChar(NativeUInt(32512)));
  FBusyCursor:=ApiLoadCursorW(0,PWideChar(NativeUInt(32648))); { IDC_NO }
  if (FNormalCursor=0) or (FBusyCursor=0) then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_WINDOW_FAILED_9b7631a7);
  WndClass.hCursor:=FNormalCursor;
  WndClass.lpszClassName := OverlayClass;
  if ApiRegisterClassExW(WndClass) = 0 then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_WINDOW_FAILED_9b7631a7);
  try
    try
    FWindow := ApiCreateWindowExW(WS_EX_TOPMOST or WS_EX_TOOLWINDOW or OverlayNoRedirectionBitmap,
      OverlayClass, CozyText_Overlay_Renderer_Overlay_ImGui_be6c27e7, WS_POPUP,
      100, 100, InitialWidth, InitialHeight, 0, 0, HInstance, nil);
    if FWindow = 0 then raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_WINDOW_FAILED_9b7631a7);
    TryRegisterSession;
    DpiProc := TCall_GetDpiForWindow(DecodeApiPointer(Slot_GetDpiForWindow));
    SetDpi(DpiProc(FWindow), nil);
    ReconcileDisplay;
    if FClosing or FFailed then Exit;
    if not Assigned(AuthorizeBeforeShow) then
      if not AuthorityValid then Exit;
    ActiveStartupStage := CozyText_Overlay_Renderer_CREATE_67557180;
    if Assigned(StartupPhase) then StartupPhase(CozyText_Overlay_Renderer_GPU_BEGIN_f4c09728);
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
    ProductCreateFault := ProductFaultTriggered(CozyText_Overlay_Renderer_gpu_create_e_outofmemory_e99c8c20);
    if ProductCreateFault then
    begin
      ProductFaultPoint(CozyText_Overlay_Renderer_gpu_create_e_outofmemory_e99c8c20);
      game_imgui_test_fault(1, ProductGpuOutOfMemory);
    end;
    try
      try
        FContext := ImGuiCreate(NativeUInt(FWindow));
      except
        on E: Exception do
        begin
          if ProductCreateFault and (FContext = nil) and
            (E.Message = OverlayGraphicsFailure(ProductGpuOutOfMemory, CozyText_Overlay_Renderer_CREATE_67557180)) then
            ProductFaultObserved(CozyText_Overlay_Renderer_gpu_create_e_outofmemory_e99c8c20);
          raise;
        end;
      end;
    finally
      if ProductCreateFault then game_imgui_test_fault(0, 0);
    end;
{$ELSE}
    FContext := ImGuiCreate(NativeUInt(FWindow));
{$ENDIF}
    ActiveStartupStage := CozyText_Overlay_Renderer_RESIZE_ca35695b;
    Resize;
    { Claim permits only hidden initialization. Capture the actual selected
      device before initial authority/profile negotiation; never guess by
      display enumeration. Mandatory profiles reject unavailable identities. }
    ActiveStartupStage := CozyText_Overlay_Renderer_GPU_IDENTITY_35325f01;
    SetMitigationGpuIdentity(ImGuiGpuIdentity(FContext));
    ActiveStartupStage := CozyText_Overlay_Renderer_UNKNOWN_d68268a9;
    if Assigned(StartupPhase) then StartupPhase(CozyText_Overlay_Renderer_GPU_READY_1c4f609c);
    if FClosing or FFailed then Exit;
    try
      if Assigned(AuthorizeBeforeShow) then AuthorizeBeforeShow();
    finally FAuthorizing := False; end;
    if not AuthorityValid then Exit;
    ApplyCapturePrivacy;
    if not AuthorityValid then Exit;
    WindowShowStarted := True; FWindowShown:=True;
    ApiShowWindow(FWindow, SW_SHOWNORMAL);
    QuitSeen:=False;
    while not QuitSeen do
    begin
      if FClosing or not AuthorityValid then Break;
      TryRegisterSession;
      MessageCount:=0;
      while (MessageCount<128) and ApiPeekMessageW(Msg,0,0,0,PM_REMOVE) do
      begin
        if Msg.message=WM_QUIT then
        begin
          if Msg.wParam<>0 then FFailed:=True;
          QuitSeen:=True; Break;
        end;
        ApiTranslateMessage(Msg); ApiDispatchMessageW(Msg);
        Inc(MessageCount);
        if FClosing then Break;
      end;
      if QuitSeen or FClosing or not AuthorityValid then Break;
      { Present(1) with one queued frame follows the actual monitor. A second
        16ms timer would cap high refresh displays and produce uneven pacing. }
      Paint;
      if FRendered and not FSessionPaused and not FMinimized and (FWindow<>0) then
      begin
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
        if Assigned(TestBeforeReady) then TestBeforeReady();
{$ENDIF}
        if not AuthorityValid then Break;
        Tick();
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
        if not FProductFaultReady then
        begin
          FProductFaultReady:=True;
          if ProductFaultTriggered(CozyText_Overlay_Renderer_gpu_resize_device_removed_973be046) then
            FResizePending:=True;
        end;
{$ENDIF}
        if not AuthorityValid then Break;
      end
      else if ApiWaitForInput=WAIT_FAILED then
        raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_MESSAGE_FAILED_b9676aaf);
    end;
    if not FFailed then Result := 0;
    except
      on E: Exception do
      begin
        if WindowShowStarted then RecordRuntimeFailure;
        { Hidden startup diagnostics precede cancellation. Only a closed stage
          and primitive native code cross the callback; never exception text.
          Once showing starts, teardown cannot wait for this network channel. }
        if not WindowShowStarted and not FClosing then
        begin
          if Assigned(StartupFailure) then
          begin
            FailureStage := ActiveStartupStage; FailureCode := 0;
            if E is EOverlayImGuiFailure then
            begin
              case EOverlayImGuiFailure(E).Stage of
                igfsBinding: FailureStage := CozyText_Overlay_Renderer_BINDING_dc262c4a;
                igfsFontRead: FailureStage := CozyText_Overlay_Renderer_FONT_READ_bb9447b4;
                igfsFontData: FailureStage := CozyText_Overlay_Renderer_FONT_DATA_73de0b71;
                igfsCreate: FailureStage := CozyText_Overlay_Renderer_CREATE_67557180;
                igfsResize: FailureStage := CozyText_Overlay_Renderer_RESIZE_ca35695b;
              end;
              FailureCode := EOverlayImGuiFailure(E).NativeCode;
            end
            else
            begin
              if E is EMathError then
                FailureStage := CozyText_Overlay_Renderer_FLOATING_POINT_562b19d1;
              { Copy only the OS numeric code while its exception record is
                alive. Never retain addresses, parameters, paths or messages. }
              if E is EExternal then
              begin
                { This renderer is Windows-only; retain its native SEH code.
                  Scope the platform annotation to these two field accesses. }
{$PUSHOPT}
{$WARN SYMBOL_PLATFORM OFF}
                if EExternal(E).ExceptionRecord <> nil then
                  FailureCode := Integer(EExternal(E).ExceptionRecord^.ExceptionCode);
{$POPOPT}
              end
              else if E is EOSError then FailureCode := Integer(EOSError(E).ErrorCode);
            end;
            try StartupFailure(FailureStage, FailureCode); except end;
          end
          else if Assigned(StartupPhase) then
            try StartupPhase(CozyText_Overlay_Renderer_FAILED_6dbd52bc); except end;
        end;
        raise;
      end;
    end;
  finally
    BeginClosing;
    try
      UnregisterSession;
      if FWindow <> 0 then
        if not ApiDestroyWindow(FWindow) then Result := 1;
    finally
      try
        if not ApiUnregisterClassW(OverlayClass, HInstance) then Result := 1;
      finally
        FShouldClose := nil;
        FRuntimeFailure := nil;
        FGetLicensedCard := nil; FRequestProductRun := nil; FProductRunState := nil;
        FCapturePrivacy := nil;
        if FFailed then Result := 1;
      end;
    end;
  end;
end;

function RunOverlayUI(const Tick: TProc;
  const ShouldClose: TFunc<Boolean>; const OnClosing: TProc; const AuthorizeBeforeShow: TProc; const CapturePrivacy: TFunc<Boolean>; const OnHidden: TProc; const StartupPhase: TProc<string>; const TextInputActive: TFunc<Boolean>; const OnTextInput: TOverlayTextInputCallback; const RequestRun: TProc; const RunState: TFunc<Integer>; const StartupFailure: TProc<string,Integer>; const RuntimeFailure: TProc<Integer>; const LicensedCard: TFunc<Integer>; const RequestProductRun: TFunc<Integer,Boolean>; const ProductRunState: TFunc<Integer>): Integer;
var Window: TOverlayWindow;
begin
  if TInterlocked.CompareExchange(RendererRunning, 1, 0) <> 0 then
    raise Exception.Create(CozyText_Overlay_Renderer_OVERLAY_ALREADY_RUNNING_6034ff09);
  Window := nil;
  try
    Window := TOverlayWindow.Create;
    ActiveWindow := Window;
    Result := Window.Run(Tick, ShouldClose, OnClosing, AuthorizeBeforeShow, CapturePrivacy, OnHidden, StartupPhase, TextInputActive, OnTextInput, RequestRun, RunState, StartupFailure, RuntimeFailure, LicensedCard, RequestProductRun, ProductRunState);
  finally
    try Window.Free;
    finally
      ActiveWindow := nil;
      TInterlocked.Exchange(RendererRunning, 0);
    end;
  end;
end;

{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
procedure SetOverlayEnvironmentObserver(const Observer: TOverlayEnvironmentObserver);
begin
  if TInterlocked.CompareExchange(RendererRunning,0,0) <> 0 then
    raise EInvalidOpException.Create(CozyText_Overlay_Renderer_OVERLAY_TEST_ALREADY_RUNNING_f593933f);
  TestEnvironmentObserver := Observer;
end;
function OverlayTestEnvironment: TOverlayEnvironmentSnapshot;
begin
  Result := Default(TOverlayEnvironmentSnapshot);
  if ActiveWindow = nil then Exit;
  ActiveWindow.RequireOwner;
  Result.Window := NativeUInt(ActiveWindow.FWindow);
  Result.Dpi := Round(ActiveWindow.FScale * 96);
  Result.ScenePhase := ActiveWindow.FScenePhase;
  Result.SceneSelected := ActiveWindow.FSceneSelected;
  Result.SceneCategory := ActiveWindow.FSceneCategory;
  Result.LicensedCard := ActiveWindow.FLicensedCard;
  Result.RevealComplete := ActiveWindow.FSceneRevealComplete;
  Result.ReceiptOnly := False; { Legacy observation: terminal receipt UI removed. }
  Result.InputClearCount := ActiveWindow.FInputClearCount;
  Result.DpiChanges := ActiveWindow.FDpiChanges;
  Result.FocusLosses := ActiveWindow.FFocusLosses;
  Result.SessionConnects := ActiveWindow.FSessionConnects;
  Result.SessionDisconnects := ActiveWindow.FSessionDisconnects;
  Result.Dragging := ActiveWindow.FDragging;
  Result.ButtonTracking := ActiveWindow.FButtonTracking;
  Result.CaptureOwned := (ActiveWindow.FWindow <> 0) and (ApiGetCapture = ActiveWindow.FWindow);
  Result.SessionPaused := ActiveWindow.FSessionPaused;
  Result.SessionNotificationsRegistered := ActiveWindow.FSessionRegistered;
  Result.DpiSuggestedMatches := ActiveWindow.FDpiSuggestedMatches;
  if ActiveWindow.FWindow <> 0 then ApiGetWindowRect(ActiveWindow.FWindow, Result.WindowRect);
end;
function OverlayTestButtonHit(X, Y: Integer): Boolean;
begin
  Result := False;
  if ActiveWindow <> nil then
  begin ActiveWindow.RequireOwner; Result := ActiveWindow.ButtonHit(X,Y); end;
end;
procedure SetOverlayTestHooks(const BeforePresent, BeforeReady: TProc);
begin
  if TInterlocked.CompareExchange(RendererRunning,0,0) <> 0 then
    raise EInvalidOpException.Create(CozyText_Overlay_Renderer_OVERLAY_TEST_ALREADY_RUNNING_f593933f);
  TestBeforePresent := BeforePresent; TestBeforeReady := BeforeReady;
end;
function OverlayTestWindow: NativeUInt;
begin
  Result := 0;
  if ActiveWindow <> nil then
  begin ActiveWindow.RequireOwner; Result := NativeUInt(ActiveWindow.FWindow); end;
end;
function OverlayTestCapturePrivacyStatus: string;
begin
  Result := '';
  if ActiveWindow <> nil then
  begin ActiveWindow.RequireOwner; Result := ActiveWindow.FPrivacyStatus; end;
end;
{$ENDIF}

procedure BindOptionalSessionApis;
var RegisterAddress, UnregisterAddress: Pointer;
begin
  { Keep both lifetime-retained addresses encoded, or leave both unavailable.
    Missing RDS services/exports cannot make a previously valid A/B/O fail. }
  try
    RegisterAddress := OptionalSystemProcAddressHash64(CozyText_Overlay_Renderer_wtsapi32_dll_4c702727, HASH_WTSRegisterSessionNotification);
    UnregisterAddress := OptionalSystemProcAddressHash64(CozyText_Overlay_Renderer_wtsapi32_dll_4c702727, HASH_WTSUnRegisterSessionNotification);
  except
    Exit;
  end;
  if (RegisterAddress = nil) or (UnregisterAddress = nil) then Exit;
  BindApiPointer(Slot_WTSRegisterSessionNotification, RegisterAddress);
  BindApiPointer(Slot_WTSUnRegisterSessionNotification, UnregisterAddress);
end;

initialization
  BindOptionalSessionApis;
  BindApiPointer(Slot_PeekMessageW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_PeekMessageW));
  BindApiPointer(Slot_MsgWaitForMultipleObjectsEx, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_MsgWaitForMultipleObjectsEx));
  BindApiPointer(Slot_SetCursor, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_SetCursor));

  BindApiPointer(Slot_SetWindowDisplayAffinity, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_SetWindowDisplayAffinity));
  BindApiPointer(Slot_GetWindowDisplayAffinity, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_GetWindowDisplayAffinity));
  BindApiPointer(Slot_GetDpiForWindow, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_GetDpiForWindow));
  BindApiPointer(Slot_MonitorFromWindow, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_MonitorFromWindow));
  BindApiPointer(Slot_GetMonitorInfoW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_GetMonitorInfoW));
  BindApiPointer(Slot_GetCurrentThreadId, RequireProcAddressHash64(CozyText_Overlay_Renderer_kernel32_dll_856d7a7d, HASH_GetCurrentThreadId));
  BindApiPointer(Slot_RegisterClassExW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_RegisterClassExW));
  BindApiPointer(Slot_UnregisterClassW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_UnregisterClassW));
  BindApiPointer(Slot_CreateWindowExW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_CreateWindowExW));
  BindApiPointer(Slot_DefWindowProcW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_DefWindowProcW));
  BindApiPointer(Slot_DestroyWindow, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_DestroyWindow));
  BindApiPointer(Slot_ShowWindow, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_ShowWindow));
  BindApiPointer(Slot_TranslateMessage, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_TranslateMessage));
  BindApiPointer(Slot_DispatchMessageW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_DispatchMessageW));
  BindApiPointer(Slot_PostQuitMessage, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_PostQuitMessage));
  BindApiPointer(Slot_BeginPaint, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_BeginPaint));
  BindApiPointer(Slot_EndPaint, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_EndPaint));
  BindApiPointer(Slot_GetClientRect, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_GetClientRect));
  BindApiPointer(Slot_InvalidateRect, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_InvalidateRect));
  BindApiPointer(Slot_LoadCursorW, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_LoadCursorW));
  BindApiPointer(Slot_SetCapture, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_SetCapture));
  BindApiPointer(Slot_GetCapture, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_GetCapture));
  BindApiPointer(Slot_ReleaseCapture, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_ReleaseCapture));
  BindApiPointer(Slot_GetCursorPos, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_GetCursorPos));
  BindApiPointer(Slot_GetWindowRect, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_GetWindowRect));
  BindApiPointer(Slot_IsWindowVisible, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_IsWindowVisible));
  BindApiPointer(Slot_SetWindowPos, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_SetWindowPos));

  BindApiPointer(Slot_TrackMouseEvent, RequireProcAddressHash64(CozyText_Overlay_Renderer_user32_dll_6bea8c9c, HASH_TrackMouseEvent));
end.
