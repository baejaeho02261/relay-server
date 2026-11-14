unit Cozy.License.Window;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{$ALIGN 8}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.License,
 System.SysUtils, Cozy.SensitiveText;
type
  TLicenseSubmitKey = reference to function(var Key: TCozySensitiveText): Boolean;
{ UI callbacks run on the owning thread. Only the worker performs API I/O.
  BeforeShow authorizes after hidden GPU setup; OnClose requests cancellation.
  JoinWorker completes before GPU resources are released. }
function RunLicenseWindow(const BeforeShow: TProc; const SubmitKey: TLicenseSubmitKey;
  const ReadState, ReadProgress: TFunc<Integer>; const OnClose, JoinWorker: TProc): Integer;
implementation
uses Winapi.Windows, Winapi.Messages, System.Types, Cozy.Clock,
  Cozy.License.Commands, Cozy.Overlay.ImGui, Cozy.ProcessMitigations,
  Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver;
const
  LicenseClass: PWideChar = CozyText_License_Window_CozyLicenseImGuiV1_38a667fb;
  PanelWidth = 340;
  PanelHeight = 380;
  MaximumKeyCharacters = 100;
  MaximumClipboardCharacters = 4096;
  InputLeft = 49;
  InputTop = 185;
  InputRight = 291;
  InputBottom = 227;
  NoRedirectionBitmap = $00200000;
  WaitInputAvailable = $0004;
  DpiChangedMessage = $02E0;
  LicenseMonitorDefaultToNearest = $00000002; { Win32 MONITOR_DEFAULTTONEAREST }
type
  TLicenseMonitorInfo = record
    Size: DWORD;
    Monitor, Work: TRect;
    Flags: DWORD;
  end;
  TCall_RegisterClassExW = function(const Value: TWndClassExW): ATOM; stdcall;
  TCall_UnregisterClassW = function(Name: PWideChar; Instance: HINST): BOOL; stdcall;
  TCall_CreateWindowExW = function(ExStyle: DWORD; ClassName, WindowName: PWideChar; Style: DWORD; X, Y, Width, Height: Integer; Parent: HWND; Menu: HMENU; Instance: HINST; Param: Pointer): HWND; stdcall;
  TCall_DefWindowProcW = function(Window: HWND; Msg: UINT; WParam: WPARAM; LParam: LPARAM): LRESULT; stdcall;
  TCall_DestroyWindow = function(Window: HWND): BOOL; stdcall;
  TCall_ShowWindow = function(Window: HWND; Show: Integer): BOOL; stdcall;
  TCall_PeekMessageW = function(var Msg: TMsg; Window: HWND; First, Last, Remove: UINT): BOOL; stdcall;
  TCall_MsgWaitForMultipleObjectsEx = function(Count: DWORD; Handles: Pointer; Milliseconds, WakeMask, Flags: DWORD): DWORD; stdcall;
  TCall_TranslateMessage = function(const Msg: TMsg): BOOL; stdcall;
  TCall_DispatchMessageW = function(const Msg: TMsg): LRESULT; stdcall;
  TCall_GetClientRect = function(Window: HWND; var Rect: TRect): BOOL; stdcall;
  TCall_BeginPaint = function(Window: HWND; var Paint: TPaintStruct): HDC; stdcall;
  TCall_EndPaint = function(Window: HWND; const Paint: TPaintStruct): BOOL; stdcall;
  TCall_LoadCursorW = function(Instance: HINST; Name: PWideChar): HCURSOR; stdcall;
  TCall_SetCursor = function(Cursor: HCURSOR): HCURSOR; stdcall;
  TCall_SetCapture = function(Window: HWND): HWND; stdcall;
  TCall_GetCapture = function: HWND; stdcall;
  TCall_ReleaseCapture = function: BOOL; stdcall;
  TCall_GetCursorPos = function(var Point: TPoint): BOOL; stdcall;
  TCall_GetWindowRect = function(Window: HWND; var Rect: TRect): BOOL; stdcall;
  TCall_SetWindowPos = function(Window, After: HWND; X, Y, Width, Height: Integer; Flags: UINT): BOOL; stdcall;
  TCall_GetDpiForWindow = function(Window: HWND): UINT; stdcall;
  TCall_MonitorFromWindow = function(Window: HWND; Flags: DWORD): THandle; stdcall;
  TCall_GetMonitorInfoW = function(Monitor: THandle; Info: Pointer): BOOL; stdcall;
  TCall_GetCurrentThreadId = function: DWORD; stdcall;
  TCall_GlobalSize = function(Memory: HGLOBAL): NativeUInt; stdcall;
  TCall_GlobalLock = function(Memory: HGLOBAL): Pointer; stdcall;
  TCall_GlobalUnlock = function(Memory: HGLOBAL): BOOL; stdcall;
  TCall_OpenClipboard = function(Window: HWND): BOOL; stdcall;
  TCall_CloseClipboard = function: BOOL; stdcall;
  TCall_GetClipboardData = function(Format: UINT): THandle; stdcall;
  TCall_IsClipboardFormatAvailable = function(Format: UINT): BOOL; stdcall;
  TLicenseWindow = class
  private
    FWindow: HWND;
    FContext: TImGuiContext;
    FKey: TCozySensitiveText;
    FOwnerThread: DWORD;
    FScale, FElapsed: Single;
    FLastFrame: Double;
    FFocused, FClosing, FClassRegistered, FResizePending, FMinimized,
      FDragging, FShift, FWasBusy, FShown, FCloseNotified,
      FReleasingCapture, FVisibleFrame, FInputFocused: Boolean;
    FDragAnchor, FDragOrigin: TPoint;
    FNormalCursor, FInputCursor, FBusyCursor: HCURSOR;
    FSubmit: TLicenseSubmitKey;
    FState, FProgress: TFunc<Integer>;
    FOnClose, FJoinWorker: TProc;
    procedure RequireOwner;
    procedure Close;
    procedure CancelInput;
    procedure ReleaseOwnCapture;
    procedure Resize;
    procedure FitWindow(const Suggested: PRect = nil);
    procedure PasteKey;
    procedure Submit;
    procedure Paint;
    procedure UpdateCursor;
    function BusyVisual: Boolean;
    function InputEnabled: Boolean;
    function InputContains(X, Y: Integer): Boolean;
    function Message(Window: HWND; Msg: UINT; WParam: WPARAM; LParam: LPARAM): LRESULT;
  public
    constructor Create(const SubmitKey: TLicenseSubmitKey;
      const ReadState, ReadProgress: TFunc<Integer>; const OnClose, JoinWorker: TProc);
    destructor Destroy; override;
    function Run(const BeforeShow: TProc): Integer;
  end;
var CurrentWindow: TLicenseWindow;
  ApiSlot_RegisterClassExW: TEncodedApiPointer;
  ApiSlot_UnregisterClassW: TEncodedApiPointer;
  ApiSlot_CreateWindowExW: TEncodedApiPointer;
  ApiSlot_DefWindowProcW: TEncodedApiPointer;
  ApiSlot_DestroyWindow: TEncodedApiPointer;
  ApiSlot_ShowWindow: TEncodedApiPointer;
  ApiSlot_PeekMessageW: TEncodedApiPointer;
  ApiSlot_MsgWaitForMultipleObjectsEx: TEncodedApiPointer;
  ApiSlot_TranslateMessage: TEncodedApiPointer;
  ApiSlot_DispatchMessageW: TEncodedApiPointer;
  ApiSlot_GetClientRect: TEncodedApiPointer;
  ApiSlot_BeginPaint: TEncodedApiPointer;
  ApiSlot_EndPaint: TEncodedApiPointer;
  ApiSlot_LoadCursorW: TEncodedApiPointer;
  ApiSlot_SetCursor: TEncodedApiPointer;
  ApiSlot_SetCapture: TEncodedApiPointer;
  ApiSlot_GetCapture: TEncodedApiPointer;
  ApiSlot_ReleaseCapture: TEncodedApiPointer;
  ApiSlot_GetCursorPos: TEncodedApiPointer;
  ApiSlot_GetWindowRect: TEncodedApiPointer;
  ApiSlot_SetWindowPos: TEncodedApiPointer;
  ApiSlot_GetDpiForWindow: TEncodedApiPointer;
  ApiSlot_MonitorFromWindow: TEncodedApiPointer;
  ApiSlot_GetMonitorInfoW: TEncodedApiPointer;
  ApiSlot_GetCurrentThreadId: TEncodedApiPointer;
  ApiSlot_GlobalSize: TEncodedApiPointer;
  ApiSlot_GlobalLock: TEncodedApiPointer;
  ApiSlot_GlobalUnlock: TEncodedApiPointer;
  ApiSlot_OpenClipboard: TEncodedApiPointer;
  ApiSlot_CloseClipboard: TEncodedApiPointer;
  ApiSlot_GetClipboardData: TEncodedApiPointer;
  ApiSlot_IsClipboardFormatAvailable: TEncodedApiPointer;

function ApiRegisterClassExW(const Value: TWndClassExW): ATOM;
var Target: TCall_RegisterClassExW;
begin
  Target := TCall_RegisterClassExW(DecodeApiPointer(ApiSlot_RegisterClassExW));
  Result := Target(Value);
end;

function ApiUnregisterClassW(Name: PWideChar; Instance: HINST): BOOL;
var Target: TCall_UnregisterClassW;
begin
  Target := TCall_UnregisterClassW(DecodeApiPointer(ApiSlot_UnregisterClassW));
  Result := Target(Name, Instance);
end;

function ApiCreateWindowExW(ExStyle: DWORD; ClassName, WindowName: PWideChar; Style: DWORD; X, Y, Width, Height: Integer; Parent: HWND; Menu: HMENU; Instance: HINST; Param: Pointer): HWND;
var Target: TCall_CreateWindowExW;
begin
  Target := TCall_CreateWindowExW(DecodeApiPointer(ApiSlot_CreateWindowExW));
  Result := Target(ExStyle, ClassName, WindowName, Style, X, Y, Width, Height, Parent, Menu, Instance, Param);
end;

function ApiDefWindowProcW(Window: HWND; Msg: UINT; WParam: WPARAM; LParam: LPARAM): LRESULT;
var Target: TCall_DefWindowProcW;
begin
  Target := TCall_DefWindowProcW(DecodeApiPointer(ApiSlot_DefWindowProcW));
  Result := Target(Window, Msg, WParam, LParam);
end;

function ApiDestroyWindow(Window: HWND): BOOL;
var Target: TCall_DestroyWindow;
begin
  Target := TCall_DestroyWindow(DecodeApiPointer(ApiSlot_DestroyWindow));
  Result := Target(Window);
end;

function ApiShowWindow(Window: HWND; Show: Integer): BOOL;
var Target: TCall_ShowWindow;
begin
  Target := TCall_ShowWindow(DecodeApiPointer(ApiSlot_ShowWindow));
  Result := Target(Window, Show);
end;

function ApiPeekMessageW(var Msg: TMsg; Window: HWND; First, Last, Remove: UINT): BOOL;
var Target: TCall_PeekMessageW;
begin
  Target := TCall_PeekMessageW(DecodeApiPointer(ApiSlot_PeekMessageW));
  Result := Target(Msg, Window, First, Last, Remove);
end;

function ApiMsgWaitForMultipleObjectsEx(Count: DWORD; Handles: Pointer; Milliseconds, WakeMask, Flags: DWORD): DWORD;
var Target: TCall_MsgWaitForMultipleObjectsEx;
begin
  Target := TCall_MsgWaitForMultipleObjectsEx(DecodeApiPointer(ApiSlot_MsgWaitForMultipleObjectsEx));
  Result := Target(Count, Handles, Milliseconds, WakeMask, Flags);
end;

function ApiTranslateMessage(const Msg: TMsg): BOOL;
var Target: TCall_TranslateMessage;
begin
  Target := TCall_TranslateMessage(DecodeApiPointer(ApiSlot_TranslateMessage));
  Result := Target(Msg);
end;

function ApiDispatchMessageW(const Msg: TMsg): LRESULT;
var Target: TCall_DispatchMessageW;
begin
  Target := TCall_DispatchMessageW(DecodeApiPointer(ApiSlot_DispatchMessageW));
  Result := Target(Msg);
end;

function ApiGetClientRect(Window: HWND; var Rect: TRect): BOOL;
var Target: TCall_GetClientRect;
begin
  Target := TCall_GetClientRect(DecodeApiPointer(ApiSlot_GetClientRect));
  Result := Target(Window, Rect);
end;

function ApiBeginPaint(Window: HWND; var Paint: TPaintStruct): HDC;
var Target: TCall_BeginPaint;
begin
  Target := TCall_BeginPaint(DecodeApiPointer(ApiSlot_BeginPaint));
  Result := Target(Window, Paint);
end;

function ApiEndPaint(Window: HWND; const Paint: TPaintStruct): BOOL;
var Target: TCall_EndPaint;
begin
  Target := TCall_EndPaint(DecodeApiPointer(ApiSlot_EndPaint));
  Result := Target(Window, Paint);
end;

function ApiLoadCursorW(Instance: HINST; Name: PWideChar): HCURSOR;
var Target: TCall_LoadCursorW;
begin
  Target := TCall_LoadCursorW(DecodeApiPointer(ApiSlot_LoadCursorW));
  Result := Target(Instance, Name);
end;

function ApiSetCursor(Cursor: HCURSOR): HCURSOR;
var Target: TCall_SetCursor;
begin
  Target := TCall_SetCursor(DecodeApiPointer(ApiSlot_SetCursor));
  Result := Target(Cursor);
end;

function ApiSetCapture(Window: HWND): HWND;
var Target: TCall_SetCapture;
begin
  Target := TCall_SetCapture(DecodeApiPointer(ApiSlot_SetCapture));
  Result := Target(Window);
end;

function ApiGetCapture: HWND;
var Target: TCall_GetCapture;
begin
  Target := TCall_GetCapture(DecodeApiPointer(ApiSlot_GetCapture));
  Result := Target();
end;

function ApiReleaseCapture: BOOL;
var Target: TCall_ReleaseCapture;
begin
  Target := TCall_ReleaseCapture(DecodeApiPointer(ApiSlot_ReleaseCapture));
  Result := Target();
end;

function ApiGetCursorPos(var Point: TPoint): BOOL;
var Target: TCall_GetCursorPos;
begin
  Target := TCall_GetCursorPos(DecodeApiPointer(ApiSlot_GetCursorPos));
  Result := Target(Point);
end;

function ApiGetWindowRect(Window: HWND; var Rect: TRect): BOOL;
var Target: TCall_GetWindowRect;
begin
  Target := TCall_GetWindowRect(DecodeApiPointer(ApiSlot_GetWindowRect));
  Result := Target(Window, Rect);
end;

function ApiSetWindowPos(Window, After: HWND; X, Y, Width, Height: Integer; Flags: UINT): BOOL;
var Target: TCall_SetWindowPos;
begin
  Target := TCall_SetWindowPos(DecodeApiPointer(ApiSlot_SetWindowPos));
  Result := Target(Window, After, X, Y, Width, Height, Flags);
end;

function ApiGetDpiForWindow(Window: HWND): UINT;
var Target: TCall_GetDpiForWindow;
begin
  Target := TCall_GetDpiForWindow(DecodeApiPointer(ApiSlot_GetDpiForWindow));
  Result := Target(Window);
end;

function ApiMonitorFromWindow(Window: HWND; Flags: DWORD): THandle;
var Target: TCall_MonitorFromWindow;
begin
  Target := TCall_MonitorFromWindow(DecodeApiPointer(ApiSlot_MonitorFromWindow));
  Result := Target(Window, Flags);
end;

function ApiGetMonitorInfoW(Monitor: THandle; Info: Pointer): BOOL;
var Target: TCall_GetMonitorInfoW;
begin
  Target := TCall_GetMonitorInfoW(DecodeApiPointer(ApiSlot_GetMonitorInfoW));
  Result := Target(Monitor, Info);
end;

function ApiGetCurrentThreadId: DWORD;
var Target: TCall_GetCurrentThreadId;
begin
  Target := TCall_GetCurrentThreadId(DecodeApiPointer(ApiSlot_GetCurrentThreadId));
  Result := Target();
end;

function ApiGlobalSize(Memory: HGLOBAL): NativeUInt;
var Target: TCall_GlobalSize;
begin
  Target := TCall_GlobalSize(DecodeApiPointer(ApiSlot_GlobalSize));
  Result := Target(Memory);
end;

function ApiGlobalLock(Memory: HGLOBAL): Pointer;
var Target: TCall_GlobalLock;
begin
  Target := TCall_GlobalLock(DecodeApiPointer(ApiSlot_GlobalLock));
  Result := Target(Memory);
end;

function ApiGlobalUnlock(Memory: HGLOBAL): BOOL;
var Target: TCall_GlobalUnlock;
begin
  Target := TCall_GlobalUnlock(DecodeApiPointer(ApiSlot_GlobalUnlock));
  Result := Target(Memory);
end;

function ApiOpenClipboard(Window: HWND): BOOL;
var Target: TCall_OpenClipboard;
begin
  Target := TCall_OpenClipboard(DecodeApiPointer(ApiSlot_OpenClipboard));
  Result := Target(Window);
end;

function ApiCloseClipboard: BOOL;
var Target: TCall_CloseClipboard;
begin
  Target := TCall_CloseClipboard(DecodeApiPointer(ApiSlot_CloseClipboard));
  Result := Target();
end;

function ApiGetClipboardData(Format: UINT): THandle;
var Target: TCall_GetClipboardData;
begin
  Target := TCall_GetClipboardData(DecodeApiPointer(ApiSlot_GetClipboardData));
  Result := Target(Format);
end;

function ApiIsClipboardFormatAvailable(Format: UINT): BOOL;
var Target: TCall_IsClipboardFormatAvailable;
begin
  Target := TCall_IsClipboardFormatAvailable(DecodeApiPointer(ApiSlot_IsClipboardFormatAvailable));
  Result := Target(Format);
end;

function LicenseWindowProc(Window: HWND; Msg: UINT; WParam: WPARAM;
  LParam: LPARAM): LRESULT; stdcall;
begin
  try
    if (CurrentWindow <> nil) and
      ((CurrentWindow.FWindow = Window) or
       ((CurrentWindow.FWindow = 0) and (Msg = WM_NCCREATE))) then
      Exit(CurrentWindow.Message(Window, Msg, WParam, LParam));
    Result := ApiDefWindowProcW(Window, Msg, WParam, LParam);
  except
    if CurrentWindow <> nil then CurrentWindow.Close;
    Result := 0;
  end;
end;

function IsKeyCharacter(Ch: WideChar): Boolean;
begin
  Result := ((Ch >= 'A') and (Ch <= 'Z')) or
    ((Ch >= 'a') and (Ch <= 'z')) or
    ((Ch >= '0') and (Ch <= '9')) or (Ch = '-');
end;

constructor TLicenseWindow.Create(const SubmitKey: TLicenseSubmitKey;
  const ReadState, ReadProgress: TFunc<Integer>; const OnClose, JoinWorker: TProc);
var Wc: TWndClassExW;
begin
  inherited Create;
  if CurrentWindow <> nil then raise EInvalidOpException.Create(CozyText_License_Window_LICENSE_WINDOW_ALREADY_EXISTS_9aff432e);
  FOwnerThread := ApiGetCurrentThreadId;
  FScale := 1;
  FSubmit := SubmitKey; FState := ReadState; FProgress := ReadProgress; FOnClose := OnClose;
  FJoinWorker := JoinWorker;
  if not Assigned(FSubmit) or not Assigned(FState) or not Assigned(FProgress) then
    raise EArgumentException.Create(CozyText_License_Window_LICENSE_WINDOW_CALLBACK_REQUIRED_5c1e6a18);
  FKey := TCozySensitiveText.Create(MaximumKeyCharacters);
  FInputFocused := False;
  FNormalCursor := ApiLoadCursorW(0, IDC_ARROW);
  FInputCursor := ApiLoadCursorW(0, IDC_IBEAM);
  FBusyCursor := ApiLoadCursorW(0, IDC_WAIT);
  if (FNormalCursor = 0) or (FInputCursor = 0) or (FBusyCursor = 0) then RaiseLastOSError;
  FillChar(Wc, SizeOf(Wc), 0);
  Wc.cbSize := SizeOf(Wc); Wc.lpfnWndProc := @LicenseWindowProc;
  Wc.hInstance := HInstance; Wc.hCursor := FNormalCursor;
  Wc.lpszClassName := LicenseClass;
  if ApiRegisterClassExW(Wc) = 0 then RaiseLastOSError;
  FClassRegistered := True;
  CurrentWindow := Self;
  FWindow := ApiCreateWindowExW(WS_EX_TOOLWINDOW or NoRedirectionBitmap,
    LicenseClass, '', WS_POPUP, CW_USEDEFAULT, CW_USEDEFAULT,
    PanelWidth, PanelHeight, 0, 0, HInstance, nil);
  if FWindow = 0 then RaiseLastOSError;
  FitWindow;
  FContext := ImGuiCreate(FWindow, True);
  SetMitigationGpuIdentity(ImGuiGpuIdentity(FContext));
  if not ImGuiSetDpi(FContext, FScale) then
    raise EInvalidOpException.Create(CozyText_License_Window_LICENSE_DPI_FAILED_5b9a2949);
  Resize;
end;

destructor TLicenseWindow.Destroy;
begin
  Close;
  if FWindow <> 0 then ApiShowWindow(FWindow, SW_HIDE);
  { Module inventories may still observe GPU modules. Finish the cancelled
    API worker before tearing down the GPU or its loaded dependencies. }
  if Assigned(FJoinWorker) then FJoinWorker();
  ImGuiDestroy(FContext);
  if FWindow <> 0 then ApiDestroyWindow(FWindow);
  FWindow := 0;
  if CurrentWindow = Self then CurrentWindow := nil;
  if FClassRegistered then ApiUnregisterClassW(LicenseClass, HInstance);
  FreeAndNil(FKey);
  FSubmit := nil; FState := nil; FProgress := nil; FOnClose := nil; FJoinWorker := nil;
  inherited Destroy;
end;

procedure TLicenseWindow.RequireOwner;
begin
  if ApiGetCurrentThreadId <> FOwnerThread then
    raise EInvalidOpException.Create(CozyText_License_Window_LICENSE_WINDOW_OWNER_INVALID_170d0ce6);
end;

procedure TLicenseWindow.ReleaseOwnCapture;
begin
  if (FWindow = 0) or (ApiGetCapture <> FWindow) then Exit;
  FReleasingCapture := True;
  try ApiReleaseCapture;
  finally FReleasingCapture := False; end;
end;

procedure TLicenseWindow.CancelInput;
begin
  FShift := False; FDragging := False; FVisibleFrame := False;
  FInputFocused := False;
  if FKey <> nil then FKey.Clear;
  ReleaseOwnCapture;
  ImGuiClearInput(FContext);
end;

procedure TLicenseWindow.Close;
begin
  if FClosing then Exit;
  FClosing := True;
  CancelInput;
  if not FCloseNotified then
  begin
    FCloseNotified := True;
    if Assigned(FOnClose) then
      try FOnClose(); except end;
  end;
end;

function TLicenseWindow.BusyVisual: Boolean;
begin
  Result := Assigned(FState) and (FState() = WorkerBusy);
end;

function TLicenseWindow.InputEnabled: Boolean;
begin
  Result := not FClosing and FShown and FFocused and FVisibleFrame and (FElapsed >= 0.45) and
    Assigned(FState) and (FState() = WorkerIdle) and not BusyVisual;
end;

function TLicenseWindow.InputContains(X, Y: Integer): Boolean;
var Area: TRect; Scale, Left, Top: Single;
begin
  Result := False;
  if (FWindow = 0) or not ApiGetClientRect(FWindow, Area) or
    (Area.Right <= 0) or (Area.Bottom <= 0) then Exit;
  { Use the same centered canvas as the native scene, including windows whose
    physical size was clamped to a smaller monitor work area. }
  Scale := Area.Right / PanelWidth;
  if Area.Bottom / PanelHeight < Scale then Scale := Area.Bottom / PanelHeight;
  Left := (Area.Right - PanelWidth * Scale) * 0.5;
  Top := (Area.Bottom - PanelHeight * Scale) * 0.5;
  Result := (X >= Left + InputLeft * Scale) and (X < Left + InputRight * Scale) and
    (Y >= Top + InputTop * Scale) and (Y < Top + InputBottom * Scale);
end;

procedure TLicenseWindow.UpdateCursor;
var Position: TPoint; Bounds: TRect; Cursor: HCURSOR;
begin
  if (FWindow = 0) or not ApiGetCursorPos(Position) or
    not ApiGetWindowRect(FWindow, Bounds) then Exit;
  if (Position.X < Bounds.Left) or (Position.X >= Bounds.Right) or
    (Position.Y < Bounds.Top) or (Position.Y >= Bounds.Bottom) then Exit;
  Cursor := FNormalCursor;
  if BusyVisual then Cursor := FBusyCursor
  else if InputEnabled and not FDragging and
    InputContains(Position.X - Bounds.Left, Position.Y - Bounds.Top) then
    Cursor := FInputCursor;
  ApiSetCursor(Cursor);
end;

procedure TLicenseWindow.FitWindow(const Suggested: PRect);
var Dpi: Cardinal; Info: TLicenseMonitorInfo; Monitor: THandle;
  Width, Height, X, Y: Integer;
begin
  Dpi := ApiGetDpiForWindow(FWindow);
  if (Dpi < 48) or (Dpi > 768) then
    raise EInvalidOpException.Create(CozyText_License_Window_LICENSE_DPI_INVALID_062ff48d);
  FScale := Dpi / 96;
  Width := Round(PanelWidth * FScale); Height := Round(PanelHeight * FScale);
  FillChar(Info, SizeOf(Info), 0); Info.Size := SizeOf(Info);
  Monitor := ApiMonitorFromWindow(FWindow, LicenseMonitorDefaultToNearest);
  if (Monitor = 0) or not ApiGetMonitorInfoW(Monitor, @Info) then RaiseLastOSError;
  if Width > Info.Work.Right - Info.Work.Left then Width := Info.Work.Right - Info.Work.Left;
  if Height > Info.Work.Bottom - Info.Work.Top then Height := Info.Work.Bottom - Info.Work.Top;
  X := Info.Work.Left + ((Info.Work.Right - Info.Work.Left - Width) div 2);
  Y := Info.Work.Top + ((Info.Work.Bottom - Info.Work.Top - Height) div 2);
  if Suggested <> nil then begin X := Suggested.Left; Y := Suggested.Top; end;
  if X < Info.Work.Left then X := Info.Work.Left;
  if Y < Info.Work.Top then Y := Info.Work.Top;
  if X + Width > Info.Work.Right then X := Info.Work.Right - Width;
  if Y + Height > Info.Work.Bottom then Y := Info.Work.Bottom - Height;
  if not ApiSetWindowPos(FWindow, 0, X, Y, Width, Height, SWP_NOACTIVATE or SWP_NOZORDER) then RaiseLastOSError;
  if (FContext <> nil) and not ImGuiSetDpi(FContext, FScale) then
    raise EInvalidOpException.Create(CozyText_License_Window_LICENSE_DPI_FAILED_5b9a2949);
  FResizePending := True;
end;

procedure TLicenseWindow.Resize;
var Area: TRect;
begin
  RequireOwner;
  if (FContext = nil) or (FWindow = 0) then Exit;
  if not ApiGetClientRect(FWindow, Area) then RaiseLastOSError;
  if (Area.Right <= 0) or (Area.Bottom <= 0) then Exit;
  if not ImGuiResize(FContext, Area.Right, Area.Bottom) then
    raise EOverlayImGuiFailure.Create(igfsResize, ImGuiLastError(FContext), CozyText_License_Window_LICENSE_RESIZE_FAILED_5183ff47);
  FResizePending := False;
end;

procedure TLicenseWindow.PasteKey;
var Handle: THandle; Data: PWideChar; Size, Limit: NativeUInt;
  I: Integer; Ch: WideChar; Value: TCozySensitiveText; Terminated: Boolean;
begin
  if not InputEnabled or not FInputFocused then Exit;
  if not ApiIsClipboardFormatAvailable(CF_UNICODETEXT) or not ApiOpenClipboard(FWindow) then Exit;
  Value := nil;
  try
    Handle := ApiGetClipboardData(CF_UNICODETEXT);
    if Handle = 0 then Exit;
    Size := ApiGlobalSize(Handle);
    if (Size < SizeOf(WideChar)) or
      (Size > NativeUInt(MaximumClipboardCharacters + 1) * SizeOf(WideChar)) then Exit;
    Data := ApiGlobalLock(Handle);
    if Data = nil then Exit;
    try
      Value := TCozySensitiveText.Create(MaximumKeyCharacters);
      Limit := Size div SizeOf(WideChar); Terminated := False;
      for I := 0 to Integer(Limit) - 1 do
      begin
        Ch := Data[I];
        if Ch = #0 then begin Terminated := True; Break; end;
        if IsKeyCharacter(Ch) then
        begin
          if Value.Count >= MaximumKeyCharacters then Exit;
          Value.Append(Ch);
        end
        else if not CharInSet(Ch, [#9, #10, #13, ' ']) then Exit;
      end;
      if not Terminated or (Value.Count = 0) or
        (FKey.Count + Value.Count > MaximumKeyCharacters) then Exit;
      FKey.AppendBuffer(Value);
    finally
      ApiGlobalUnlock(Handle);
    end;
  finally
    FillChar(Ch, SizeOf(Ch), 0);
    FreeAndNil(Value);
    ApiCloseClipboard;
  end;
end;

procedure TLicenseWindow.Submit;
var Key: TCozySensitiveText;
begin
  if not InputEnabled or (FKey = nil) or (FKey.Count = 0) then Exit;
  Key := FKey; FKey := nil;
  try
    { Ownership moves UI -> mailbox -> API worker. No plaintext is passed to
      ImGui, ordinary UI strings, logs, clipboard writes or persistent files.
      A refused enqueue is not a close request; terminal worker states remain
      authoritative in Run and Paint. }
    FWasBusy := FSubmit(Key);
    FInputFocused := False;
    FShift := False; FDragging := False;
    ReleaseOwnCapture;
    ImGuiClearInput(FContext);
  finally
    FreeAndNil(Key);
    FKey := TCozySensitiveText.Create(MaximumKeyCharacters);
  end;
  UpdateCursor;
end;

procedure TLicenseWindow.Paint;
var Area: TRect; NowSeconds, Delta: Double;
  State, Phase, Actions, Presented, Percent: Integer;
begin
  RequireOwner;
  if FClosing or FMinimized or not FShown or (FContext = nil) then Exit;
  State := FState();
  if (State = WorkerFailed) or (State = WorkerStopped) or (State = WorkerTransferred) then
  begin Close; Exit; end;
  if BusyVisual then Phase := 1
  else
  begin
    Phase := 0;
    if FWasBusy then
    begin
      FWasBusy := False;
      Phase := 2; { One silent retry frame restores the native input focus. }
      FInputFocused := True;
      ImGuiClearInput(FContext);
    end;
  end;
  if FResizePending then Resize;
  if not ApiGetClientRect(FWindow, Area) then RaiseLastOSError;
  if (Area.Right <= 0) or (Area.Bottom <= 0) then Exit;
  NowSeconds := CozyFrameSeconds;
  Delta := 1/60;
  if FLastFrame > 0 then Delta := NowSeconds - FLastFrame;
  if Delta < 0.000001 then Delta := 0.000001;
  { Progress comes only from completed worker milestones. Animation time is
    independent and never delays rejection or an authenticated transfer. }
  FLastFrame := NowSeconds; FElapsed := FElapsed + Delta;
  if Delta > 0.1 then Delta := 0.1;
  if not ImGuiNewFrame(FContext, Area.Right, Area.Bottom, Delta) then
    raise EInvalidOpException.Create(CozyText_License_Window_LICENSE_FRAME_FAILED_518c078b);
  ImGuiBeginCanvas(FContext);
  Percent := 0;
  if Phase = 1 then Percent := FProgress();
  if Percent < 0 then Percent := 0;
  if Percent > 99 then Percent := 99;
  Actions := ImGuiLicenseScene(FContext, Phase, FKey.Count, Percent / 100);
  ImGuiEndCanvas(FContext);
  Presented := ImGuiPresent(FContext);
  FVisibleFrame := Presented = IMGUI_PRESENT_VISIBLE;
  if (Actions < 0) or (Presented = IMGUI_PRESENT_FAILED) then
    raise EInvalidOpException.Create(CozyText_License_Window_LICENSE_RENDER_FAILED_ad5531e6);
  { Input actions from an occluded/failed frame never consume a license. }
  if Presented <> IMGUI_PRESENT_VISIBLE then Exit;
  if InputEnabled then
  begin
    if (Actions and 4) <> 0 then FInputFocused := True
    else if (Actions and 8) <> 0 then FInputFocused := False;
    if (Actions and 1) <> 0 then Submit;
  end;
  UpdateCursor;
end;

function TLicenseWindow.Message(Window: HWND; Msg: UINT; WParam: WPARAM;
  LParam: LPARAM): LRESULT;
var PaintInfo: TPaintStruct; Position: TPoint; Bounds: TRect; X, Y: Integer;
  Ch: WideChar;
begin
  RequireOwner; Result := 0;
  case Msg of
    WM_NCCREATE: begin FWindow := Window; Exit(ApiDefWindowProcW(Window, Msg, WParam, LParam)); end;
    WM_ERASEBKGND: Exit(1);
    WM_PAINT: begin ApiBeginPaint(Window, PaintInfo); ApiEndPaint(Window, PaintInfo); Exit; end;
    WM_CLOSE: begin Close; Exit; end;
    WM_QUERYENDSESSION: begin Close; Exit(1); end;
    WM_ENDSESSION: begin if WParam <> 0 then Close; Exit; end;
    WM_DESTROY: begin FWindow := 0; Close; Exit; end;
    WM_SIZE: begin FMinimized := WParam = SIZE_MINIMIZED; FResizePending := True; if FMinimized then CancelInput; Exit; end;
    WM_SETFOCUS: begin FFocused := True; ImGuiFocus(FContext, True); Exit; end;
    WM_KILLFOCUS: begin FFocused := False; CancelInput; ImGuiFocus(FContext, False); Exit; end;
    WM_CANCELMODE, WM_CAPTURECHANGED:
      begin
        FDragging := False;
        if not FReleasingCapture then
        begin FInputFocused := False; ImGuiClearInput(FContext); end;
        Exit;
      end;
    DpiChangedMessage: begin CancelInput; FitWindow(PRect(LParam)); Exit; end;
    WM_DISPLAYCHANGE: begin CancelInput; FitWindow; Exit; end;
    WM_SETCURSOR:
      if LoWord(LParam) = HTCLIENT then
      begin
        UpdateCursor;
        Exit(1);
      end;
    WM_MOUSEMOVE:
      begin
        X := SmallInt(LoWord(LParam)); Y := SmallInt(HiWord(LParam));
        if FDragging then
        begin
          if ApiGetCursorPos(Position) then
            ApiSetWindowPos(Window, 0, FDragOrigin.X + Position.X - FDragAnchor.X,
              FDragOrigin.Y + Position.Y - FDragAnchor.Y, 0, 0,
              SWP_NOACTIVATE or SWP_NOZORDER or SWP_NOSIZE);
        end
        else ImGuiMousePos(FContext, X, Y);
        UpdateCursor;
        Exit;
      end;
    WM_LBUTTONDOWN:
      begin
        if not InputEnabled then Exit;
        X := SmallInt(LoWord(LParam)); Y := SmallInt(HiWord(LParam));
        if (Y >= 0) and (Y < Round(28 * FScale)) and (X >= 0) and
          (X < Round(PanelWidth * FScale)) and
          ApiGetCursorPos(FDragAnchor) and ApiGetWindowRect(Window, Bounds) then
        begin
          FDragOrigin := Bounds.TopLeft; FDragging := True; ApiSetCapture(Window);
        end
        else
        begin
          FInputFocused := InputContains(X, Y);
          ImGuiMousePos(FContext, X, Y); ImGuiMouseButton(FContext, 0, True);
          ApiSetCapture(Window);
        end;
        Exit;
      end;
    WM_LBUTTONUP:
      begin
        ImGuiMouseButton(FContext, 0, False); FDragging := False;
        ReleaseOwnCapture;
        Exit;
      end;
    WM_KEYDOWN, WM_SYSKEYDOWN:
      begin
        if (Msg = WM_SYSKEYDOWN) and (WParam = VK_F4) then begin Close; Exit; end;
        if InputEnabled then
        begin
          if WParam = VK_SHIFT then FShift := True;
          if (WParam = VK_INSERT) and FShift and FInputFocused then PasteKey;
          if WParam = VK_RETURN then begin if (LParam and $40000000) = 0 then Submit; Exit; end;
          if WParam = VK_BACK then begin if FInputFocused then FKey.Backspace; Exit; end;
          ImGuiKey(FContext, WParam, True);
        end;
        Exit;
      end;
    WM_KEYUP, WM_SYSKEYUP:
      begin if WParam = VK_SHIFT then FShift := False; ImGuiKey(FContext, WParam, False); Exit; end;
    WM_CHAR:
      begin
        if not InputEnabled or not FInputFocused then Exit;
        Ch := WideChar(WParam and $FFFF);
        try
          if Ch = #22 then PasteKey
          else if IsKeyCharacter(Ch) and (FKey.Count < MaximumKeyCharacters) then
          FKey.Append(Ch);
        finally FillChar(Ch, SizeOf(Ch), 0); end;
        Exit;
      end;
  end;
  Result := ApiDefWindowProcW(Window, Msg, WParam, LParam);
end;

function TLicenseWindow.Run(const BeforeShow: TProc): Integer;
var Msg: TMsg; Count, State: Integer;
begin
  RequireOwner; Result := 1;
  if not Assigned(BeforeShow) then raise EArgumentException.Create(CozyText_License_Window_LICENSE_AUTHORIZATION_REQUIRED_dc82299f);
  BeforeShow();
  if FClosing then Exit;
  FShown := True; ApiShowWindow(FWindow, SW_SHOW);
  while not FClosing do
  begin
    Count := 0;
    while (Count < 128) and ApiPeekMessageW(Msg, 0, 0, 0, PM_REMOVE) do
    begin
      if Msg.message = WM_QUIT then begin Close; Break; end;
      ApiTranslateMessage(Msg); ApiDispatchMessageW(Msg); Inc(Count);
    end;
    State := FState();
    if State = WorkerTransferred then begin Result := 0; Close; Break; end;
    if (State = WorkerFailed) or (State = WorkerStopped) then begin Close; Break; end;
    Paint;
    if FMinimized or FClosing then
      ApiMsgWaitForMultipleObjectsEx(0, nil, 50, QS_ALLINPUT, WaitInputAvailable);
  end;
  { The worker can commit between the loop state read and Paint. Its sticky
    terminal mailbox remains authoritative after Close requested cancellation. }
  if FState() = WorkerTransferred then Result := 0;
end;

function RunLicenseWindow(const BeforeShow: TProc; const SubmitKey: TLicenseSubmitKey;
  const ReadState, ReadProgress: TFunc<Integer>; const OnClose, JoinWorker: TProc): Integer;
var Window: TLicenseWindow;
begin
  Window := TLicenseWindow.Create(SubmitKey, ReadState, ReadProgress, OnClose, JoinWorker);
  try Result := Window.Run(BeforeShow);
  finally Window.Free; end;
end;

initialization
  BindApiPointer(ApiSlot_RegisterClassExW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_RegisterClassExW));
  BindApiPointer(ApiSlot_UnregisterClassW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_UnregisterClassW));
  BindApiPointer(ApiSlot_CreateWindowExW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_CreateWindowExW));
  BindApiPointer(ApiSlot_DefWindowProcW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_DefWindowProcW));
  BindApiPointer(ApiSlot_DestroyWindow, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_DestroyWindow));
  BindApiPointer(ApiSlot_ShowWindow, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_ShowWindow));
  BindApiPointer(ApiSlot_PeekMessageW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_PeekMessageW));
  BindApiPointer(ApiSlot_MsgWaitForMultipleObjectsEx, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_MsgWaitForMultipleObjectsEx));
  BindApiPointer(ApiSlot_TranslateMessage, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_TranslateMessage));
  BindApiPointer(ApiSlot_DispatchMessageW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_DispatchMessageW));
  BindApiPointer(ApiSlot_GetClientRect, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_GetClientRect));
  BindApiPointer(ApiSlot_BeginPaint, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_BeginPaint));
  BindApiPointer(ApiSlot_EndPaint, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_EndPaint));
  BindApiPointer(ApiSlot_LoadCursorW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_LoadCursorW));
  BindApiPointer(ApiSlot_SetCursor, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_SetCursor));
  BindApiPointer(ApiSlot_SetCapture, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_SetCapture));
  BindApiPointer(ApiSlot_GetCapture, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_GetCapture));
  BindApiPointer(ApiSlot_ReleaseCapture, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_ReleaseCapture));
  BindApiPointer(ApiSlot_GetCursorPos, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_GetCursorPos));
  BindApiPointer(ApiSlot_GetWindowRect, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_GetWindowRect));
  BindApiPointer(ApiSlot_SetWindowPos, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_SetWindowPos));
  BindApiPointer(ApiSlot_GetDpiForWindow, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_GetDpiForWindow));
  BindApiPointer(ApiSlot_MonitorFromWindow, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_MonitorFromWindow));
  BindApiPointer(ApiSlot_GetMonitorInfoW, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_GetMonitorInfoW));
  BindApiPointer(ApiSlot_GetCurrentThreadId, RequireProcAddressHash64(CozyText_License_Window_kernel32_dll_4850f5dd, HASH_GetCurrentThreadId));
  BindApiPointer(ApiSlot_GlobalSize, RequireProcAddressHash64(CozyText_License_Window_kernel32_dll_4850f5dd, HASH_GlobalSize));
  BindApiPointer(ApiSlot_GlobalLock, RequireProcAddressHash64(CozyText_License_Window_kernel32_dll_4850f5dd, HASH_GlobalLock));
  BindApiPointer(ApiSlot_GlobalUnlock, RequireProcAddressHash64(CozyText_License_Window_kernel32_dll_4850f5dd, HASH_GlobalUnlock));
  BindApiPointer(ApiSlot_OpenClipboard, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_OpenClipboard));
  BindApiPointer(ApiSlot_CloseClipboard, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_CloseClipboard));
  BindApiPointer(ApiSlot_GetClipboardData, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_GetClipboardData));
  BindApiPointer(ApiSlot_IsClipboardFormatAvailable, RequireProcAddressHash64(CozyText_License_Window_user32_dll_4e29255d, HASH_IsClipboardFormatAvailable));
end.
