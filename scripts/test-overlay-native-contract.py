"""Source regression gates only; not a Delphi compile, ABI execution or Windows UI test."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2] / 'GameConnect_Win64'
read = lambda name: (root / name).read_text(encoding='utf-8-sig')
console = read('Game.Console.pas')
completion = read('Game.LicenseCompletion.pas')
data = read('Game.Overlay.Data.pas')
host = read('Game.Overlay.Host.pas')
plugin = read('Game.Overlay.Plugin.pas')
abi = read('Game.Overlay.Abi.pas')
storage = read('Game.Overlay.Storage.pas')
count = 0


def body(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


def check(name, condition):
    global count
    assert condition, name
    count += 1
    print('PASS', name)


initialize = body(host, 'procedure TPluginHost.Initialize;', 'procedure TPluginHost.Invalidate;')
download = body(host, 'procedure TPluginHost.Download;', 'procedure TPluginHost.VerifyMeasurements(')
report = body(host, 'procedure TPluginHost.SendNextBatch;', 'procedure TPluginHost.Poll;')
poll = body(host, 'procedure TPluginHost.Poll;', 'procedure TPluginHost.Initialize;')
worker = body(host, 'procedure TPluginHost.Execute;', 'procedure TPluginHost.CloseCapability;')
frame = body(host, 'function TPluginHost.ReadFrame(', 'function ReadHostFrame(')
destroy = body(host, 'destructor TPluginHost.Destroy;', 'function RunOverlayPlugin(')
manifest = body(host, 'procedure TPluginHost.ReadManifest(', 'procedure TPluginHost.Download;')
snapshot = body(host, 'procedure TPluginHost.PrepareSnapshot(', 'procedure TPluginHost.SendNextBatch;')

check('A retains its original role; only B references the plugin host',
      all('Game.Overlay.' not in read(name) for name in ('GameLauncher.dpr', 'GameLauncher.dproj'))
      and all('Game.Overlay.Host' in read(name) and 'Game.Overlay.Runtime' not in read(name)
              and 'Game.Overlay.Plugin' not in read(name)
              for name in ('GameConnect.dpr', 'GameConnect.dproj')))
check('Completion retries one request identity with bounded transport budgets',
      completion.count("Body.AddPair('requestId'") == 1
      and completion.index("Body.AddPair('requestId'") < completion.index('for Attempt := 1 to 2')
      and "PostJSON('bootstrap', Body, 8000)" in completion)
check('The renderer artifact is downloaded and verified before the standard Windows loader',
      initialize.index('ReadManifest(True)') < initialize.index('Download;')
      < initialize.index('LoadLibraryExW(')
      and download.index('FFile.Seal(') < download.index('IntegrityHashHandle(FFile.Handle)')
      < download.index('SameFile(Digest, FManifest.FileDigest)')
      and 'RestrictedSystem32Search = $00000800;' in host
      and 'LoadLibraryExW(PWideChar(FFile.Path), 0, RestrictedSystem32Search)' in initialize)
check('The host reuses retained B integrity and existing module/code implementations',
      'FOwnImage.VerifyNow' in host and 'FOwnCode.MeasureNow' in host
      and 'TCodeIntegrity.Create(FFile.Handle, FModule)' in initialize
      and 'FPluginCode.MeasureExportTableNow' in host
      and 'CollectModuleInventoryJSON(' in host
      and not any(token in destroy for token in ('FOwnImage.Free', 'FOwnCode.Free')))
check('No renderer entry is reached until loaded-module reporting and a server poll succeed',
      initialize.index('LoadLibraryExW(') < initialize.index('PrepareSnapshot(')
      < initialize.index('SendNextBatch;') < initialize.index('Poll;')
      and host.rindex('Host.Initialize;') < host.rindex('Result := Host.Run;')
      and "RequireHost(Status = 'READY'" in report
      and "RequireHost(FAuthorized, 'OVERLAY_PLUGIN_NOT_READY')" in poll)
check('Manifest treats the server release version as text and pins the exact ABI and release',
      "TextField(Data, 'version', 40)" in manifest
      and "IntField(Data, 'version')" not in manifest
      and 'PluginNameValid(Next.FileName)' in manifest
      and "SameText(ExtractFileExt(Value), '.bin')" in host
      and "['A'..'Z', 'a'..'z', '0'..'9', '_', '-']" in host
      and "ChangeFileExt(BootstrapRandomFileName('.exe'), '.bin')" in download
      and 'Next.FileName = FManifest.FileName' in manifest
      and 'TextField(Data, \'exportName\') = OVERLAY_PLUGIN_ENTRY' in manifest
      and 'Next.ID = FManifest.ID' in manifest
      and 'SameCode(Next.HostCode, FManifest.HostCode)' in manifest)
check('Only the final inventory batch carries complete=true and each batch has fresh own proof',
      "Payload.AddPair('complete', TJSONBool.Create(FBatchIndex = FBatchCount - 1))" in report
      and report.index('VerifyMeasurements(Own)') < report.index("Body := NewBody('plugin-report')")
      and 'TEncoding.UTF8.GetByteCount(Text) <= 8192' in report
      and 'ModuleBatchSize = 4;' in host)
check('Random local module lookup uses the loaded file, preserving all approved content checks',
      "ChangeFileExt(BootstrapRandomFileName('.exe'), '.bin')" in download
      and 'LoadedFileName := ExtractFileName(FFile.Path);' in snapshot
      and "SameText(TextField(Row, 'name', 180), LoadedFileName)" in snapshot
      and 'FManifest.FileName' not in snapshot
      and all(f"HexField(Row, '{field}'" in snapshot for field in
              ('fileSha256', 'fileCrc64', 'fileXxh64', 'fileBlake3'))
      and "SameCode(ReadCodeDigest(Row, 'code'), FManifest.Code)" in snapshot
      and "SameCode(ReadCodeDigest(Row, 'exportTable'), FManifest.ExportDigest)" in snapshot
      and "RequireHost(Found = 1, 'OVERLAY_PLUGIN_MODULE_MISSING')" in snapshot
      and "ReplaceText(Row, 'name'" not in snapshot)
check('Slow module scans run separately from the lease-polling worker',
      'TInventoryCollector = class(TThread)' in host
      and 'FCollector.BeginCollection;' in worker
      and 'CollectModuleInventoryJSON(' not in worker
      and worker.index('if Tick >= FNextPoll then Poll;') < worker.index('FCollector.FinishedCollection'))
check('Visible expiry is latched and a late network reply cannot revive it',
      'InterlockedCompareExchange(FInvalidated, 0, 0)' in poll
      and poll.index('FGrant.LeaseDeadlineTick') < poll.index('FGrant := Next')
      and 'InterlockedExchange(FInvalidated, 1)' in frame
      and 'GetTickCount64 >= FGrant.LeaseDeadlineTick' in frame)
check('UI callback uses bounded frame copies without network or hash work',
      'Frame.Title[I - 1]' in frame and 'Frame.Lines[I][J - 1]' in frame
      and not any(token in frame for token in ('PostJSON(', 'IntegrityHash', 'CollectModuleInventory', 'VerifyMeasurements(')))
check('Host joins its workers before unloading the DLL and deleting its temporary file',
      destroy.index('StopAndJoin;') < destroy.index('FPluginCode.Free;')
      < destroy.index('FreeLibrary(FModule)') < destroy.index('FFile.Free;')
      and body(host, 'procedure TPluginHost.StopAndJoin;', 'function TPluginHost.ReadFrame(')
      .index('if FStarted then WaitFor;') <
      body(host, 'procedure TPluginHost.StopAndJoin;', 'function TPluginHost.ReadFrame(')
      .index('FreeAndNil(FCollector)'))
check('The plugin exposes only fixed-size POD records and a versioned C-compatible entry',
      'OVERLAY_FRAME_V1_SIZE = 4192;' in abi
      and 'OVERLAY_HOST_CONTEXT_V1_SIZE = 32;' in abi
      and "OVERLAY_PLUGIN_ENTRY = 'GameOverlayRunV1';" in abi
      and 'TOverlayFrameV1 = packed record' in abi
      and 'TOverlayHostContextV1 = packed record' in abi
      and 'SizeOf(TOverlayReadFrameV1) = 8' in abi
      and 'GameOverlayRunV1 name \'GameOverlayRunV1\'' in read('GameOverlayPlugin.dpr'))
check('The DLL renderer does not import host transport, PEB resolver or integrity initialization',
      not any(token in plugin + read('GameOverlayPlugin.dpr') for token in (
          'GameConnectTransport', 'Game.PEB', 'Game.CodeIntegrity', 'Game.Security'))
      and 'LeaseTimerMilliseconds = 100;' in plugin
      and 'if not ReadFrame(Frame) then' in plugin
      and 'Winapi.Windows.LPARAM(GetMessagePos())' in plugin)
check('No managed objects or exceptions escape the exported renderer lifetime',
      plugin.rindex('Result := Window.Run;') < plugin.rindex('Window.Free;')
      < plugin.rindex('except')
      and 'function ReadHostFrame(UserData: Pointer; Frame: POverlayFrameV1): LongBool; stdcall;' in host)
check('The plugin has no alternate process, injection, or network path',
      not re.search(r'\b(?:VirtualAlloc\w*|WriteProcessMemory|CreateRemoteThread\w*|'
                    r'CreateProcess\w*|ShellExecute\w*|PostJSON|LoadLibrary\w*)\s*\(', plugin, re.I)
      and not re.search(r'\b(?:WriteProcessMemory|CreateRemoteThread\w*|VirtualAllocEx)\s*\(', host, re.I))
check('The temporary file is bounded, private, pinned and never accepted by pathname alone',
      '16 * 1024 * 1024' in storage and 'D:P(A;OICI;FA;;;SY)' in storage
      and 'FILE_FLAG_OPEN_REPARSE_POINT' in storage
      and 'nNumberOfLinks = 1' in storage
      and 'nFileIndexHigh' in storage and 'nFileIndexLow' in storage)
check('Display data still rejects duplicate fields and validates its exact SHA-256 before parsing',
      'Obj.Count <> Length(Names)' in data and 'Matches <> 1' in data
      and "CheckFields(Document, ['schema', 'format', 'title', 'lines', 'theme'])" in data
      and data.index('IntegritySHA256Text(DocumentText) <> Result.Document.SHA256')
      < data.index('TJSONObject.ParseJSONValue(DocumentText)'))
check('Display time includes network latency and cannot exceed a 30-second lease',
      'Duration > 30000' in data and 'Elapsed := NowTick - RequestStarted' in data
      and 'Elapsed >= UInt64(Duration)' in data
      and 'NowTick + UInt64(Duration) - Elapsed' in data)
print(f'Overlay native source contracts: {count} passed. Static checks only; '
      'Delphi compilation, Windows ABI/loading and real rendering NOT executed here.')
