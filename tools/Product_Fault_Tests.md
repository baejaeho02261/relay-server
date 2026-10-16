# Isolated Windows product fault execution

`Run_Product_Fault_Tests.bat` executes existing A/B/O binaries. It does not compile,
create CI evidence, approve publication, or claim physical GPU failure coverage.
Run on an interactive Windows x64 desktop with Node, PowerShell 7 x64, OpenSSL,
and the repository's installed Node dependencies.

Build ordinary final Release A/B/O separately from the dedicated projects under
`GameConnect_Win64/tests/product-faults/`. The dedicated projects retain optimized
Release configuration but export a product-fault marker. Ordinary publication
always rejects that marker. The runner admits it only inside its new private
fixture process. The production authentication, signatures, pin, server reports,
and handoff cryptography still execute.

Create an input JSON with absolute paths. Example paths below are placeholders:

```json
{
  "version": 1,
  "releaseVersion": "1.0.0",
  "artifacts": {
    "A": "C:\\build\\final\\A.exe",
    "B": "C:\\build\\final\\B.exe",
    "O": "C:\\build\\final\\O.exe"
  },
  "faultArtifacts": {
    "A": "C:\\build\\fault\\A.exe",
    "B": "C:\\build\\fault\\B.exe",
    "O": "C:\\build\\fault\\O.exe"
  },
  "nativeReceiveProbe": "C:\\build\\probes\\TlsReceiveProbe.exe"
}
```

Run `Run_Product_Fault_Tests.bat C:\\path\\product-fault-inputs.json`.
Use `/nopause` as the second argument for an unattended invocation in an already
interactive desktop session. An optional `scenarios` array selects exact IDs;
omitting it selects every product case. Missing artifact sets are `NOT_RUN`.

| IDs | Executed bytes | Required observation |
| --- | --- | --- |
| `handoff-body-interrupt-ab`, `handoff-body-interrupt-bo` | Dedicated A/B/O | A real partial encrypted body, writer interruption, failed transfer, terminal authority and reuse denial |
| `handoff-parent-exit-ab`, `handoff-parent-exit-bo` | Dedicated A/B/O | Partial body followed by actual owning parent exit |
| `handoff-child-exit-ab`, `handoff-child-exit-bo` | Dedicated A/B/O | Partial body barrier and termination of the exact child handle in the fixture's Job object |
| `response-loss-redeem`, `response-loss-claim-b`, `response-loss-claim-o`, `response-loss-transfer` | Selected final Release | Durable service success, loss of exactly that socket's response, actual client retry of the same request/result, no duplicate consumption or delegation |
| `tls-session-record-authentication-failure` | Selected final Release | A real O transfer, then exactly one mutated TLS 1.2 application record on renewal, fail-closed application exit and terminal server authority |
| `signed-exe-replacement`, `signed-json-replacement` | Selected final Release | Fixture-local signed B bytes or approval JSON changed after staging; actual A request rejected before a flow, license consumption or O exists |
| `gpu-create-e-outofmemory`, `gpu-resize-device-removed`, `gpu-present-device-reset` | Dedicated A/B/O | Actual renderer call returns the requested injected HRESULT; ordinary shutdown retires authority |
| `overlay-lease-expiry` | Dedicated A/B/O | Real post-transfer 120-second server grant; stop renewal only, exact PID/HWND hide event at the native deadline before automatic exit, unchanged real-time server expiry, retired session secrets and captured old authority rejected |

The lease case withholds the exact owned O cleanup request so the conservative
client deadline cannot close the server row one round-trip before expiry. It
does not change clocks, shorten a grant, command the window closed, or kill O.
The WinEvent observer uses the OS event generation tick and rejects a window
that reappears. `Run_Manual_Windows_Tests.bat` optionally accepts `faultArtifacts`
and an admin-exported `verificationContext` path, preserving the legacy V2
report and exporting a separate V3 domain-9 observation with distinct test-build
hashes. A dedicated-test PASS is not a final Release execution claim.

Each scenario uses a new localhost server, private data directory, ephemeral
release signing key, personalized A, assigned one-use license and process Job
objects. Only fixture-owned paths and held process handles are touched. The
runner waits for normal server retirement, including original lease expiry after
an abrupt parent exit; it never changes the clock or shortens production leases.
A case can therefore take several minutes. Case timeout is 450 seconds.

Successful response-loss cases require a real visible O before closure. Creation
failure intentionally precedes a visible O. Other faults require their exact
native observation; requesting a fault is insufficient. Replay checks reuse
captured authentic requests after terminal authority and require rejection with
no new durable side effect. These are testserver-local service checks after the
native run, not a fabricated native client report.

The result JSON records each selected final/test-build SHA-512, input stability,
case observations, server retirement, reuse-denied checks and cleanup. It stays
`INCOMPLETE` if required inputs or a native boundary probe are missing, and `FAIL`
if a fault was never observed or cleanup/reuse assertions fail. Application and
server logs, bodies, tickets, license input, keys and test stores remain private
and are removed. The report contains no such credentials.

`native-receive-fault-tests.js` is a separate actual SChannel/receive-boundary
probe. Its bounded framing/JSON/TLS cases are not represented as A/B/O session
execution. Signed replacement cases above cover server distribution boundaries;
native process-launch TOCTOU and real driver/device removal remain separate.

On Linux the Windows cases are **NOT_RUN**. Run portable harness regression with:

```text
node GameWeb/scripts/test-product-fault-tests.js
```

## Lifecycle and genuine expiry bundle

Run `Run_Lifecycle_Windows_Tests.bat` to select existing final Release A/B/O and
the dedicated product-fault A/B/O built in the RAD Studio IDE. Input/result JSON
files are created beside the BAT. No CI evidence or production reset is needed.

- `lifecycle-cleanup-success` executes the selected final files, then binds each
  signed A/B parent-exit and removal report to held process observations.
- `lifecycle-cleanup-refused` pauses only the dedicated O after B has exited.
  An exact-hash, single-link, owned B file handle denies DELETE sharing; the
  actual production cleanup must report the Windows failure and B residual.
- `lifecycle-cleanup-scheduled` holds that same B with DELETE sharing. The actual
  non-POSIX disposition must be pending while the observer handle is open, and
  path absence is checked only after it closes. SCHEDULED is not REMOVED.
- `overlay-lease-expiry` additionally requires the real signed O lifecycle report
  after server expiry, using a test-only pause of at most 1.5 seconds within the
  existing shutdown budget. The unchanged server verifies the old diagnostic
  permit, while old runtime authority remains rejected.

Each case cross-checks the server-state and license-workspace timeline projections.
Client observations remain labeled CLIENT_REPORTED. These tests do not claim that
the server directly observed Windows process or filesystem state. Missing events,
missing reports, unavailable OS paths or unexecuted cases cannot become PASS.
Actual Delphi compilation and Windows execution are still required on the operator PC.

An optional admin-exported `verificationContext` binds the local results to the
registered final A/B/O and source manifest. The runner then emits a separate
`-verification.json` V3 report for domain 9 with distinct final/dedicated artifact
hashes. Only these named lifecycle checks are reported; no other test becomes PASS.
