param([string]$ImagePath)
$ErrorActionPreference = 'Stop'

# Run in Windows PowerShell 5.1. The production C# implementation is loaded
# directly from the normalizer; no alternate sorting implementation is tested.
# An optional real EXE is read into memory only and is never overwritten.
$testDirectory = $null

function Get-TestSha512([byte[]]$Bytes) {
  $hash = [Security.Cryptography.SHA512]::Create()
  try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
  finally { $hash.Dispose() }
}

function Invoke-NormalizerProcess([string]$Engine, [string]$ScriptPath, [string]$FixturePath) {
  # Start a fresh copy of this PowerShell engine so the real script executes,
  # including Add-Type, FileStream, atomic replacement, readback, and exit code.
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $Engine
  $start.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $ScriptPath + '" -ImagePath "' + $FixturePath + '"'
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $start
  try {
    if (-not $process.Start()) { throw 'Could not start the production normalizer process.' }
    $outputTask = $process.StandardOutput.ReadToEndAsync()
    $errorTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) {
      $process.Kill()
      $process.WaitForExit()
      throw 'Production normalizer process timed out.'
    }
    return [pscustomobject]@{
      ExitCode = $process.ExitCode
      Output = $outputTask.Result
      Error = $errorTask.Result
    }
  } finally { $process.Dispose() }
}


try {
  $normalizerPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'Cozy.Build\Cozy.Normalize-PE-Unwind.ps1'
  $normalizerText = [IO.File]::ReadAllText($normalizerPath)
  $match = [regex]::Match($normalizerText, '(?ms)^\$source[ \t]*=[ \t]*@''\r?\n(?<Core>.*?)^''@[ \t]*\r?$')
  if (!$match.Success) { throw 'Production normalizer C# source block was not found.' }
  if ('GameImGui.PeUnwindNormalizer' -as [type]) {
    throw 'Run this test in a fresh Windows PowerShell process to load the current implementation.'
  }
  $testSource = @'
namespace GameImGui.Tests
{
    public static class PeUnwindRegression
    {
        private const int Pe = 0x80;
        private const int Optional = Pe + 24;
        private const int Sections = Optional + 240;
        private const int Pdata = 0x600;
        private const int PdataLength = 36;
        private const ulong ImageBase = 0x140000000UL;
        private static int checks;

        private static void Check(bool value, string message)
        {
            if (!value) throw new System.Exception("FAIL: " + message);
            checks++;
        }

        private static void U16(byte[] bytes, int offset, ushort value)
        {
            System.Buffer.BlockCopy(System.BitConverter.GetBytes(value), 0, bytes, offset, 2);
        }

        private static void U32(byte[] bytes, int offset, uint value)
        {
            System.Buffer.BlockCopy(System.BitConverter.GetBytes(value), 0, bytes, offset, 4);
        }

        private static void U64(byte[] bytes, int offset, ulong value)
        {
            System.Buffer.BlockCopy(System.BitConverter.GetBytes(value), 0, bytes, offset, 8);
        }

        private static uint Read32(byte[] bytes, int offset)
        {
            return System.BitConverter.ToUInt32(bytes, offset);
        }

        private static bool Equal(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return false;
            for (int i = 0; i < left.Length; i++)
                if (left[i] != right[i]) return false;
            return true;
        }

        private static void Section(byte[] bytes, int index, string name,
            uint virtualSize, uint rva, uint rawOffset, uint flags)
        {
            int offset = Sections + index * 40;
            byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
            System.Buffer.BlockCopy(nameBytes, 0, bytes, offset, nameBytes.Length);
            U32(bytes, offset + 8, virtualSize);
            U32(bytes, offset + 12, rva);
            U32(bytes, offset + 16, 0x200);
            U32(bytes, offset + 20, rawOffset);
            U32(bytes, offset + 36, flags);
        }

        private static byte[] Fixture(bool sorted)
        {
            byte[] bytes = new byte[0xc00];
            U16(bytes, 0, 0x5a4d);
            U32(bytes, 0x3c, Pe);
            U32(bytes, Pe, 0x4550);
            U16(bytes, Pe + 4, 0x8664);
            U16(bytes, Pe + 6, 4);
            U16(bytes, Pe + 20, 240);
            U16(bytes, Pe + 22, 0x22);
            U16(bytes, Optional, 0x20b);
            bytes[Optional + 2] = 14;
            U32(bytes, Optional + 4, 0x200);
            U32(bytes, Optional + 8, 0x600);
            U32(bytes, Optional + 16, 0x1000);
            U32(bytes, Optional + 20, 0x1000);
            U64(bytes, Optional + 24, ImageBase);
            U32(bytes, Optional + 32, 0x1000);
            U32(bytes, Optional + 36, 0x200);
            U16(bytes, Optional + 40, 6);
            U16(bytes, Optional + 48, 6);
            U32(bytes, Optional + 56, 0x5000);
            U32(bytes, Optional + 60, 0x400);
            U16(bytes, Optional + 68, 2);
            U16(bytes, Optional + 70, 0x8160);
            U64(bytes, Optional + 72, 0x100000);
            U64(bytes, Optional + 80, 0x1000);
            U64(bytes, Optional + 88, 0x100000);
            U64(bytes, Optional + 96, 0x1000);
            U32(bytes, Optional + 108, 16);
            U32(bytes, Optional + 112 + 3 * 8, 0x2000);
            U32(bytes, Optional + 116 + 3 * 8, PdataLength);
            Section(bytes, 0, ".text", 0x200, 0x1000, 0x400, 0x60000020);
            Section(bytes, 1, ".pdata", PdataLength, 0x2000, Pdata, 0x40000040);
            Section(bytes, 2, ".xdata", 0x20, 0x3000, 0x800, 0x40000040);
            Section(bytes, 3, ".reloc", 0x20, 0x4000, 0xa00, 0x42000040);
            for (int i = 0x400; i < 0x600; i++) bytes[i] = 0x90;
            int[] order = sorted ? new int[] { 0, 1, 2 } : new int[] { 2, 0, 1 };
            for (int i = 0; i < order.Length; i++)
            {
                uint n = (uint)order[i];
                U32(bytes, Pdata + i * 12, 0x1000 + n * 0x40);
                U32(bytes, Pdata + i * 12 + 4, 0x1020 + n * 0x40);
                U32(bytes, Pdata + i * 12 + 8, 0x3000 + n * 4);
                bytes[0x800 + i * 4] = 1;
                bytes[0x41f + i * 0x40] = 0xc3;
            }
            // Sentinel data verifies that padding, unrelated sections, and the
            // image length are preserved instead of rebuilding the PE image.
            bytes[0x3f0] = 0x7b;
            bytes[0x700] = 0x6d;
            bytes[0x81f] = 0x4e;
            bytes[0xbff] = 0x5a;
            return bytes;
        }

        public static byte[] FileFixture(string kind)
        {
            byte[] bytes = Fixture(false);
            if (kind == "signed")
            {
                U32(bytes, Optional + 112 + 4 * 8, 0xb80);
                U32(bytes, Optional + 116 + 4 * 8, 16);
                U32(bytes, 0xb80, 16);
                U16(bytes, 0xb84, 0x200);
                U16(bytes, 0xb86, 2);
            }
            else if (kind == "overlap") U32(bytes, Pdata + 24, 0x1010);
            else if (kind != "unsorted") throw new System.ArgumentException("Unknown fixture kind.");
            return bytes;
        }

        private static string[] Records(byte[] bytes, int table, int size)
        {
            string[] result = new string[size / 12];
            for (int i = 0; i < result.Length; i++)
                result[i] = System.BitConverter.ToString(bytes, table + i * 12, 12);
            System.Array.Sort(result, System.StringComparer.Ordinal);
            return result;
        }

        private static void VerifyReorderOnly(byte[] before, byte[] after, int table, int size)
        {
            Check(before.Length == after.Length, "image length is preserved");
            int checksum = checked((int)Read32(before, 0x3c)) + 24 + 64;
            bool checksumPresent = Read32(before, checksum) != 0;
            for (int i = 0; i < before.Length; i++)
                if ((i < table || i >= table + size) &&
                    (!checksumPresent || i < checksum || i >= checksum + 4) &&
                    before[i] != after[i])
                    throw new System.Exception("FAIL: unrelated byte changed at " + i.ToString("X"));
            checks++;
            string[] oldRecords = Records(before, table, size);
            string[] newRecords = Records(after, table, size);
            for (int i = 0; i < oldRecords.Length; i++)
                Check(oldRecords[i] == newRecords[i], "complete 12-byte runtime-function records preserved");
            for (int i = 12; i < size; i += 12)
                Check(Read32(after, table + i - 12) < Read32(after, table + i),
                    "runtime-function records are strictly ordered by BeginAddress");
        }

        private static void Reject(string name, System.Action<byte[]> corrupt)
        {
            Reject(name, corrupt, false);
        }

        private static void Reject(string name, System.Action<byte[]> corrupt, bool sorted)
        {
            byte[] bytes = Fixture(sorted);
            corrupt(bytes);
            byte[] original = (byte[])bytes.Clone();
            bool rejected = false;
            try { GameImGui.PeUnwindNormalizer.Normalize(bytes); }
            catch (System.InvalidOperationException error)
            {
                if (!error.Message.StartsWith("PE_UNWIND_", System.StringComparison.Ordinal)) throw;
                rejected = true;
            }
            Check(rejected, name + " is rejected as invalid PE metadata");
            Check(Equal(bytes, original), name + " does not modify the input on failure");
        }

        private static void Relocation(byte[] bytes, uint page, ushort entry)
        {
            U32(bytes, Optional + 112 + 5 * 8, 0x4000);
            U32(bytes, Optional + 116 + 5 * 8, 12);
            U32(bytes, 0xa00, page);
            U32(bytes, 0xa04, 12);
            U16(bytes, 0xa08, entry);
            U16(bytes, 0xa0a, 0);
        }

        public static string Run()
        {
            checks = 0;
            byte[] input = Fixture(false);
            byte[] original = (byte[])input.Clone();
            var result = GameImGui.PeUnwindNormalizer.Normalize(input);
            Check(result.Changed, "unsorted fixture requires normalization");
            Check(result.RecordCount == 3, "all three runtime-function records found");
            Check(result.Inversions == 1, "one adjacent ordering inversion detected");
            Check(Equal(input, original), "normalization does not mutate its input buffer");
            VerifyReorderOnly(original, result.Bytes, Pdata, PdataLength);
            Check(Equal(result.Bytes, Fixture(true)), "normalized image equals sorted fixture exactly");

            var again = GameImGui.PeUnwindNormalizer.Normalize(result.Bytes);
            Check(!again.Changed && again.Inversions == 0, "second normalization is a no-op");
            Check(Equal(again.Bytes, result.Bytes), "normalization is byte-for-byte idempotent");
            var sorted = GameImGui.PeUnwindNormalizer.Normalize(Fixture(true));
            Check(!sorted.Changed && sorted.RecordCount == 3, "already sorted valid image is accepted unchanged");

            byte[] withChecksum = Fixture(false);
            U32(withChecksum, Optional + 64, 1);
            var checksummed = GameImGui.PeUnwindNormalizer.Normalize(withChecksum);
            // Known answer from an independent 16-bit one's-complement sum of
            // the complete synthetic fixture with the checksum field excluded.
            Check(Read32(checksummed.Bytes, Optional + 64) == 0x103f,
                "existing PE checksum is recomputed correctly");
            Check(Read32(withChecksum, Optional + 64) == 1, "checksum update does not mutate input");
            VerifyReorderOnly(withChecksum, checksummed.Bytes, Pdata, PdataLength);
            var checksumAgain = GameImGui.PeUnwindNormalizer.Normalize(checksummed.Bytes);
            Check(!checksumAgain.Changed && Equal(checksumAgain.Bytes, checksummed.Bytes),
                "checksummed output is byte-for-byte idempotent");

            Reject("wrong architecture", delegate(byte[] b) { U16(b, Pe + 4, 0x14c); });
            Reject("DLL instead of executable", delegate(byte[] b) { U16(b, Pe + 22, 0x2022); });
            Reject("PE32 instead of PE32+", delegate(byte[] b) { U16(b, Optional, 0x10b); });
            Reject("signed image", delegate(byte[] b) {
                U32(b, Optional + 112 + 4 * 8, 0xb80);
                U32(b, Optional + 116 + 4 * 8, 16);
                U32(b, 0xb80, 16);
                U16(b, 0xb84, 0x200);
                U16(b, 0xb86, 2);
            });
            Reject("already sorted signed image", delegate(byte[] b) {
                U32(b, Optional + 112 + 4 * 8, 0xb80);
                U32(b, Optional + 116 + 4 * 8, 16);
                U32(b, 0xb80, 16);
                U16(b, 0xb84, 0x200);
                U16(b, 0xb86, 2);
            }, true);
            Reject("partial runtime-function row", delegate(byte[] b) {
                U32(b, Optional + 116 + 3 * 8, PdataLength - 1);
            });
            Reject("missing exception directory", delegate(byte[] b) {
                U32(b, Optional + 112 + 3 * 8, 0);
                U32(b, Optional + 116 + 3 * 8, 0);
            });
            Reject("overlapping function ranges", delegate(byte[] b) {
                U32(b, Pdata + 24, 0x1010);
            });
            Reject("duplicate function ranges", delegate(byte[] b) {
                System.Buffer.BlockCopy(b, Pdata + 12, b, Pdata + 24, 12);
            });
            Reject("function outside executable section", delegate(byte[] b) {
                U32(b, Pdata, 0x3000);
                U32(b, Pdata + 4, 0x3010);
            });
            Reject("writable exception table", delegate(byte[] b) {
                U32(b, Sections + 40 + 36, 0xc0000040);
            });
            Reject("another directory aliases exception table", delegate(byte[] b) {
                U32(b, Optional + 112 + 6 * 8, 0x2000);
                U32(b, Optional + 116 + 6 * 8, 12);
            });
            Reject("invalid unwind version", delegate(byte[] b) { b[0x800] = 0; });
            Reject("unaligned unwind RVA", delegate(byte[] b) { U32(b, Pdata + 8, 0x3001); });
            Reject("truncated unwind slots", delegate(byte[] b) { b[0x802] = 255; });
            Reject("unwind metadata aliases exception table", delegate(byte[] b) {
                U32(b, Pdata + 8, 0x2000);
            });
            Reject("relocation targets exception table", delegate(byte[] b) {
                Relocation(b, 0x2000, 0xa000);
            });
            Reject("relocated pointer points into exception table", delegate(byte[] b) {
                Relocation(b, 0x3000, 0xa010);
                U64(b, 0x810, ImageBase + 0x2000);
            });
            Reject("truncated relocation block", delegate(byte[] b) {
                Relocation(b, 0x3000, 0xa010);
                U32(b, 0xa04, 16);
            });
            return "PASS: PE unwind normalization, reorder-only preservation, idempotency, and rejection cases (" + checks + " assertions).";
        }

        public static string VerifyImage(byte[] input)
        {
            byte[] original = (byte[])input.Clone();
            var result = GameImGui.PeUnwindNormalizer.Normalize(input);
            Check(Equal(input, original), "real input image is never modified");
            int optional = checked((int)Read32(original, 0x3c)) + 24;
            int pe = optional - 24;
            uint rva = Read32(original, optional + 112 + 3 * 8);
            int size = checked((int)Read32(original, optional + 116 + 3 * 8));
            int section = optional + System.BitConverter.ToUInt16(original, pe + 20);
            int sectionCount = System.BitConverter.ToUInt16(original, pe + 6);
            int table = -1;
            for (int i = 0; i < sectionCount; i++)
            {
                int at = section + i * 40;
                uint sectionRva = Read32(original, at + 12);
                uint rawSize = Read32(original, at + 16);
                if (rva >= sectionRva && (ulong)rva - sectionRva + (uint)size <= rawSize)
                {
                    table = checked((int)((ulong)Read32(original, at + 20) + rva - sectionRva));
                    break;
                }
            }
            Check(table >= 0, "real image exception directory is file-backed");
            VerifyReorderOnly(original, result.Bytes, table, size);
            var again = GameImGui.PeUnwindNormalizer.Normalize(result.Bytes);
            Check(!again.Changed && again.Inversions == 0, "real image normalized output is ordered");
            Check(Equal(again.Bytes, result.Bytes), "real image normalization is idempotent");
            return "PASS: real image tested in memory only; records=" + result.RecordCount +
                ", inversions=" + result.Inversions + ", changed=" + result.Changed + ".";
        }
    }
}
'@
  Add-Type -TypeDefinition ($match.Groups['Core'].Value + [Environment]::NewLine + $testSource) -Language CSharp
  Write-Output ([GameImGui.Tests.PeUnwindRegression]::Run())

  $engine = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  $testDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'Game ImGui unwind test ' + [Guid]::NewGuid().ToString('N'))
  [void][IO.Directory]::CreateDirectory($testDirectory)
  $fixturePath = [IO.Path]::Combine($testDirectory, 'unsorted overlay fixture.exe')
  [byte[]]$fixture = [GameImGui.Tests.PeUnwindRegression]::FileFixture('unsorted')
  $expected = [GameImGui.PeUnwindNormalizer]::Normalize($fixture)
  $expectedHash = Get-TestSha512 $expected.Bytes
  [IO.File]::WriteAllBytes($fixturePath, $fixture)
  $first = Invoke-NormalizerProcess $engine $normalizerPath $fixturePath
  if ($first.ExitCode -ne 0) { throw ('File wrapper failed to normalize: ' + $first.Output + $first.Error) }
  [byte[]]$saved = [IO.File]::ReadAllBytes($fixturePath)
  if ($saved.Length -ne $expected.Bytes.Length -or (Get-TestSha512 $saved) -ne $expectedHash) { throw 'File wrapper did not save the expected normalized bytes.' }
  $readback = [GameImGui.PeUnwindNormalizer]::Normalize($saved)
  if ($readback.Changed -or $readback.Inversions -ne 0) { throw 'File wrapper saved an unordered exception table.' }
  if (-not $first.Output.Contains('ordering=PASS') -or -not $first.Output.Contains($fixturePath) -or -not $first.Output.Contains('bytes=' + $saved.Length) -or -not $first.Output.Contains($expectedHash)) { throw 'File wrapper receipt did not identify the saved image.' }
  $second = Invoke-NormalizerProcess $engine $normalizerPath $fixturePath
  if ($second.ExitCode -ne 0 -or (Get-TestSha512 ([IO.File]::ReadAllBytes($fixturePath))) -ne $expectedHash -or -not $second.Output.Contains('already ordered; file unchanged.')) { throw ('File wrapper second pass was not idempotent: ' + $second.Output + $second.Error) }

  foreach ($kind in @('signed', 'overlap')) {
    $invalidPath = [IO.Path]::Combine($testDirectory, $kind + ' overlay fixture.exe')
    [byte[]]$invalid = [GameImGui.Tests.PeUnwindRegression]::FileFixture($kind)
    $originalHash = Get-TestSha512 $invalid
    [IO.File]::WriteAllBytes($invalidPath, $invalid)
    $failed = Invoke-NormalizerProcess $engine $normalizerPath $invalidPath
    if ($failed.ExitCode -eq 0) { throw ($kind + ' file wrapper case was accepted.') }
    $expectedReason = if ($kind -eq 'signed') { 'PE_UNWIND_SIGNED_IMAGE_REFUSED' } else { 'PE_UNWIND_DUPLICATE_OR_OVERLAPPING_FUNCTIONS' }
    if (-not $failed.Error.Contains($expectedReason)) { throw ($kind + ' file wrapper failed for an unexpected reason: ' + $failed.Output + $failed.Error) }
    if ((Get-TestSha512 ([IO.File]::ReadAllBytes($invalidPath))) -ne $originalHash) { throw ($kind + ' file wrapper rejection changed the original file.') }
    if ($failed.Output.Contains('ordering=PASS')) { throw ($kind + ' file wrapper rejection printed a success receipt.') }
  }
  if ([IO.Directory]::GetFiles($testDirectory, '.game-unwind-*.pending').Length -ne 0) { throw 'File wrapper left temporary output behind.' }
  Write-Output 'PASS: production PowerShell file wrapper, paths with spaces, saved-byte receipt, second-pass idempotency, and unchanged signed/overlap rejection cases.'

  # The IDE and test tools use the production normalizer directly. Keep the literal-path
  # and failure-propagation checks after removing the optional BAT finalizer.
  # Quotes, &, (), $, apostrophe and ! must stay arguments, never script source.
  $specialFixturePath = [IO.Path]::Combine($testDirectory, 'new $overlay''s (build) & final!.exe')
  [IO.File]::WriteAllBytes($specialFixturePath, $fixture)
  $specialSuccess = Invoke-NormalizerProcess $engine $normalizerPath $specialFixturePath
  if ($specialSuccess.ExitCode -ne 0 -or (Get-TestSha512 ([IO.File]::ReadAllBytes($specialFixturePath))) -ne $expectedHash) { throw ('Literal-path normalizer did not save expected bytes: ' + $specialSuccess.Output + $specialSuccess.Error) }
  if (-not $specialSuccess.Output.Contains($specialFixturePath) -or -not $specialSuccess.Output.Contains($expectedHash) -or -not $specialSuccess.Output.Contains('ordering=PASS')) { throw 'Literal-path normalizer did not identify the saved image.' }
  $specialInvalidPath = [IO.Path]::Combine($testDirectory, 'signed $overlay''s (build) & rejection!.exe')
  [byte[]]$specialInvalid = [GameImGui.Tests.PeUnwindRegression]::FileFixture('signed')
  $specialInvalidHash = Get-TestSha512 $specialInvalid
  [IO.File]::WriteAllBytes($specialInvalidPath, $specialInvalid)
  $specialFailure = Invoke-NormalizerProcess $engine $normalizerPath $specialInvalidPath
  if ($specialFailure.ExitCode -eq 0 -or -not $specialFailure.Error.Contains('PE_UNWIND_SIGNED_IMAGE_REFUSED')) { throw ('Literal-path normalizer did not propagate failure: ' + $specialFailure.Output + $specialFailure.Error) }
  if ((Get-TestSha512 ([IO.File]::ReadAllBytes($specialInvalidPath))) -ne $specialInvalidHash -or $specialFailure.Output.Contains('ordering=PASS')) { throw 'Literal-path normalizer rejection changed the input or reported success.' }
  if ([IO.Directory]::GetFiles($testDirectory, '.game-unwind-*.pending').Length -ne 0) { throw 'Literal-path normalizer left temporary output behind.' }
  Write-Output 'PASS: direct production normalizer, literal special-character paths, saved-byte receipt, and preserved nonzero failure exit.'

  if ($ImagePath) {
    [byte[]]$imageBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ImagePath).ProviderPath)
    Write-Output ([GameImGui.Tests.PeUnwindRegression]::VerifyImage($imageBytes))
  }
  exit 0
} catch {
  Write-Error $_ -ErrorAction Continue
  exit 1
} finally {
  if ($null -ne $testDirectory -and [IO.Directory]::Exists($testDirectory)) { [IO.Directory]::Delete($testDirectory, $true) }
}
