param([Parameter(Mandatory = $true)][string]$ImagePath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Delphi's classic Win64 linker can retain bcc64 COMDAT unwind records in
# object order. Windows requires the exception directory sorted by BeginAddress.
# Fix the unsigned, unpublished build product; never relax runtime/server checks.
# The C# core is pure and separately exercised by Cozy.Tests/Cozy.Unwind/Cozy.Test-PE-Unwind.ps1.
$source = @'
using System;
using System.Collections.Generic;

namespace GameImGui {
    public sealed class NormalizeResult {
        public byte[] Bytes;
        public bool Changed;
        public int RecordCount;
        public int Inversions;
    }

    public static class PeUnwindNormalizer {
        private sealed class Section {
            public uint Rva, Span, Raw, RawSize, Flags;
            public ulong Mapped;
        }
        private sealed class Record {
            public uint Begin, End, Unwind;
            public int Offset;
        }
        private sealed class Image {
            public byte[] Bytes;
            public uint ImageSize, Headers, ExceptionRva, ExceptionSize;
            public ulong ImageBase;
            public int Optional, DirectoryCount, ChecksumOffset;
            public List<Section> Sections = new List<Section>();

            public Section Locate(uint rva, uint size) {
                if (size == 0) Fail("EMPTY_RANGE");
                foreach (Section s in Sections)
                    if (rva >= s.Rva && (ulong)rva + size <= (ulong)s.Rva + Math.Min(s.Span, s.RawSize)) return s;
                Fail("RANGE_NOT_FILE_BACKED"); return null;
            }
            public int RawAt(uint rva, uint size) {
                Section s = Locate(rva, size);
                return checked((int)((ulong)s.Raw + rva - s.Rva));
            }
            public void Code(uint begin, uint end) {
                if (end <= begin) Fail("CODE_RANGE_INVALID");
                Section s = Locate(begin, end - begin);
                if ((s.Flags & 0xA0000000U) != 0x20000000U) Fail("CODE_NOT_READONLY_EXECUTABLE");
            }
            public int Metadata(uint rva, uint size) {
                Section s = Locate(rva, size);
                if ((s.Flags & 0x60000000U) != 0x40000000U) Fail("UNWIND_NOT_READABLE_METADATA");
                if (Overlaps(rva, size, ExceptionRva, ExceptionSize)) Fail("UNWIND_ALIASES_EXCEPTION_TABLE");
                return checked((int)((ulong)s.Raw + rva - s.Rva));
            }
            public void Unwind(uint rva, HashSet<uint> done, HashSet<uint> active, int depth) {
                // Low-bit indirect RUNTIME_FUNCTION pointers would be invalidated
                // by reordering, so this deliberately supports direct records only.
                if ((rva & 3) != 0) Fail("INDIRECT_OR_UNALIGNED_UNWIND");
                if (done.Contains(rva)) return;
                if (depth > 64 || !active.Add(rva)) Fail("UNWIND_CHAIN_INVALID");
                int at = Metadata(rva, 4);
                int version = Bytes[at] & 7, flags = Bytes[at] >> 3;
                if ((version != 1 && version != 2) || flags > 7 || ((flags & 4) != 0 && (flags & 3) != 0)) Fail("UNWIND_FORMAT_UNSUPPORTED");
                uint body = checked((uint)(4 + 2 * ((Bytes[at + 2] + 1) & ~1)));
                uint trailer = (flags & 4) != 0 ? 12U : ((flags & 3) != 0 ? 4U : 0U);
                at = Metadata(rva, body + trailer);
                int tail = checked(at + (int)body);
                if ((flags & 4) != 0) {
                    Code(U32(Bytes, tail), U32(Bytes, tail + 4));
                    Unwind(U32(Bytes, tail + 8), done, active, depth + 1);
                } else if ((flags & 3) != 0) {
                    uint handler = U32(Bytes, tail);
                    if (handler == uint.MaxValue) Fail("UNWIND_HANDLER_INVALID");
                    Code(handler, handler + 1);
                }
                active.Remove(rva); done.Add(rva);
            }
        }

        private static void Fail(string reason) { throw new InvalidOperationException("PE_UNWIND_" + reason); }
        private static bool Overlaps(ulong a, ulong an, ulong b, ulong bn) { return an != 0 && bn != 0 && a < b + bn && b < a + an; }
        private static ushort U16(byte[] b, int at) { return (ushort)(b[at] | (b[at + 1] << 8)); }
        private static uint U32(byte[] b, int at) { return (uint)(b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)); }
        private static ulong U64(byte[] b, int at) { return U32(b, at) | ((ulong)U32(b, at + 4) << 32); }
        private static void Put32(byte[] b, int at, uint value) { for (int i = 0; i < 4; ++i) b[at + i] = (byte)(value >> (8 * i)); }

        private static Image Parse(byte[] bytes) {
            if (bytes == null || bytes.Length < 512 || bytes.Length > 64 * 1024 * 1024 || U16(bytes, 0) != 0x5A4D) Fail("FILE_INVALID");
            uint peValue = U32(bytes, 0x3C);
            if (peValue < 64 || (ulong)peValue + 24 > (ulong)bytes.Length) Fail("HEADER_INVALID");
            int pe = (int)peValue, opt = pe + 24, count = U16(bytes, pe + 6), optSize = U16(bytes, pe + 20);
            uint attributes = U16(bytes, pe + 22);
            if (U32(bytes, pe) != 0x4550 || U16(bytes, pe + 4) != 0x8664 || (attributes & 2) == 0 || (attributes & 0x2000) != 0 || count < 1 || count > 96 || optSize < 160 || (ulong)opt + (uint)optSize + (uint)count * 40 > (ulong)bytes.Length) Fail("AMD64_EXECUTABLE_REQUIRED");
            if (U16(bytes, opt) != 0x20B || U16(bytes, opt + 68) != 2) Fail("PE32PLUS_GUI_REQUIRED");
            Image image = new Image();
            image.Bytes = bytes; image.Optional = opt; image.ChecksumOffset = opt + 64;
            image.ImageSize = U32(bytes, opt + 56); image.Headers = U32(bytes, opt + 60); image.ImageBase = U64(bytes, opt + 24);
            uint directories = U32(bytes, opt + 108);
            if (image.ImageSize < 4096 || image.ImageSize > 128 * 1024 * 1024 || image.Headers < opt + optSize + count * 40 || image.Headers > bytes.Length || image.Headers > image.ImageSize || directories > 16 || 112 + directories * 8 > optSize) Fail("LAYOUT_INVALID");
            image.DirectoryCount = (int)directories;
            if (directories <= 3) Fail("EXCEPTION_DIRECTORY_REQUIRED");
            // Authenticode signatures bind the bytes: signed files are never edited,
            // even if their exception directory is already in canonical order.
            if (directories > 4 && (U32(bytes, opt + 144) != 0 || U32(bytes, opt + 148) != 0)) Fail("SIGNED_IMAGE_REFUSED");
            for (int i = 0; i < count; ++i) {
                int at = opt + optSize + i * 40;
                Section s = new Section();
                s.Span = U32(bytes, at + 8); s.Rva = U32(bytes, at + 12); s.RawSize = U32(bytes, at + 16); s.Raw = U32(bytes, at + 20); s.Flags = U32(bytes, at + 36);
                if (s.Span == 0) s.Span = s.RawSize;
                s.Mapped = Math.Max(s.Span, s.RawSize);
                if (s.Span == 0 || s.Rva < image.Headers || (ulong)s.Rva + s.Mapped > image.ImageSize || (s.RawSize != 0 && (s.Raw < image.Headers || (ulong)s.Raw + s.RawSize > (ulong)bytes.Length))) Fail("SECTION_INVALID");
                foreach (Section old in image.Sections)
                    if (Overlaps(s.Rva, s.Mapped, old.Rva, old.Mapped) || Overlaps(s.Raw, s.RawSize, old.Raw, old.RawSize)) Fail("SECTION_OVERLAP");
                image.Sections.Add(s);
            }
            uint entry = U32(bytes, opt + 16);
            if (entry == uint.MaxValue) Fail("ENTRY_INVALID");
            image.Code(entry, entry + 1);
            image.ExceptionRva = U32(bytes, opt + 136); image.ExceptionSize = U32(bytes, opt + 140);
            if (image.ExceptionRva == 0 || (image.ExceptionRva & 3) != 0 || image.ExceptionSize == 0 || image.ExceptionSize % 12 != 0 || image.ExceptionSize > 16 * 1024 * 1024) Fail("EXCEPTION_DIRECTORY_INVALID");
            Section table = image.Locate(image.ExceptionRva, image.ExceptionSize);
            if ((table.Flags & 0xE0000000U) != 0x40000000U) Fail("EXCEPTION_TABLE_NOT_READONLY_METADATA");
            for (int i = 0; i < image.DirectoryCount; ++i) {
                if (i == 3 || i == 4) continue;
                uint rva = U32(bytes, opt + 112 + i * 8), size = U32(bytes, opt + 116 + i * 8);
                if (Overlaps(rva, size, image.ExceptionRva, image.ExceptionSize)) Fail("DIRECTORY_ALIASES_EXCEPTION_TABLE");
            }
            return image;
        }

        private static void CheckRelocations(Image image) {
            if (image.DirectoryCount <= 5) return;
            byte[] b = image.Bytes;
            uint rva = U32(b, image.Optional + 152), size = U32(b, image.Optional + 156);
            if ((rva == 0) != (size == 0) || size > 16 * 1024 * 1024) Fail("RELOCATION_DIRECTORY_INVALID");
            if (size == 0) return;
            int at = image.RawAt(rva, size), end = checked(at + (int)size);
            while (at < end) {
                if (end - at < 8) Fail("RELOCATION_BLOCK_INVALID");
                uint page = U32(b, at), block = U32(b, at + 4);
                if (page >= image.ImageSize || (page & 4095) != 0 || block < 8 || (block & 1) != 0 || (ulong)at + block > (ulong)end) Fail("RELOCATION_BLOCK_INVALID");
                int stop = checked(at + (int)block);
                for (int p = at + 8; p < stop; p += 2) {
                    ushort slot = U16(b, p); int kind = slot >> 12;
                    if (kind == 0) continue;
                    // This is an AMD64 template normalizer, not a relocation editor.
                    // Unknown operand types could hide pointers into moved rows.
                    if (kind != 10 && kind != 3) Fail("RELOCATION_KIND_UNSUPPORTED");
                    uint width = kind == 10 ? 8U : 4U;
                    ulong targetValue = (ulong)page + (uint)(slot & 4095);
                    if (targetValue + width > image.ImageSize) Fail("RELOCATION_TARGET_INVALID");
                    uint target = (uint)targetValue;
                    if (Overlaps(target, width, image.ExceptionRva, image.ExceptionSize)) Fail("RELOCATION_TOUCHES_EXCEPTION_TABLE");
                    // The operand can end in loader zero-fill. Read the actual
                    // pristine value rather than treating virtual bytes as file data.
                    ulong operand = 0;
                    Section section = null;
                    foreach (Section s in image.Sections)
                        if (target >= s.Rva && targetValue + width <= (ulong)s.Rva + s.Span) { section = s; break; }
                    if (section == null) Fail("RELOCATION_TARGET_INVALID");
                    for (int j = 0; j < width; ++j) {
                        ulong offset = targetValue - section.Rva + (uint)j;
                        if (offset < section.RawSize) operand |= (ulong)b[checked((int)((ulong)section.Raw + offset))] << (j * 8);
                    }
                    if (operand >= image.ImageBase && operand - image.ImageBase >= image.ExceptionRva && operand - image.ImageBase < (ulong)image.ExceptionRva + image.ExceptionSize) Fail("RELOCATED_POINTER_TO_EXCEPTION_TABLE");
                }
                at = stop;
            }
        }

        private static uint Checksum(byte[] bytes, int checksumOffset) {
            ulong sum = 0;
            for (int i = 0; i < bytes.Length; i += 2) {
                uint word = (i >= checksumOffset && i < checksumOffset + 4) ? 0U : bytes[i];
                if (i + 1 < bytes.Length && !(i + 1 >= checksumOffset && i + 1 < checksumOffset + 4)) word |= (uint)bytes[i + 1] << 8;
                sum += word; sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = (sum & 0xFFFF) + (sum >> 16);
            return checked((uint)((sum & 0xFFFF) + (sum >> 16) + (ulong)bytes.Length));
        }

        public static NormalizeResult Normalize(byte[] input) {
            Image image = Parse(input);
            CheckRelocations(image);
            int at = image.RawAt(image.ExceptionRva, image.ExceptionSize), count = checked((int)(image.ExceptionSize / 12));
            List<Record> records = new List<Record>(count);
            HashSet<uint> done = new HashSet<uint>(), active = new HashSet<uint>();
            int inversions = 0; uint previous = 0;
            for (int i = 0; i < count; ++i) {
                int p = at + i * 12;
                Record item = new Record(); item.Begin = U32(input, p); item.End = U32(input, p + 4); item.Unwind = U32(input, p + 8); item.Offset = p;
                image.Code(item.Begin, item.End); image.Unwind(item.Unwind, done, active, 0);
                if (i != 0 && item.Begin < previous) ++inversions;
                previous = item.Begin; records.Add(item);
            }
            records.Sort(delegate(Record a, Record b) { return a.Begin.CompareTo(b.Begin); });
            for (int i = 1; i < count; ++i)
                if (records[i].Begin < records[i - 1].End) Fail("DUPLICATE_OR_OVERLAPPING_FUNCTIONS");
            NormalizeResult result = new NormalizeResult();
            result.RecordCount = count; result.Inversions = inversions; result.Changed = inversions != 0; result.Bytes = input;
            if (!result.Changed) return result;
            result.Bytes = (byte[])input.Clone();
            for (int i = 0; i < count; ++i) Buffer.BlockCopy(input, records[i].Offset, result.Bytes, at + i * 12, 12);
            if (U32(input, image.ChecksumOffset) != 0) Put32(result.Bytes, image.ChecksumOffset, Checksum(result.Bytes, image.ChecksumOffset));
            return result;
        }
    }
}
'@

$temporary = $null
$stream = $null
try {
    Add-Type -TypeDefinition $source -Language CSharp
    $resolved = (Resolve-Path -LiteralPath $ImagePath).ProviderPath
    if (-not [IO.File]::Exists($resolved)) { throw 'PE_UNWIND_FILE_REQUIRED' }
    if (([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'PE_UNWIND_REPARSE_POINT_REFUSED' }
    $stream = New-Object IO.FileStream($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ($stream.Length -lt 512 -or $stream.Length -gt (64 * 1024 * 1024)) { throw 'PE_UNWIND_FILE_INVALID' }
    $bytes = New-Object byte[] ([int]$stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -le 0) { throw 'PE_UNWIND_READ_INCOMPLETE' }
        $offset += $read
    }
    $result = [GameImGui.PeUnwindNormalizer]::Normalize($bytes)
    if ($result.Changed) {
        $temporary = [IO.Path]::Combine([IO.Path]::GetDirectoryName($resolved), '.game-unwind-' + [Guid]::NewGuid().ToString('N') + '.pending')
        $output = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $output.Write($result.Bytes, 0, $result.Bytes.Length); $output.Flush($true) } finally { $output.Dispose() }
        $stream.Dispose(); $stream = $null
        # Same-directory Replace is atomic. A failure leaves the original build
        # product intact and exits nonzero, preventing PublishRandomExecutable.
        # PowerShell converts $null to String.Empty for a .NET string argument.
        # Pass an actual null backup path; an empty path makes Replace fail.
        [IO.File]::Replace($temporary, $resolved, [System.Management.Automation.Language.NullString]::Value)
        $temporary = $null
    }
    # Check the bytes actually saved on disk, not just the in-memory result.
    # A successful receipt therefore identifies the exact build artifact.
    $savedBytes = [IO.File]::ReadAllBytes($resolved)
    $verified = [GameImGui.PeUnwindNormalizer]::Normalize($savedBytes)
    if ($verified.Changed -or $verified.Inversions -ne 0) { throw 'PE_UNWIND_READBACK_NOT_ORDERED' }
    $sha512 = [Security.Cryptography.SHA512]::Create()
    try {
        $expectedHash = [BitConverter]::ToString($sha512.ComputeHash($result.Bytes)).Replace('-', '').ToLowerInvariant()
        $savedHash = [BitConverter]::ToString($sha512.ComputeHash($savedBytes)).Replace('-', '').ToLowerInvariant()
    } finally { $sha512.Dispose() }
    if ($savedBytes.Length -ne $result.Bytes.Length -or $savedHash -ne $expectedHash) { throw 'PE_UNWIND_READBACK_MISMATCH' }
    if ($result.Changed) {
        Write-Host ('PE unwind normalized: {0} records, {1} ordering inversions corrected.' -f $result.RecordCount, $result.Inversions)
    } else {
        Write-Host ('PE unwind ready: {0} records, already ordered; file unchanged.' -f $result.RecordCount)
    }
    Write-Host ('PE unwind verified: ordering=PASS; records={0}; bytes={1}' -f $verified.RecordCount, $savedBytes.Length)
    Write-Host ('PE unwind image: "{0}"' -f $resolved)
    Write-Host ('PE unwind SHA-512: {0}' -f $savedHash)
    exit 0
} catch {
    [Console]::Error.WriteLine('ERROR: Overlay PE unwind preparation failed: ' + $_.Exception.Message)
    exit 1
} finally {
    if ($null -ne $stream) { $stream.Dispose() }
    if ($null -ne $temporary -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
}
