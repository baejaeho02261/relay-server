using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

// Opt-in hook transport only. This task never replaces or launches a Delphi
// compiler. Its evaluated properties are explicitly untrusted declarations.
public sealed class GameBuildObservation : Task {
    [Required] public string Mode { get; set; }
    [Required] public string Node { get; set; }
    [Required] public string Script { get; set; }
    [Required] public string RunDirectory { get; set; }
    [Required] public string Role { get; set; }
    public string Configuration { get; set; }
    public string Project { get; set; }
    public string Platform { get; set; }
    public string Defines { get; set; }
    public string Units { get; set; }
    public string Includes { get; set; }
    public string Objects { get; set; }
    public string Dcu { get; set; }
    public string Exe { get; set; }
    public string Optimize { get; set; }
    public string DebugInformation { get; set; }
    public string[] References { get; set; }
    public string[] MainSources { get; set; }
    private static string Json(string value) {
        StringBuilder b = new StringBuilder("\"");
        foreach (char c in value ?? "") {
            if (c == '"' || c == '\\') b.Append('\\').Append(c);
            else if (c < 32) b.Append("\\u").Append(((int)c).ToString("x4"));
            else b.Append(c);
        }
        return b.Append('"').ToString();
    }
    private static string List(string[] values) {
        List<string> result = new List<string>();
        foreach (string value in values ?? new string[0]) result.Add(Json(value));
        return "[" + String.Join(",", result.ToArray()) + "]";
    }
    private static string Quote(string value) {
        // Windows CreateProcess argument quoting, without cmd.exe expansion.
        StringBuilder b = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { ++slashes; continue; }
            if (c == '"') { b.Append('\\', slashes * 2 + 1); b.Append(c); }
            else { b.Append('\\', slashes); b.Append(c); }
            slashes = 0;
        }
        return b.Append('\\', slashes * 2).Append('"').ToString();
    }
    public override bool Execute() {
        try {
            if (Mode != "before" && Mode != "ready" && Mode != "after") throw new InvalidOperationException("MODE");
            if (Role != "A" && Role != "B" && Role != "O") throw new InvalidOperationException("ROLE");
            if (!Path.IsPathRooted(Node) || !File.Exists(Node)) throw new InvalidOperationException("ABSOLUTE_NODE_REQUIRED");
            if (!Path.IsPathRooted(RunDirectory) || !Directory.Exists(RunDirectory)) throw new InvalidOperationException("PREPARED_RUN_REQUIRED");
            DirectoryInfo cursor = new DirectoryInfo(RunDirectory);
            while (cursor != null) { if ((cursor.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("RUN_REPARSE_POINT"); cursor = cursor.Parent; }
            string arguments = Quote(Script) + " " + Mode + " " + Quote(RunDirectory) + " " + Role;
            if (Mode != "after") {
                Dictionary<string, string> fields = new Dictionary<string, string>();
                fields.Add("project", Project); fields.Add("configuration", Configuration); fields.Add("platform", Platform);
                fields.Add("defines", Defines); fields.Add("unitSearchPath", Units); fields.Add("includePath", Includes);
                fields.Add("objectPath", Objects); fields.Add("dcuOutput", Dcu); fields.Add("exeOutput", Exe);
                fields.Add("optimize", Optimize); fields.Add("debugInformation", DebugInformation);
                List<string> items = new List<string>(); foreach (KeyValuePair<string, string> item in fields) items.Add(Json(item.Key) + ":" + Json(item.Value));
                items.Add("\"references\":" + List(References)); items.Add("\"mainSources\":" + List(MainSources));
                string propertyFile = Path.Combine(RunDirectory, Role + "-" + Mode + "-evaluated-properties.json");
                using (FileStream f = new FileStream(propertyFile, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    byte[] bytes = new UTF8Encoding(false).GetBytes("{" + String.Join(",", items.ToArray()) + "}\n"); f.Write(bytes, 0, bytes.Length); f.Flush(true);
                }
                arguments += " " + Quote(Configuration) + " " + Quote(propertyFile);
            }
            ProcessStartInfo si = new ProcessStartInfo(Node, arguments);
            si.UseShellExecute = false; si.CreateNoWindow = true;
            // Inherit output handles, avoiding a pipe deadlock on large receipts.
            using (Process process = Process.Start(si)) { process.WaitForExit(); if (process.ExitCode != 0) throw new InvalidOperationException("HOOK_FAILED_" + process.ExitCode); }
            Log.LogMessage(MessageImportance.High, "GAME_IDE_OBSERVATION_" + Mode.ToUpperInvariant() + " role=" + Role + " (declaration; external trace required)");
            return true;
        } catch (Exception e) { Log.LogError("GAME_IDE_OBSERVATION_FAILED: " + e.Message); return false; }
    }
}
