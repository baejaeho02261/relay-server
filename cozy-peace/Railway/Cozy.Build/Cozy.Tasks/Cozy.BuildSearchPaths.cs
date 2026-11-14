// Compiled by Cozy.BuildIsolation.targets with the active MSBuild C# compiler.
// Keep this public name in sync with UsingTask; no inline-task factory is needed.
using System;
using System.IO;
using Microsoft.Build.Framework;

public sealed class GameValidateSearchPaths : Microsoft.Build.Utilities.Task
{
    [Required] public string Root { get; set; }
    [Required] public string ProjectDirectory { get; set; }
    [Required] public string Role { get; set; }
    [Required] public string Dcu { get; set; }
    [Required] public string Exe { get; set; }
    [Required] public string Final { get; set; }
    public string Units { get; set; }
    public string Includes { get; set; }
    public string Objects { get; set; }
    [Output] public string ResolvedUnits { get; set; }
    [Output] public string ResolvedIncludes { get; set; }
    [Output] public string ResolvedObjects { get; set; }

    public override bool Execute()
    {
        ResolvedUnits = null; ResolvedIncludes = null; ResolvedObjects = null;
        try {
            Func<string, string> canonical = value => Path.GetFullPath(value).TrimEnd('\\', '/');
            string root = canonical(Root);
            string projectName;
            switch (Role) {
                case "A": projectName = "Cozy.Launcher"; break;
                case "B": projectName = "Cozy.Client"; break;
                case "O": projectName = "Cozy.Overlay"; break;
                default: throw new InvalidOperationException("invalid production role");
            }
            string expectedProject = canonical(Path.Combine(root, "Cozy.Projects\\" + projectName));
            string projectDirectory = canonical(ProjectDirectory);
            if (!String.Equals(projectDirectory, expectedProject, StringComparison.OrdinalIgnoreCase)) {
                Log.LogError("GAME_BUILD_PROJECT_DIRECTORY_INVALID");
                return false;
            }
            string expectedDcu = canonical(Path.Combine(expectedProject, "dcu"));
            if (!String.Equals(canonical(Dcu), expectedDcu, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(canonical(Exe), expectedProject, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(canonical(Final), expectedProject, StringComparison.OrdinalIgnoreCase)) {
                Log.LogError("GAME_BUILD_OUTPUT_OVERRIDE_FORBIDDEN");
                return false;
            }
            string bridge = canonical(Path.Combine(root, "Cozy.BuildOutputs\\Cozy.ImGui"));
            Action<string> rejectReparse = full => {
                DirectoryInfo directory = new DirectoryInfo(full);
                while (directory != null) {
                    if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidOperationException("reparse point in build path");
                    directory = directory.Parent;
                }
            };
            // Validate output ancestry before the MSBuild RemoveDir clean step too.
            rejectReparse(canonical(Dcu)); rejectReparse(canonical(Exe)); rejectReparse(canonical(Final));
            string[] sourceDirectories = { "Cozy.Source\\Cozy.Application", "Cozy.Source\\Cozy.License", "Cozy.Source\\Cozy.Lifecycle", "Cozy.Source\\Cozy.Platform", "Cozy.Source\\Cozy.Security", "Cozy.Source\\Cozy.Network", "Cozy.Source\\Cozy.Identity", "Cozy.Source\\Cozy.Integrity", "Cozy.Source\\Cozy.Crypto", "Cozy.Source\\Cozy.Overlay", "Cozy.Source\\Cozy.Handoff", "Cozy.Source\\Cozy.Configuration", "Cozy.Source\\Cozy.Protection", "Cozy.Source\\Cozy.Security.NHW" };
            string[] names = { "unit", "include", "object" };
            string[] lists = { Units, Includes, Objects };
            for (int kind = 0; kind < lists.Length; kind++) {
                foreach (string raw in (lists[kind] ?? "").Split(';')) {
                    string entry = raw.Trim();
                    if (entry.Length == 0) continue;
                    if (entry.IndexOfAny(new char[] { '*', '?', '\"', '\r', '\n', '%', '$', '@' }) >= 0)
                        throw new InvalidOperationException("unresolved or wildcard path");
                    string full = canonical(Path.IsPathRooted(entry) ? entry : Path.Combine(projectDirectory, entry));
                    bool allowed = kind == 2 && (Role == "O" || Role == "B") && String.Equals(full, bridge, StringComparison.OrdinalIgnoreCase);
                    if (kind < 2) foreach (string relative in sourceDirectories)
                        if (String.Equals(full, canonical(Path.Combine(root, relative)), StringComparison.OrdinalIgnoreCase)) allowed = true;
                    if (!allowed) {
                        Log.LogError("GAME_BUILD_FOREIGN_SEARCH_PATH_FORBIDDEN: " + names[kind] + " path is outside its canonical allowlist");
                        return false;
                    }
                    // Reparse points could make lexical equality point outside the reviewed source tree.
                    rejectReparse(full);
                }
            }
            // Validate caller-supplied paths before restoring the complete canonical list.
            // This also fills IDE-cleared paths without accepting a foreign override.
            string[] resolvedSources = Array.ConvertAll(sourceDirectories,
                relative => canonical(Path.Combine(root, relative)));
            foreach (string sourceDirectory in resolvedSources) rejectReparse(sourceDirectory);
            if ((Role == "O" || Role == "B")) rejectReparse(bridge);
            ResolvedUnits = String.Join(";", resolvedSources);
            ResolvedIncludes = ResolvedUnits;
            ResolvedObjects = (Role == "O" || Role == "B") ? bridge : String.Empty;
            return true;
        } catch (Exception ex) {
            Log.LogError("GAME_BUILD_SEARCH_PATH_INVALID: " + ex.GetType().Name);
            return false;
        }
    }
}
