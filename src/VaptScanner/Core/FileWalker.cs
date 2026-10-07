using System.Text.RegularExpressions;

namespace VaptScanner.Core;

/// <summary>Enumerates scannable files under a root, honouring default and user excludes.</summary>
public sealed class FileWalker
{
    private static readonly HashSet<string> DefaultExcludedDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "bin", "obj", ".git", ".vs", ".vscode", ".idea", "node_modules", "packages",
        "TestResults", "artifacts", ".vapt-reports", "vapt-reports", "dist", "coverage"
    };

    private static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".cshtml", ".razor", ".js", ".ts", ".jsx", ".tsx",
        ".json", ".config", ".xml", ".csproj", ".props", ".targets", ".sln",
        ".yml", ".yaml", ".env", ".ini", ".properties", ".ps1", ".sh", ".cmd", ".bat",
        ".sql", ".txt", ".md", ".tf", ".bicep", ".pem", ".key", ".pfx", ".p12"
    };

    private static readonly HashSet<string> ScannableFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Dockerfile", ".env", "docker-compose.yml", "docker-compose.yaml", "packages.config", "web.config", "app.config"
    };

    private const long MaxFileBytes = 2 * 1024 * 1024;

    private readonly string _root;
    private readonly List<Regex> _excludeGlobs;

    public FileWalker(string root, IEnumerable<string> excludeGlobs)
    {
        _root = Path.GetFullPath(root);
        _excludeGlobs = excludeGlobs.Select(GlobToRegex).ToList();
    }

    public string Root => _root;

    public IEnumerable<string> Enumerate()
    {
        if (File.Exists(_root))
        {
            yield return _root;
            yield break;
        }

        var stack = new Stack<string>();
        stack.Push(_root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> subdirs, files;
            try
            {
                subdirs = Directory.EnumerateDirectories(dir);
                files = Directory.EnumerateFiles(dir);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sub in subdirs)
            {
                var name = Path.GetFileName(sub);
                if (DefaultExcludedDirs.Contains(name)) continue;
                if (IsExcluded(Relative(sub) + "/")) continue;
                stack.Push(sub);
            }

            foreach (var file in files)
            {
                var name = Path.GetFileName(file);
                var ext = Path.GetExtension(file);
                bool wanted = ScannableExtensions.Contains(ext) || ScannableFileNames.Contains(name) ||
                              name.StartsWith(".env", StringComparison.OrdinalIgnoreCase) ||
                              name.StartsWith("Dockerfile", StringComparison.OrdinalIgnoreCase);
                if (!wanted) continue;
                if (name.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase)) continue;
                if (IsExcluded(Relative(file))) continue;
                try { if (new FileInfo(file).Length > MaxFileBytes) continue; } catch { continue; }
                yield return file;
            }
        }
    }

    public string Relative(string fullPath)
    {
        var baseDir = File.Exists(_root) ? Path.GetDirectoryName(_root)! : _root;
        return Path.GetRelativePath(baseDir, fullPath).Replace('\\', '/');
    }

    private bool IsExcluded(string relative) => _excludeGlobs.Any(r => r.IsMatch(relative));

    /// <summary>Supports **, * and ? in globs, e.g. "**/Migrations/**", "tests/**", "*.Designer.cs".</summary>
    public static Regex GlobToRegex(string glob)
    {
        glob = glob.Replace('\\', '/').Trim();
        if (!glob.Contains('/')) glob = "**/" + glob; // bare pattern matches anywhere
        var pattern = "^" + Regex.Escape(glob)
            .Replace(@"\*\*/", "(.*/)?")
            .Replace(@"\*\*", ".*")
            .Replace(@"\*", "[^/]*")
            .Replace(@"\?", "[^/]") + "/?$";
        // Directory globs like "tests/**" should also match the folder itself.
        return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static bool LooksBinary(string text) => text.Contains('\0');
}
