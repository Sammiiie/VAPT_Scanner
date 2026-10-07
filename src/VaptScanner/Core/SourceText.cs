using System.Text;

namespace VaptScanner.Core;

/// <summary>
/// A loaded source file with helpers to translate offsets to line numbers and
/// "masked" views where comments are blanked out (preserving offsets and newlines)
/// so rules don't fire on commented-out code.
/// </summary>
public sealed class SourceText
{
    private readonly int[] _lineStarts;

    public string RelativePath { get; }
    public string FullPath { get; }
    public string Raw { get; }
    public string[] Lines { get; }

    /// <summary>Raw text with comments replaced by spaces (C#, JS, Razor, XML comments).</summary>
    public string NoComments { get; }

    public string Extension { get; }
    public string FileName { get; }

    public SourceText(string fullPath, string relativePath, string raw)
    {
        FullPath = fullPath;
        RelativePath = relativePath;
        Raw = raw;
        FileName = Path.GetFileName(fullPath);
        Extension = Path.GetExtension(fullPath).ToLowerInvariant();
        Lines = raw.Split('\n');

        var starts = new List<int> { 0 };
        for (int i = 0; i < raw.Length; i++)
            if (raw[i] == '\n') starts.Add(i + 1);
        _lineStarts = starts.ToArray();

        NoComments = Extension switch
        {
            ".cs" or ".js" or ".ts" or ".jsx" or ".tsx" => MaskCStyleComments(raw, verbatimStrings: Extension == ".cs"),
            ".cshtml" or ".razor" => MaskXmlComments(MaskRazorComments(MaskCStyleComments(raw, verbatimStrings: true))),
            ".config" or ".xml" or ".csproj" or ".props" or ".targets" => MaskXmlComments(raw),
            _ => raw
        };
    }

    public (int line, int column) Position(int offset)
    {
        int idx = Array.BinarySearch(_lineStarts, offset);
        if (idx < 0) idx = ~idx - 1;
        return (idx + 1, offset - _lineStarts[idx] + 1);
    }

    public string LineText(int line) =>
        line >= 1 && line <= Lines.Length ? Lines[line - 1].TrimEnd('\r') : "";

    public string Snippet(int line, int maxLength = 220)
    {
        var text = LineText(line).Trim();
        return text.Length > maxLength ? text[..maxLength] + "…" : text;
    }

    /// <summary>
    /// Blanks out // and /* */ comments while leaving string and char literals intact.
    /// Handles regular, verbatim (@"..."), interpolated ($"...") and raw ("""...""") strings well enough
    /// for pattern matching purposes.
    /// </summary>
    internal static string MaskCStyleComments(string s, bool verbatimStrings)
    {
        var sb = new StringBuilder(s);
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            char next = i + 1 < s.Length ? s[i + 1] : '\0';

            // Line comment
            if (c == '/' && next == '/')
            {
                // Don't treat URLs like "http://x" outside strings as comments; we only get here outside strings.
                while (i < s.Length && s[i] != '\n') { sb[i] = ' '; i++; }
                continue;
            }
            // Block comment
            if (c == '/' && next == '*')
            {
                sb[i] = ' '; sb[i + 1] = ' '; i += 2;
                while (i < s.Length && !(s[i] == '*' && i + 1 < s.Length && s[i + 1] == '/'))
                {
                    if (s[i] != '\n') sb[i] = ' ';
                    i++;
                }
                if (i < s.Length) { sb[i] = ' '; if (i + 1 < s.Length) sb[i + 1] = ' '; i += 2; }
                continue;
            }
            // Raw string literal """ ... """
            if (verbatimStrings && c == '"' && next == '"' && i + 2 < s.Length && s[i + 2] == '"')
            {
                int q = 0;
                while (i < s.Length && s[i] == '"') { q++; i++; }
                var closing = new string('"', q);
                int end = s.IndexOf(closing, i, StringComparison.Ordinal);
                i = end < 0 ? s.Length : end + q;
                continue;
            }
            // Verbatim string @"..." or $@"..." or @$"..."
            if (verbatimStrings && c == '"' && i > 0 && (s[i - 1] == '@' || (i > 1 && s[i - 1] == '$' && s[i - 2] == '@')))
            {
                i++;
                while (i < s.Length)
                {
                    if (s[i] == '"')
                    {
                        if (i + 1 < s.Length && s[i + 1] == '"') { i += 2; continue; }
                        i++; break;
                    }
                    i++;
                }
                continue;
            }
            // Regular string / char / JS template literal
            if (c == '"' || c == '\'' || (c == '`' && !verbatimStrings))
            {
                char quote = c;
                i++;
                while (i < s.Length && s[i] != quote)
                {
                    if (s[i] == '\\') i++;
                    else if (s[i] == '\n' && quote != '`') break; // unterminated; bail at end of line
                    i++;
                }
                i++;
                continue;
            }
            i++;
        }
        return sb.ToString();
    }

    internal static string MaskXmlComments(string s) => MaskBetween(s, "<!--", "-->");

    internal static string MaskRazorComments(string s) => MaskBetween(s, "@*", "*@");

    private static string MaskBetween(string s, string open, string close)
    {
        var sb = new StringBuilder(s);
        int i = 0;
        while ((i = s.IndexOf(open, i, StringComparison.Ordinal)) >= 0)
        {
            int end = s.IndexOf(close, i + open.Length, StringComparison.Ordinal);
            int stop = end < 0 ? s.Length : end + close.Length;
            for (int k = i; k < stop; k++) if (s[k] != '\n') sb[k] = ' ';
            i = stop;
        }
        return sb.ToString();
    }
}
