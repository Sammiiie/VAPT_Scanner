using System.Text.RegularExpressions;
using VaptScanner.Core;

namespace VaptScanner.Analyzers;

/// <summary>Result of a rule's extra validation step. Null means "not a finding".</summary>
public sealed record RuleCheck(Severity? Severity = null, string? Detail = null)
{
    public static readonly RuleCheck Accept = new();
}

/// <summary>
/// A regex-driven rule. The regex locates a candidate; the optional Check delegate inspects the
/// surrounding code to discard false positives or adjust severity.
/// </summary>
public sealed class PatternRule
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    public required RuleInfo Info { get; init; }
    public required Regex Pattern { get; init; }
    public required string[] Extensions { get; init; }

    /// <summary>Match against the raw text (including comments) instead of the comment-masked text.</summary>
    public bool MatchRaw { get; init; }

    public Func<SourceText, Match, RuleCheck?>? Check { get; init; }

    public static Regex Rx(string pattern, RegexOptions extra = RegexOptions.None) =>
        new(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Multiline | extra, RegexTimeout);

    public bool AppliesTo(SourceText src) =>
        Extensions.Contains(src.Extension) || Extensions.Contains(src.FileName, StringComparer.OrdinalIgnoreCase);

    public IEnumerable<Finding> Run(SourceText src, string source)
    {
        var text = MatchRaw ? src.Raw : src.NoComments;
        MatchCollection matches;
        try { matches = Pattern.Matches(text); _ = matches.Count; }
        catch (RegexMatchTimeoutException) { yield break; }

        foreach (Match m in matches)
        {
            RuleCheck? check;
            try { check = Check is null ? RuleCheck.Accept : Check(src, m); }
            catch (RegexMatchTimeoutException) { check = null; }
            if (check is null) continue;

            var (line, col) = src.Position(m.Index);
            yield return Finding.From(Info, src.RelativePath, line, col, src.Snippet(line), source, check.Severity, check.Detail);
        }
    }
}

/// <summary>Helpers that let rules look at a C# expression the way a reviewer would.</summary>
public static class CodeHelpers
{
    private static readonly Regex StringLiteral = new(@"\$?@?""(?:[^""\\]|\\.|"""")*""", RegexOptions.Compiled);
    private static readonly Regex SqlKeyword = new(@"\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|EXEC(?:UTE)?|MERGE|FROM|WHERE|ORDER\s+BY|DROP|TRUNCATE)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Returns the expression starting at <paramref name="start"/> up to the first top-level comma or
    /// closing parenthesis (for a call argument), or up to ';' (for an assignment).
    /// </summary>
    public static string ExtractArgument(string text, int start, bool untilSemicolon = false)
    {
        int depth = 0, i = start;
        bool inString = false, verbatim = false;
        while (i < text.Length && i - start < 2000)
        {
            char c = text[i];
            if (inString)
            {
                if (verbatim && c == '"' && i + 1 < text.Length && text[i + 1] == '"') { i += 2; continue; }
                if (!verbatim && c == '\\') { i += 2; continue; }
                if (c == '"') inString = false;
                i++; continue;
            }
            if (c == '"')
            {
                inString = true;
                verbatim = i > 0 && (text[i - 1] == '@' || (i > 1 && text[i - 1] == '$' && text[i - 2] == '@'));
                i++; continue;
            }
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}')
            {
                if (depth == 0) break;
                depth--;
            }
            else if (c == ',' && depth == 0 && !untilSemicolon) break;
            else if (c == ';' && depth == 0) break;
            i++;
        }
        return text[start..Math.Min(i, text.Length)].Trim();
    }

    /// <summary>All top-level arguments of a call whose '(' is at <paramref name="openParen"/>.</summary>
    public static List<string> ExtractArguments(string text, int openParen)
    {
        var args = new List<string>();
        int i = openParen + 1;
        for (int guard = 0; guard < 12 && i < text.Length; guard++)
        {
            var arg = ExtractArgument(text, i);
            int end = i + IndexAfter(text, i, arg);
            if (arg.Length > 0) args.Add(arg);
            if (end >= text.Length || text[end] != ',') break;
            i = end + 1;
        }
        return args;
    }

    private static int IndexAfter(string text, int start, string arg)
    {
        int pos = text.IndexOf(arg, start, StringComparison.Ordinal);
        return pos < 0 ? 0 : pos - start + arg.Length + CountTrailingWhitespace(text, pos + arg.Length);
    }

    private static int CountTrailingWhitespace(string text, int from)
    {
        int n = 0;
        while (from + n < text.Length && char.IsWhiteSpace(text[from + n])) n++;
        return n;
    }

    /// <summary>
    /// True when a string-valued expression is assembled at runtime from non-literal parts:
    /// interpolation with holes, concatenation with variables, string.Format/Concat, StringBuilder output.
    /// </summary>
    public static bool IsDynamicString(string expr)
    {
        if (string.IsNullOrWhiteSpace(expr)) return false;
        // Interpolated string with at least one hole.
        if (Regex.IsMatch(expr, @"(?:\$@?|@\$)""[^""]*\{[^{}""]+\}") ) return true;
        if (Regex.IsMatch(expr, @"\$""""""[\s\S]*\{[^{}]+\}")) return true; // raw interpolated
        // Concatenation where at least one operand is not a literal.
        var withoutLiterals = StringLiteral.Replace(expr, "\"\"");
        if (withoutLiterals.Contains('+'))
        {
            var parts = withoutLiterals.Split('+').Select(p => p.Trim().Trim('(', ')').Trim()).ToList();
            if (parts.Any(p => p != "\"\"" && p.Length > 0 && !IsConstLike(p))) return true;
        }
        if (Regex.IsMatch(expr, @"\b(?:string|String)\.(?:Format|Concat|Join)\s*\(")) return true;
        if (Regex.IsMatch(expr, @"\.Append(?:Format|Line)?\s*\(")) return true;
        return false;
    }

    // ALL_CAPS / PascalCase constants (e.g. TableName) are a judgement call; treat SCREAMING_CASE as constant.
    private static bool IsConstLike(string token) => Regex.IsMatch(token, @"^[A-Z][A-Z0-9_]*$");

    public static bool IsPureLiteral(string expr)
    {
        expr = expr.Trim();
        if (expr.StartsWith("$")) return !IsDynamicString(expr);
        var stripped = StringLiteral.Replace(expr, "").Replace("+", "").Trim();
        return expr.Contains('"') && stripped.Length == 0;
    }

    public static bool ContainsSqlKeyword(string text) => SqlKeyword.IsMatch(text);

    public static string RemoveStringLiterals(string text) => StringLiteral.Replace(text, "\"\"");

    public static string Window(string text, int index, int before, int after)
    {
        int s = Math.Max(0, index - before);
        int e = Math.Min(text.Length, index + after);
        return text[s..e];
    }

    /// <summary>Statement containing the index (from previous ';' or '{' to the next ';').</summary>
    public static string Statement(string text, int index)
    {
        int s = index;
        while (s > 0 && text[s - 1] != ';' && text[s - 1] != '{' && text[s - 1] != '}' && index - s < 1500) s--;
        int e = text.IndexOf(';', index);
        if (e < 0 || e - index > 2000) e = Math.Min(text.Length, index + 2000);
        return text[s..e];
    }
}
