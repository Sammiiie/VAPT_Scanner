using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaptScanner.Core;

/// <summary>
/// Optional project-level settings read from .vaptconfig.json at the scan root.
/// Command-line flags override these.
/// </summary>
public sealed class VaptConfig
{
    [JsonPropertyName("exclude")] public List<string> Exclude { get; set; } = new();
    [JsonPropertyName("disabledRules")] public List<string> DisabledRules { get; set; } = new();
    [JsonPropertyName("severityOverrides")] public Dictionary<string, Severity> SeverityOverrides { get; set; } = new();
    [JsonPropertyName("failOn")] public string? FailOn { get; set; }
    [JsonPropertyName("minSeverity")] public string? MinSeverity { get; set; }
    [JsonPropertyName("skipDependencyAudit")] public bool SkipDependencyAudit { get; set; }

    public static VaptConfig Load(string root, Action<string> note)
    {
        var dir = File.Exists(root) ? Path.GetDirectoryName(Path.GetFullPath(root))! : root;
        var path = Path.Combine(dir, ".vaptconfig.json");
        if (!File.Exists(path)) return new VaptConfig();
        try
        {
            var cfg = JsonSerializer.Deserialize<VaptConfig>(File.ReadAllText(path), JsonOpts.Read) ?? new VaptConfig();
            note($"Loaded settings from .vaptconfig.json");
            return cfg;
        }
        catch (Exception ex)
        {
            note($"Ignored .vaptconfig.json: {ex.Message}");
            return new VaptConfig();
        }
    }
}

public sealed class ScanOptions
{
    public required string Path { get; init; }
    public List<string> Exclude { get; } = new();
    public HashSet<string> DisabledRules { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, Severity> SeverityOverrides { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Severity FailOn { get; set; } = Severity.High;
    public Severity MinSeverity { get; set; } = Severity.Low;
    public bool SkipDependencyAudit { get; set; }
    public bool OfflineDependencyAudit { get; set; }
    public string? BaselinePath { get; set; }
    public bool IncludeTests { get; set; } = true;
}

public static class JsonOpts
{
    public static readonly JsonSerializerOptions Read = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static readonly JsonSerializerOptions Write = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };
}
