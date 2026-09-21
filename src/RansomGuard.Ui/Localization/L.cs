using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows.Data;
using System.Windows.Markup;

namespace RansomGuard.Ui;

// Presentation resources only. Language NEVER changes protocol verbs, SIDs, paths, hashes or policy.
public sealed class L : INotifyPropertyChanged
{
    public static L Instance { get; } = new();
    private readonly Dictionary<string, string> _uk = Load("uk-UA");
    private readonly Dictionary<string, string> _en = Load("en-US");
    public static string Language { get; private set; } = "uk-UA";
    public static CultureInfo Culture => CultureInfo.GetCultureInfo(Language);
    public static event EventHandler? Changed;
    public event PropertyChangedEventHandler? PropertyChanged;
    public string this[string key] => T(key);
    public static bool Supported(string? language) => language is "uk-UA" or "en-US";
    public static string T(string key)
    {
        var selected = Language == "uk-UA" ? Instance._uk : Instance._en;
        return selected.TryGetValue(key, out var value) ? value : Instance._en.GetValueOrDefault(key, "[" + key + "]");
    }
    public static string F(string key, params object?[] arguments) => string.Format(Culture, T(key), arguments);
    public static void Select(string language)
    {
        if (!Supported(language)) throw new ArgumentException("Unsupported UI language.", nameof(language));
        bool changed = Language != language;
        Language = language;
        // Set only the UI process cultures. Backend JSON and security comparisons stay invariant.
        CultureInfo.CurrentUICulture = Culture; CultureInfo.CurrentCulture = Culture;
        CultureInfo.DefaultThreadCurrentUICulture = Culture; CultureInfo.DefaultThreadCurrentCulture = Culture;
        if (changed)
        {
            Instance.PropertyChanged?.Invoke(Instance, new PropertyChangedEventArgs("Item[]"));
            Changed?.Invoke(Instance, EventArgs.Empty);
        }
    }
    private static Dictionary<string, string> Load(string language)
    {
        using var stream = typeof(L).Assembly.GetManifestResourceStream("RansomGuard.Ui.Localization." + language + ".json")
            ?? throw new InvalidOperationException("Missing bundled language resource: " + language);
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream)
            ?? throw new InvalidDataException("Invalid language resource.");
    }
    internal static void ValidateResources()
    {
        if (!Instance._en.Keys.Order().SequenceEqual(Instance._uk.Keys.Order()))
            throw new InvalidDataException("Localization resource keys differ.");
        foreach (var text in Instance._en.Values.Concat(Instance._uk.Values))
            _ = System.Text.CompositeFormat.Parse(text);
    }
}

[MarkupExtensionReturnType(typeof(string))]
public sealed class LocExtension : MarkupExtension
{
    public string Key { get; set; }
    public LocExtension(string key) => Key = key;
    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding("[" + Key + "]") { Source = L.Instance, Mode = BindingMode.OneWay }.ProvideValue(serviceProvider);
}
public sealed record LanguageOption(string Code, string Name);
