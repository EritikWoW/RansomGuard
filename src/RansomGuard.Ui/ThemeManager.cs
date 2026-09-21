using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace RansomGuard.Ui;

internal static class ThemeManager
{
    public static string AppliedTheme { get; private set; } = "Dark";
    private static double _lastScale = -1;
    private static bool? _lastHighContrast;
    public static void Apply(string choice, double scale)
    {
        string actual = choice == "System" ? ReadSystemTheme() : choice;
        if (actual is not ("Dark" or "Light")) actual = "Dark";
        scale = Math.Clamp(scale, 1.0, 1.2);
        if (actual == AppliedTheme && scale == _lastScale && _lastHighContrast == SystemParameters.HighContrast) return;
        var app = Application.Current;
        var theme = new ResourceDictionary { Source = new Uri($"pack://application:,,,/RansomGuard.Ui;component/Themes/{actual}.xaml", UriKind.Absolute) };
        if (SystemParameters.HighContrast)
        {
            foreach (string key in new[] { "Page", "Sidebar", "Surface", "Raised", "Hover", "Chrome", "DisabledSurface", "AccentSoft", "InfoSoft", "WarningSoft", "DangerSoft", "SuccessSoft", "PurpleSoft", "Card" })
                theme[key+"Brush"] = SystemColors.WindowBrush;
            foreach (string key in new[] { "Text", "Secondary", "Muted", "Disabled", "Border", "InputBorder", "Accent", "Info", "Warning", "Danger", "Success", "Purple", "InfoBorder", "Focus" })
                theme[key+"Brush"] = SystemColors.WindowTextBrush;
            theme["AccentFillBrush"] = SystemColors.HighlightBrush;
            theme["SelectedBrush"] = SystemColors.WindowBrush;
            theme["OnAccentBrush"] = SystemColors.HighlightTextBrush;
        }
        app.Resources.MergedDictionaries[0] = theme;
        scale = Math.Clamp(scale, 1.0, 1.2);
        app.Resources["BodySize"] = 14.0 * scale;
        app.Resources["CaptionSize"] = 13.0 * scale;
        app.Resources["SectionSize"] = 18.0 * scale;
        app.Resources["HeadingSize"] = 32.0 * scale;
        app.Resources["MetricSize"] = 23.0 * scale;
        AppliedTheme = actual;
        _lastScale = scale; _lastHighContrast = SystemParameters.HighContrast;
    }
    private static string ReadSystemTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", false);
            return key?.GetValue("AppsUseLightTheme") is int i && i == 0 ? "Dark" : "Light";
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or System.IO.IOException) { return "Dark"; }
    }
}
