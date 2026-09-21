using System.IO;
using System.Text.Json;

namespace RansomGuard.Ui;

internal sealed record UiPreferences(string Theme = "Dark", double TextScale = 1.0, string Language = "uk-UA")
{
    private static string Folder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RansomGuard", "Ui");
    private static string FileName => Path.Combine(Folder, "preferences.json");
    public static UiPreferences Load()
    {
        try
        {
            CheckPath(Folder);
            if (!File.Exists(FileName) || new FileInfo(FileName).Length > 4096) return new();
            CheckPath(FileName);
            var p = JsonSerializer.Deserialize<UiPreferences>(File.ReadAllText(FileName)) ?? new();
            return new(p.Theme is "Light" or "Dark" or "System" ? p.Theme : "Dark",
                p.TextScale is >= 1 and <= 1.2 ? p.TextScale : 1, L.Supported(p.Language) ? p.Language : "uk-UA");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException) { return new(); }
    }
    public bool Save()
    {
        string? temporary = null;
        try
        {
            CheckPath(Folder);
            Directory.CreateDirectory(Folder);
            CheckPath(Folder);
            CheckPath(FileName);
            temporary = Path.Combine(Folder, Guid.NewGuid().ToString("N")+".tmp");
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                JsonSerializer.Serialize(stream, this);
            File.Move(temporary, FileName, true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
        finally { if (temporary is not null && File.Exists(temporary)) { try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { } } }
    }
    private static void CheckPath(string path)
    {
        string? current = Path.GetFullPath(path);
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("UI preferences refuse reparse-point paths.");
            current = Path.GetDirectoryName(current);
        }
    }
}
