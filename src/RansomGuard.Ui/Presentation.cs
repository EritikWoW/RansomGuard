using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using RansomGuard.Core;

namespace RansomGuard.Ui;

public sealed class EqualVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.Ordinal) ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
public sealed class BooleanVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        ((value is true) != string.Equals(parameter?.ToString(),"Invert",StringComparison.Ordinal)) ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
public sealed class StringEqualsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.Ordinal);
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
internal sealed class RelayCommand(Action<object?> execute, Func<bool>? canExecute = null) : ICommand
{
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => canExecute?.Invoke() ?? true;
    public void Execute(object? parameter) => execute(parameter);
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
internal sealed class IncidentRow
{
    public IncidentSummaryDto Source { get; }
    public IncidentRow(IncidentSummaryDto source) => Source = source;
    public string CaseCaption => L.F("Detail.Case", CaseId);
    public string SignatureCaption => L.F("Detail.Signature", Signature);
    public string TrustCaption => L.F("Detail.Trust", Trust);
    public string CaseId => Source.CaseId ?? "—";
    public string Time => Source.CapturedUtc.ToLocalTime().ToString("HH:mm:ss");
    public string Date => Source.CapturedUtc.ToLocalTime().ToString("d", L.Culture);
    public string Process => Source.ProcessName ?? L.T("T146");
    public string Pid => Source.Pid.ToString(CultureInfo.InvariantCulture);
    public string FullTime => Source.CapturedUtc.ToLocalTime().ToString("G", L.Culture);
    public bool IsLab => (Source.Action ?? "").Contains("Lab", StringComparison.OrdinalIgnoreCase);
    public string Icon => IsLab ? "flask" : "file";
    public string ActionShort => IsLab ? L.T("T147") : L.T("T016");
    public string StatusLabel => IsLab ? "LAB" : L.T("T088");
    public string Severity => Source.Score >= 85 ? "High" : Source.Score >= 60 ? "Medium" : "Review";
    public string SeverityText => Source.Score >= 85 ? L.T("T148") : Source.Score >= 60 ? L.T("T149") : L.T("T150");
    public int Score => Source.Score;
    public int FileCount => Source.DistinctFiles;
    public string Action => (Source.Action ?? "").Contains("Lab", StringComparison.OrdinalIgnoreCase) ? L.T("T017") : L.T("T016");
    public string Priority => (Source.Priority ?? "").Contains("Critical",StringComparison.OrdinalIgnoreCase) ? L.T("T151") :
        (Source.Priority ?? "").Contains("High",StringComparison.OrdinalIgnoreCase) ? L.T("T152") : L.T("T153");
    public string Reasons => string.Join(Environment.NewLine, (Source.Reasons ?? Array.Empty<string>()).Select(UiMessages.Message));
    public string Signature => Source.SignatureStatus switch
    {
        "Valid" or "ValidCached" => L.T("T154"),
        "NoEmbeddedSignatureOrCatalogOnly" => L.T("T155"),
        _ => Source.SignatureStatus ?? L.T("T037")
    };
    public string Trust => Source.LocalDisposition switch { "Unknown" => L.T("T156"), "ReviewedTrusted" or "Trusted" => L.T("T157"), "BlockedByAdministrator" or "Denied" => L.T("T158"), _ => Source.LocalDisposition ?? L.T("T037") };
    public string Operations => L.F("T159", Source.Writes, Source.Renames, Source.Deletes);
    public string ScopedReview => Source.ScopedTrust is not { } trust ? L.T("T160") :
        (trust.Applies ? L.T("Rule.Context") : L.T("Rule.NotApplied")) + ": " + UiMessages.Message(trust.Reason) + "\n" +
        L.F("Rule.Summary", trust.RuleId ?? L.T("Rule.NoId"), UiMessages.Effect(trust.Effect), UiMessages.YesNo(trust.NotificationQuieted));
    public string Searchable => $"{Process} {Pid} {CaseId} {Reasons} {Source.Priority}";
}
internal sealed record FolderRow(string Path)
{
    public string DisplayName => System.IO.Path.GetFileName(Path.TrimEnd('\\','/')) is string s && s.Length > 0 ? s : Path;
    public string Icon => DisplayName.Equals("Pictures",StringComparison.OrdinalIgnoreCase) ? "picture" : "folder";
    public string Note => L.T("T161");
}
internal sealed record DiagnosticRow(string Name, string Value, string Note);

internal sealed class ScopedRuleRow(ScopedRuleSummaryDto source)
{
    public string Id => source.Id;
    public string Name => source.Name;
    public string Executable => source.ExecutableName;
    public string Sha256 => source.Sha256;
    public string Scope => L.F("T162", source.DirectoryCount, string.Join(", ",source.Operations.Select(UiMessages.Operation)));
    public string Effect => source.Effect=="QuietRepeat" ? L.T("T163") : L.T("T164");
    public string Status => source.State switch {"Configured"=>L.T("T165"),"Expired"=>L.T("T166"),"Disabled"=>L.T("T167"),_=>source.State};
    public string ExpiryCaption => L.F("Rule.Expiry", Expiry);
    public string Expiry => source.ExpiresUtc.ToLocalTime().ToString("G", L.Culture);
    public string Check => source.LastCheckedUtc is DateTime t ? $"{t.ToLocalTime():HH:mm:ss}: {UiMessages.Message(source.LastResult)}" : L.T("T168");
    public string Statistics => L.F("Rule.Stats", source.MatchedIncidents, source.QuietedWarnings, UiMessages.YesNo(source.OneRunOnly));
}
