using System.Globalization;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using RansomGuard.Core;
using RansomGuard.Management;

namespace RansomGuard.Ui.Administration;

// A short-lived elevated window of the SAME UI executable. No console or script bridge.
// Preview/test construction performs no store, SCM, filesystem verification or UAC calls.
internal sealed class AdminWindow : Window
{
    private string _action;
    private readonly string? _initialId;
    private readonly bool _preview;
    internal SetupWizardPane? SetupPane { get; private set; }
    private readonly TextBox _technical = new() { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MaxHeight = 150, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private RuleList? _list;
    private PreparedRule? _prepared;
    private bool _busy, _populating;
    public bool Applied { get; private set; }
    private readonly StackPanel _body = new() { Margin = new Thickness(24) };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 14, 0, 0) };
    private readonly TextBlock _review = new() { TextWrapping = TextWrapping.Wrap, FontSize = 14 };
    private readonly CheckBox _approval = new() { Margin = new Thickness(0, 8, 0, 12) };
    private readonly TextBlock _approvalText = new() { TextWrapping = TextWrapping.Wrap, MaxWidth = 480 };
    private readonly TextBlock _account = new() { TextWrapping = TextWrapping.Wrap };
    private Expander? _advancedContext;
    private Grid? _rulesLayout;
    private readonly Button _verify = new() { Content = L.T("T177"), Margin = new Thickness(0, 0, 10, 0) };
    private readonly Button _apply = new() { Content = L.T("T178"), IsEnabled = false, Margin = new Thickness(0, 0, 10, 0) };
    private readonly TextBox _name = Field(), _exe = Field(), _sid = Field(), _pid = Field(), _hours = Field("8"), _reason = Field();
    private readonly TextBox _roots = new() { AcceptsReturn = true, MinHeight = 96, MaxHeight = 140, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private readonly ComboBox _effect = new() { ItemsSource = new[] { new LanguageOption("AnnotateOnly", L.T("T164")), new LanguageOption("QuietRepeat", L.T("T163")) }, DisplayMemberPath = "Name", SelectedValuePath = "Code", SelectedIndex = 0 };
    private readonly ComboBox _rules = new() { DisplayMemberPath = "Name", SelectedValuePath = "Id", MinWidth = 300 };
    private readonly CheckBox _unsigned = new() { Content = L.T("T179"), Margin = new Thickness(0, 8, 0, 8) };
    private readonly CheckBox _write = new() { Content = L.T("T180"), IsChecked = true, Margin = new Thickness(0, 0, 18, 0) };
    private readonly CheckBox _rename = new() { Content = L.T("T181"), Margin = new Thickness(0, 0, 18, 0) };
    private readonly CheckBox _delete = new() { Content = L.T("T182") };
    private readonly TextBox _maxFiles = Field("16"), _maxWrites = Field("256"), _maxRenames = Field("16"), _maxDeletes = Field("16"), _quiet = Field("120");
    private static TextBox Field(string text = "") => new() { Text = text, MaxLength = 1024, MinHeight = 32 };
    public AdminWindow(string action, string? id, bool preview = false)
    {
        AdminContract.ValidateIntent(action, id);
        _action = action; _initialId = id; _preview = preview;
        if (!preview) RuleAdministration.DemandAdministrator();
        Language = System.Windows.Markup.XmlLanguage.GetLanguage(L.Language);
        Title = L.T("T184"); Width = 910; Height = 850; MinWidth = 640; MinHeight = 520;
        var work = SystemParameters.WorkArea; Width = Math.Min(Width, work.Width - 32); Height = Math.Min(Height, work.Height - 32);
        MinWidth = Math.Min(MinWidth, Width); MinHeight = Math.Min(MinHeight, Height); WindowStartupLocation = WindowStartupLocation.CenterScreen;
        SetResourceReference(BackgroundProperty, "PageBrush"); SetResourceReference(ForegroundProperty, "TextBrush");
        Icon = System.Windows.Media.Imaging.BitmapFrame.Create(new Uri("pack://application:,,,/RansomGuard.Ui;component/Assets/ransomguard.ico"));
        UseLayoutRounding = true;
        if (action is "install" or "start" or "stop" or "restart" or "uninstall" or "state-repair")
        {
            Width = Math.Min(780, work.Width - 32); Height = Math.Min(action is "install" or "state-repair" ? 720 : 540, work.Height - 32);
            Closing += (_, e) => { if (SetupPane?.IsBusy == true) e.Cancel = true; };
            ShowSetup(action, false);
            Loaded += async (_, _) => { if (SetupPane is not null) await SetupPane.LoadAsync(); };
            return;
        }

        var grid = new Grid(); grid.RowDefinitions.Add(new() { Height = GridLength.Auto }); grid.RowDefinitions.Add(new()); grid.RowDefinitions.Add(new() { Height = GridLength.Auto });
        var header = new StackPanel { Margin = new Thickness(24, 22, 24, 12) };
        header.Children.Add(new TextBlock { Text = "RansomGuard", FontSize = 24, FontWeight = FontWeights.SemiBold });
        var notice = new TextBlock { Text = preview ? L.T("T185") : L.T("T186"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) };
        notice.SetResourceReference(ForegroundProperty, "SecondaryBrush"); header.Children.Add(notice); grid.Children.Add(header);
        var scroll = new ScrollViewer { Content = _body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled }; Grid.SetRow(scroll, 1); grid.Children.Add(scroll);
        var footer = new StackPanel { Margin = new Thickness(24, 12, 24, 20) };
        _approval.Content = _approvalText;
        _approvalText.SetResourceReference(ForegroundProperty, "TextBrush");
        footer.Children.Add(_approval);
        var buttons = new WrapPanel(); buttons.Children.Add(_verify); buttons.Children.Add(_apply);
        var close = new Button { Content = L.T("T187"), IsCancel = true }; close.Click += (_, _) => Close(); buttons.Children.Add(close); footer.Children.Add(buttons); footer.Children.Add(_status);
        var details = new Expander { Header = Hint(L.T("Admin.TechnicalDetails")), Content = _technical, Margin = new Thickness(0, 8, 0, 0), IsExpanded = false };
        footer.Children.Add(details);
        var stateButton = new Button { Content = L.T("Setup.ReviewSettings"), Margin = new Thickness(0, 8, 0, 0), HorizontalAlignment = HorizontalAlignment.Left };
        stateButton.Click += async (_, _) => { if (!_busy) { ShowSetup("state-repair", true); if (SetupPane is not null) await SetupPane.LoadAsync(); } };
        footer.Children.Add(stateButton);
        Grid.SetRow(footer, 2); grid.Children.Add(footer); _rulesLayout = grid; Content = grid;
        _approval.Checked += (_, _) => UpdateApply(); _approval.Unchecked += (_, _) => UpdateApply(); _verify.Click += Verify_Click; _apply.Click += Apply_Click;
        Closing += (_, e) => { if (_busy || SetupPane?.IsBusy == true) { e.Cancel = true; _status.Text = L.T("T188"); } };
        BuildRules();
        _roots.MaxLength = 16384; _reason.MaxLength = 400; _name.MaxLength = 80; _pid.MaxLength = 10; _hours.MaxLength = 3;
        foreach (var field in new[] { _name, _exe, _sid, _pid, _hours, _reason, _roots, _maxFiles, _maxWrites, _maxRenames, _maxDeletes, _quiet }) field.TextChanged += (_, _) => Invalidate();
        _effect.SelectionChanged += (_, _) => Invalidate();
        foreach (var box in new[] { _unsigned, _write, _rename, _delete }) { box.Checked += (_, _) => Invalidate(); box.Unchecked += (_, _) => Invalidate(); }
        Loaded += async (_, _) => { if (SetupPane is null) await LoadAsync(); };
    }
    private void Label(string text, UIElement field)
    {
        var l = new TextBlock { Text = text, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 14, 0, 6), TextWrapping = TextWrapping.Wrap };
        _body.Children.Add(l); _body.Children.Add(field);
    }
    private static TextBlock Hint(string text)
    { var t = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 4) }; t.SetResourceReference(ForegroundProperty, "SecondaryBrush"); return t; }
    private void BuildRules()
    {
        _body.Children.Add(Hint(L.T("T189")));
        if (_action != "add")
        {
            Label(L.T("T190"), _rules); _rules.SelectionChanged += (_, _) => FillRule();
            var choices = new WrapPanel();
            foreach (string a in new[] { "edit", "disable", "remove" })
            { var b = new Button { Content = a switch { "edit" => L.T("T191"), "disable" => L.T("T192"), _ => L.T("T193") }, Margin = new Thickness(0, 8, 8, 0) }; b.Click += (_, _) => { _action = a; _prepared = null; _approval.IsChecked = false; UpdateApply(); UpdateMode(); }; choices.Children.Add(b); }
            _body.Children.Add(choices);
        }
        Label(L.T("T194"), _name);
        var row = new Grid(); row.ColumnDefinitions.Add(new()); row.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); row.Children.Add(_exe);
        var browse = new Button { Content = L.T("T195"), Margin = new Thickness(8, 0, 0, 0) }; Grid.SetColumn(browse, 1); row.Children.Add(browse);
        browse.Click += (_, _) => { if (_preview || _action is not ("add" or "edit")) return; var d = new OpenFileDialog { Filter = L.T("Admin.ExeFilter"), CheckFileExists = true }; if (d.ShowDialog(this) == true) _exe.Text = d.FileName; }; Label(L.T("T196"), row);
        var processButton = new Button { Content = L.T("T197"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 8, 0, 0) };
        processButton.Click += ChooseProcess_Click; _body.Children.Add(processButton);
        Label(L.T("RuleUx.Account"), _account);
        var context = new StackPanel();
        context.Children.Add(Hint(L.T("RuleUx.AdvancedAccountHelp")));
        context.Children.Add(Hint(L.T("T198"))); context.Children.Add(_sid);
        context.Children.Add(Hint(L.T("T199"))); context.Children.Add(_pid);
        _advancedContext = new Expander { Header = Hint(L.T("RuleUx.AdvancedContext")), Content = context, IsExpanded = false, Margin = new Thickness(0, 6, 0, 8) };
        _body.Children.Add(_advancedContext);
        Label(L.T("T200"), _roots); AddFolderButton();
        var operations = new WrapPanel(); operations.Children.Add(_write); operations.Children.Add(_rename); operations.Children.Add(_delete); Label(L.T("T201"), operations);
        _body.Children.Add(Hint(L.T("T202")));
        Label(L.T("T203"), _effect); _body.Children.Add(Hint(L.T("T204"))); Label(L.T("T205"), _hours); _body.Children.Add(_unsigned);
        var limits = new WrapPanel();
        foreach (var (text, box) in new[] { (L.T("Admin.Files"), _maxFiles), (L.T("Admin.Writes"), _maxWrites), (L.T("Admin.Renames"), _maxRenames), (L.T("Admin.Deletes"), _maxDeletes), (L.T("Admin.QuietSeconds"), _quiet) })
        { var p = new StackPanel { Width = 130, Margin = new Thickness(0, 0, 10, 0) }; p.Children.Add(Hint(text)); p.Children.Add(box); limits.Children.Add(p); }
        var advanced = new Expander { Header = L.T("T206"), Content = limits, Margin = new Thickness(0, 16, 0, 0) }; _body.Children.Add(advanced);
        Label(L.T("T207"), _reason); Label(L.T("RuleUx.Review"), _review);
        UpdateMode();
    }
    private void ShowSetup(string action, bool returnToRules)
    {
        var pane = new SetupWizardPane(action, _preview); SetupPane = pane; Content = pane;
        pane.Changed += (_, _) => Applied = true;
        pane.CloseRequested += async (_, _) =>
        {
            if (pane.IsBusy) return;
            if (returnToRules && _rulesLayout is not null)
            {
                SetupPane = null; Content = _rulesLayout; Invalidate(); await LoadAsync();
            }
            else Close();
        };
    }
    private void AddFolderButton()
    {
        var add = new Button { Content = L.T("T216"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 0) };
        add.Click += (_, _) =>
        {
            if (_preview || _roots.IsReadOnly) return;
            var picker = new OpenFolderDialog { Multiselect = false, Title = L.T("T217") };
            if (picker.ShowDialog(this) == true) _roots.Text = string.Join(Environment.NewLine, Roots().Append(picker.FolderName).Distinct(StringComparer.OrdinalIgnoreCase));
        }; _body.Children.Add(add);
    }
    private async Task LoadAsync()
    {
        if (_preview)
        {
            _populating = true;
            _name.Text = L.T("Preview.RuleName"); _exe.Text = @"C:\Program Files\Example\example.exe"; _sid.Text = "S-1-5-21-1-2-3-1001";
            _roots.Text = @"C:\Users\Example\Documents\Test"; _reason.Text = L.T("Preview.Only");
            _review.Text = L.T("RuleUx.PreviewSummary");
            _technical.Text = L.F("Preview.AdminReport", new string('A', 64));
            _account.Text = L.T("RuleUx.PreviewAccount");
            _populating = false; _verify.IsEnabled = false; _apply.IsEnabled = false; _approvalText.Text = L.T("Setup.Preview"); return;
        }
        await Busy(async () =>
        {
                _list = null; _rules.ItemsSource = null; _prepared = null; _approval.IsChecked = false;
                _list = await Task.Run(RuleAdministration.List);
                if (_list.State == "UnavailableOrInvalid") throw new IOException(_list.Error);
                _rules.ItemsSource = _list.Rules;
                if (_initialId is not null) _rules.SelectedValue = _initialId;
                else if (_rules.Items.Count > 0) _rules.SelectedIndex = 0;
                if (_action == "add")
                { using var me = WindowsIdentity.GetCurrent(); _sid.Text = me.User?.Value ?? ""; ShowAccount(); _status.Text = L.T("RuleUx.UserWarning"); }
                else if (_rules.SelectedItem is null) _status.Text = L.T("T220");
        });
    }
    private void FillRule()
    {
        if (_rules.SelectedItem is not ScopedTrustRule r) return;
        _populating = true;
        _name.Text = r.Name; _exe.Text = r.ImagePath; _sid.Text = r.UserSid; _roots.Text = string.Join(Environment.NewLine, r.Roots);
        _pid.Text = r.Instance?.Pid.ToString(CultureInfo.InvariantCulture) ?? "";
        _effect.SelectedValue = r.Effect; _reason.Text = ""; _hours.Text = "8";
        _unsigned.IsChecked = r.SignaturePolicy == "ExactUnsignedHash";
        _write.IsChecked = r.Operations.Contains("Write"); _rename.IsChecked = r.Operations.Contains("Rename"); _delete.IsChecked = r.Operations.Contains("Delete");
        _maxFiles.Text = r.MaxDistinctFiles.ToString(CultureInfo.InvariantCulture); _maxWrites.Text = r.MaxWrites.ToString(CultureInfo.InvariantCulture); _maxRenames.Text = r.MaxRenames.ToString(CultureInfo.InvariantCulture); _maxDeletes.Text = r.MaxDeletes.ToString(CultureInfo.InvariantCulture); _quiet.Text = r.QuietSeconds.ToString(CultureInfo.InvariantCulture);
        _review.Text = DescribeRule(r);
        _technical.Text = JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true });
        ShowAccount();
        _populating = false; _prepared = null; _approval.IsChecked = false; UpdateMode();
    }
    private async void ChooseProcess_Click(object sender, RoutedEventArgs e)
    {
        if (_preview || _busy || _action is not ("add" or "edit")) return;
        await Busy(async () =>
        {
            var rows = await Task.Run(RuleAdministration.Processes);
            var list = new ListBox { ItemsSource = rows, DisplayMemberPath = "Display", Margin = new Thickness(12) };
            list.SetResourceReference(Control.BackgroundProperty, "SurfaceBrush");
            list.SetResourceReference(Control.ForegroundProperty, "TextBrush");
            var select = new Button { Content = L.T("T221"), Margin = new Thickness(12), HorizontalAlignment = HorizontalAlignment.Right };
            var dock = new DockPanel(); DockPanel.SetDock(select, Dock.Bottom); dock.Children.Add(select); dock.Children.Add(list);
            var picker = new Window { Owner = this, Title = L.T("T222"), Width = 800, Height = 500, Content = dock, WindowStartupLocation = WindowStartupLocation.CenterOwner };
            picker.SetResourceReference(BackgroundProperty, "PageBrush"); picker.SetResourceReference(ForegroundProperty, "TextBrush");
            select.Click += (_, _) => { if (list.SelectedItem is ProcessChoice) picker.DialogResult = true; };
            if (picker.ShowDialog() == true && list.SelectedItem is ProcessChoice selected)
            {
                _exe.Text = selected.ImagePath; _sid.Text = selected.UserSid; _pid.Text = selected.Pid.ToString(CultureInfo.InvariantCulture);
                if (string.IsNullOrWhiteSpace(_name.Text)) _name.Text = selected.Name;
                ShowAccount(); _status.Text = L.T("RuleUx.ProcessSelected");
            }
        });
    }
    private void Invalidate() { if (_populating) return; _prepared = null; _approval.IsChecked = false; UpdateApply(); }
    private string[] Roots() => _roots.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    private static int Number(TextBox field) => int.Parse(field.Text, CultureInfo.InvariantCulture);
    private RuleDraft Draft() => new(_name.Text.Trim(), _exe.Text.Trim(), _sid.Text.Trim(), Roots(),
        new[] { _write.IsChecked == true ? "Write" : null, _rename.IsChecked == true ? "Rename" : null, _delete.IsChecked == true ? "Delete" : null }.OfType<string>().ToArray(),
        Number(_hours), _effect.SelectedValue?.ToString() ?? "AnnotateOnly", _reason.Text.Trim(), _unsigned.IsChecked == true,
        string.IsNullOrWhiteSpace(_pid.Text) ? null : Number(_pid), Number(_maxFiles), Number(_maxWrites), Number(_maxRenames), Number(_maxDeletes), Number(_quiet));
    private string? SelectedId => (_rules.SelectedItem as ScopedTrustRule)?.Id;
    private void UpdateMode()
    {
        if (_action == "rules") _action = "edit";
        bool editing = _action is "add" or "edit";
        foreach (var field in new[] { _name, _exe, _sid, _pid, _hours, _maxFiles, _maxWrites, _maxRenames, _maxDeletes, _quiet }) field.IsReadOnly = !editing;
        _roots.IsReadOnly = !editing;
        _effect.IsEnabled = editing;
        foreach (var box in new[] { _unsigned, _write, _rename, _delete }) box.IsEnabled = editing;
        _verify.Visibility = editing ? Visibility.Visible : Visibility.Collapsed;
        _apply.Content = _action switch { "add" or "edit" => L.T("T224"), "disable" => L.T("T225"), "remove" => L.T("T226"), "install" => L.T("T227"), "start" => L.T("T228"), "stop" => L.T("T229"), "restart" => L.T("T230"), _ => L.T("T231") };
        UpdateApply();
    }
    private void UpdateApply()
    {
        bool editing = _action is "add" or "edit";
        _approvalText.Text = L.T(editing ? "RuleUx.ApproveRule" : _action == "disable" ? "RuleUx.DisableConsent" : "RuleUx.RemoveConsent");
        _approval.IsEnabled = !_busy && (!editing || _prepared is not null) && !_preview;
        _apply.IsEnabled = !_preview && !_busy && _approval.IsChecked == true &&
            (editing ? _prepared is not null : SelectedId is not null) &&
            (_action is not ("edit" or "disable" or "remove") || SelectedId is not null) &&
            (_action is not ("disable" or "remove") || !string.IsNullOrWhiteSpace(_reason.Text));
    }
    private async void Verify_Click(object sender, RoutedEventArgs e)
    {
        if (_preview || _busy) return;
        if (_action is not ("add" or "edit")) return;
        // Re-verifying may produce a different hash even if form text did not change.
        // Never carry the acknowledgement over to a newly prepared rule.
        _approval.IsChecked = false; _prepared = null;
        await Busy(async () =>
        {
            var draft = Draft(); string? id = _action == "edit" ? SelectedId ?? throw new IOException("Choose a rule.") : null;
            _prepared = await Task.Run(() => RuleAdministration.Prepare(draft, id));
            _review.Text = DescribeRule(_prepared.Rule) + "\n" + L.T("Admin.Signature") + UiMessages.State(_prepared.Image.Signature.Status);
            _technical.Text = JsonSerializer.Serialize(_prepared.Rule, new JsonSerializerOptions { WriteIndented = true });
            _status.Text = L.T("RuleUx.Ready");
        });
    }
    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (_preview || _busy || !_apply.IsEnabled) return;
        await Busy(async () =>
        {
            if (_approval.IsChecked != true) return;
            string confirmation = AdminContract.Confirmation(_action, _prepared?.Rule.Sha256);
            if (_action is "add" or "edit")
            {
                var prepared = _prepared ?? throw new IOException("Verify first.");
                await Task.Run(() => RuleAdministration.Save(prepared, confirmation));
            }
            else if (_action is "disable" or "remove")
            {
                var id = SelectedId ?? throw new IOException("Choose a rule.");
                var digest = _list?.Digest ?? throw new IOException("Reload rules."); var reason = _reason.Text.Trim();
                await Task.Run(() => RuleAdministration.Change(_action, id, digest, reason, confirmation));
            }
            Applied = true; _prepared = null; _approval.IsChecked = false;
            _status.Text = L.T("T235");
            if (_action is "add" or "edit" or "disable" or "remove")
            { _list = await Task.Run(RuleAdministration.List); _rules.ItemsSource = _list.Rules; }

        });
    }
    private async Task Busy(Func<Task> action)
    {
        if (_busy) return;
        _busy = true; _body.IsEnabled = false; _verify.IsEnabled = false; _approval.IsEnabled = false; UpdateApply(); _status.Text = L.T("T236"); _technical.Clear();
        try { await action(); }
        catch (Exception ex) { _prepared = null; _approval.IsChecked = false; _status.Text = UiMessages.ErrorSummary(ex); _technical.Text = ex.ToString(); }
        finally { _busy = false; _body.IsEnabled = true; _approval.IsEnabled = true; _verify.IsEnabled = !_preview; UpdateApply(); }
    }
    private static string DescribeRule(ScopedTrustRule rule) => L.F("RuleUx.Summary", rule.Name,
        Path.GetFileName(rule.ImagePath), string.Join(", ", rule.Roots), UiMessages.Effect(rule.Effect), rule.ExpiresUtc.ToLocalTime().ToString("g", L.Culture));
    private void ShowAccount()
    {
        try
        {
            var value = new SecurityIdentifier(_sid.Text).Translate(typeof(NTAccount)).Value;
            _account.Text = L.F("RuleUx.AccountValue", value, string.IsNullOrWhiteSpace(_pid.Text) ? L.T("RuleUx.FutureRuns") : L.T("RuleUx.ThisRun"));
        }
        catch (Exception ex) when (ex is ArgumentException or IdentityNotMappedException or System.Security.SecurityException)
        { _account.Text = L.T("RuleUx.AccountUnavailable"); }
    }
}
