using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using RansomGuard.Core;
using RansomGuard.Management;
using Microsoft.Win32;

namespace RansomGuard.Ui.Administration;

// One visible, already elevated administrative window. Every change requires a
// distinct reviewed click; inspecting/choosing folders has no system side effects.
internal sealed class SetupWizardPane : UserControl
{
    private enum Page { Checking, Folders, Review, Reset, Working, Done, Error }
    private readonly bool _preview;
    private string _intent;
    private Page _page;
    private SetupReview? _review;
    private ManagedServiceStatus? _service;
    private StateStoreReport? _state;
    private readonly List<string> _folders = new();
    private readonly StackPanel _body = new();
    private readonly TextBlock _title = Text("", 25, "TextBrush", true);
    private readonly TextBlock _subtitle = Text("", 14, "SecondaryBrush");
    private readonly TextBlock _step = Text("", 12, "AccentBrush", true);
    private readonly TextBlock _footerNote = Text("", 12, "SecondaryBrush");
    private readonly Button _back = new();
    private readonly Button _primary = new();
    private readonly Button _close = new();
    private readonly Expander _details;
    private readonly TextBox _technical;
    private string _error = "", _errorDetails = "", _doneTitle = "", _doneMessage = "", _archive = "";
    private bool _automatic, _startAfter = true, _acknowledged, _installedHere, _loadStarted, _attemptedInstall;
    private string _workingKey = "Setup.Checking";
    public bool IsBusy { get; private set; }
    public bool Applied { get; private set; }
    public event EventHandler? CloseRequested;
    public event EventHandler? Changed;

    internal SetupWizardPane(string action, bool preview)
    {
        if (action is not ("install" or "start" or "stop" or "restart" or "uninstall" or "state-repair"))
            throw new ArgumentException("Unsupported setup action.");
        _intent = action; _preview = preview;
        SetResourceReference(BackgroundProperty, "PageBrush");
        SetResourceReference(ForegroundProperty, "TextBrush");
        FontFamily = new FontFamily("Segoe UI"); FontSize = 14;
        var layout = new Grid();
        layout.RowDefinitions.Add(new() { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new());
        layout.RowDefinitions.Add(new() { Height = GridLength.Auto });
        var heading = new StackPanel { Margin = new Thickness(28, 24, 28, 10) };
        heading.Children.Add(_step); _title.Margin = new Thickness(0, 9, 0, 5); heading.Children.Add(_title);
        heading.Children.Add(_subtitle); layout.Children.Add(heading);
        var stack = new StackPanel { Margin = new Thickness(28, 8, 28, 16) }; stack.Children.Add(_body);
        _technical = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = 180, FontSize = 12,
            FontFamily = new FontFamily("Consolas"), IsReadOnlyCaretVisible = true };
        _technical.SetResourceReference(ForegroundProperty, "SecondaryBrush");
        _details = new Expander { Header = Text(L.T("Setup.Details"), 13, "SecondaryBrush"),
            Content = _technical, IsExpanded = false, Margin = new Thickness(0, 18, 0, 0),
            Name = "SetupTechnicalDetails" };
        _details.SetResourceReference(ForegroundProperty, "SecondaryBrush"); stack.Children.Add(_details);
        var scroll = new ScrollViewer { Content = stack, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        Grid.SetRow(scroll, 1); layout.Children.Add(scroll);
        var bottom = new StackPanel { Margin = new Thickness(28, 14, 28, 22) };
        _footerNote.Margin = new Thickness(0, 0, 0, 12); bottom.Children.Add(_footerNote);
        var actions = new Grid(); actions.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        actions.ColumnDefinitions.Add(new()); actions.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        actions.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        _back.Content = L.T("Setup.Back"); _back.Click += Back_Click; actions.Children.Add(_back);
        _primary.Name = "SetupPrimaryAction"; _primary.Style = (Style)FindResource("PrimaryButton");
        _primary.Margin = new Thickness(8, 0, 10, 0); _primary.Click += Primary_Click;
        Grid.SetColumn(_primary, 2); actions.Children.Add(_primary);
        _close.Name = "SetupCancelAction"; _close.Content = L.T("Setup.Cancel");
        _close.IsCancel = true; _close.Click += (_, _) => { if (!IsBusy) CloseRequested?.Invoke(this, EventArgs.Empty); };
        Grid.SetColumn(_close, 3); actions.Children.Add(_close); bottom.Children.Add(actions);
        var border = new Border { BorderThickness = new Thickness(0, 1, 0, 0), Child = bottom };
        border.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        Grid.SetRow(border, 2); layout.Children.Add(border); Content = layout;
        _page = Page.Checking; Render();
    }
    internal async Task LoadAsync()
    {
        if (_loadStarted) return; _loadStarted = true;
        if (_preview) { SetPreviewScenario(_intent == "install" ? "folders" : _intent == "state-repair" ? "reset" : "review"); return; }
        await InspectAsync();
    }
    private async Task InspectAsync()
    {
        await BusyAsync("Setup.Checking", async () =>
        {
            _review = null; _acknowledged = false;
            _service = await Task.Run(ServiceAdministration.Query);
            if (!_service.QuerySucceeded) throw new IOException(_service.Error);
            _state = await Task.Run(StateStoreAdministration.Inspect);
            // Unknown owners/redirected storage are never offered automatic migration.
            _review = ReviewSnapshot(false, false);
            if (_intent == "state-repair") { RouteState(); return; }
            if (_intent == "install" && !_service.Installed) { _page = Page.Folders; return; }
            bool installAlreadyExists = _intent == "install" && _service.Installed;
            if (!_service.Installed) throw new InvalidOperationException("Setup.NotInstalled");
            string installedPath = _service.ImagePath;
            bool paired = await Task.Run(() => ServiceAdministration.MatchesInstalledPeer(installedPath, PackageIdentity.ServiceSha256()));
            if (!paired) throw new InvalidOperationException("Setup.DifferentPackage");
            if (installAlreadyExists)
            {
                if (_service.State == "Running")
                { Complete("Setup.AlreadyRunning", "Setup.CheckOverview"); return; }
                _intent = "start"; // no reinstall; startup still needs a new reviewed click
            }
            _review = ReviewSnapshot(true, true);
            if (_state.Exists && (!_state.PrivateAcl || _state.LegacyUntrusted) && _intent == "start") RouteState();
            else _page = Page.Review;
        });
    }
    private SetupReview ReviewSnapshot(bool packageVerified, bool foldersVerified)
    {
        var s = _service; var r = _state;
        var storage = r is null ? SetupStorage.Unknown : !r.Exists ? SetupStorage.Missing : (r.PrivateAcl && !r.LegacyUntrusted) ? SetupStorage.Private : SetupStorage.NeedsReview;
        bool canArchive = r is not null && (!r.Exists || r.OwnerSid is "S-1-5-18" or "S-1-5-32-544");
        return new(s?.QuerySucceeded == true, s?.Installed == true, s?.State ?? "Unknown",
            packageVerified, foldersVerified, storage, canArchive, r?.Revision);
    }
    private void RouteState()
    {
        if (_state is { PrivateAcl: true, LegacyUntrusted: false })
        { Complete("Setup.SettingsReady", "Setup.NoResetRequired"); return; }
        if (_review is not { CanArchive: true, ServiceQuerySucceeded: true } ||
            (_review.Installed && _review.ServiceState != "Stopped"))
            throw new InvalidOperationException("Setup.ResetBlocked");
        _page = Page.Reset;
    }
    private async Task ReviewFoldersAsync()
    {
        if (_preview) { SetPreviewScenario("review"); return; }
        string[] folders = _folders.ToArray();
        await BusyAsync("Setup.Checking", async () =>
        {
            _review = null;
            string package = ServiceAdministration.GetPackageRoot(AppContext.BaseDirectory);
            string hash = PackageIdentity.ServiceSha256();
            await Task.Run(() => ServiceAdministration.ReviewInstallInput(package, hash, folders));
            _service = await Task.Run(ServiceAdministration.Query);
            _state = await Task.Run(StateStoreAdministration.Inspect);
            _review = ReviewSnapshot(true, true); _acknowledged = false;
            if (_state.Exists && (!_state.PrivateAcl || _state.LegacyUntrusted)) RouteState(); else _page = Page.Review;
        });
    }
    private async void Primary_Click(object sender, RoutedEventArgs e)
    {
        if (IsBusy || !_primary.IsEnabled) return;
        if (_page == Page.Done) { CloseRequested?.Invoke(this, EventArgs.Empty); return; }
        if (_page == Page.Error) { if (!_preview) await InspectAsync(); return; }
        if (_page == Page.Folders) { await ReviewFoldersAsync(); return; }
        if (_preview) return; // synthetic UI never crosses a native mutation boundary
        if (_page == Page.Reset)
        {
            if (!SetupReviewPolicy.CanReset(_review, _acknowledged, IsBusy)) return;
            string revision = _review!.StorageRevision!;
            await BusyAsync("Setup.Preparing", async () =>
            {
                // Consent was given to RESET ONLY, not to installation or startup.
                var result = await Task.Run(() => StateStoreAdministration.Recover(revision, AdminContract.Confirmation("state-repair")));
                MarkChanged(); _archive = result.Archive ?? ""; _acknowledged = false;
                _state = await Task.Run(StateStoreAdministration.Inspect);
                _service = await Task.Run(ServiceAdministration.Query);
                _review = ReviewSnapshot(false, false);
                if (_intent == "state-repair") { Complete("Setup.SettingsPrepared", "Setup.PreparedNoStart"); return; }
                if (_intent == "install") _page = Page.Folders; // preserve selection; require a NEW review and click
                else
                {
                    string installedPath = _service.ImagePath;
                    bool paired = await Task.Run(() => ServiceAdministration.MatchesInstalledPeer(installedPath, PackageIdentity.ServiceSha256()));
                    if (!paired) throw new InvalidOperationException("Setup.DifferentPackage");
                    _review = ReviewSnapshot(true, true); _page = Page.Review;
                }
            });
            return;
        }
        if (_page != Page.Review) return;
        if (_intent == "install")
        {
            if (!SetupReviewPolicy.CanInstall(_review, IsBusy)) return;
            string[] folders = _folders.ToArray(); bool automatic = _automatic, startAfter = _startAfter;
            await BusyAsync("Setup.Installing", async () =>
            {
                string package = ServiceAdministration.GetPackageRoot(AppContext.BaseDirectory);
                string hash = PackageIdentity.ServiceSha256();
                _attemptedInstall = true;
                await Task.Run(() => ServiceAdministration.Install(package, hash, folders, automatic, AdminContract.Confirmation("install")));
                _installedHere = true; MarkChanged();
                if (startAfter)
                {
                    _workingKey = "Setup.Starting"; Render();
                    await Task.Run(() => ServiceAdministration.Execute("start", AdminContract.Confirmation("start")));
                }
                _service = await Task.Run(ServiceAdministration.Query);
                if (!_service.QuerySucceeded || (startAfter && _service.State != "Running")) throw new IOException("Setup.StartNotConfirmed");
                Complete(startAfter ? "Setup.InstalledRunning" : "Setup.InstalledStopped", startAfter ? "Setup.CheckOverview" : "Setup.CanStartLater");
            });
        }
        else
        {
            if (!SetupReviewPolicy.CanControl(_review, _intent, _acknowledged, IsBusy)) return;
            string action = _intent;
            await BusyAsync("Setup.Applying", async () =>
            {
                await Task.Run(() => ServiceAdministration.Execute(action, AdminContract.Confirmation(action)));
                MarkChanged(); _service = await Task.Run(ServiceAdministration.Query);
                if (!_service.QuerySucceeded) throw new IOException(_service.Error);
                Complete(action switch { "start" or "restart" => "Setup.Started", "stop" => "Setup.Stopped", _ => "Setup.Unregistered" },
                    action is "start" or "restart" ? "Setup.CheckOverview" : action == "stop" ? "Setup.NoMonitoring" : "Setup.FilesPreserved");
            });
        }
    }
    private void MarkChanged() { Applied = true; Changed?.Invoke(this, EventArgs.Empty); }
    private void Complete(string titleKey, string messageKey)
    { _doneTitle = titleKey; _doneMessage = messageKey; _page = Page.Done; }
    private async Task BusyAsync(string progressKey, Func<Task> work)
    {
        if (IsBusy) return;
        IsBusy = true; _workingKey = progressKey; _page = Page.Working; _details.IsExpanded = false;
        _error = _errorDetails = ""; Render();
        try { await work(); }
        catch (Exception ex)
        {
            // Applied operations are not undone by an error in a later step.
            _review = null; _acknowledged = false; _page = Page.Error; _errorDetails = ex.ToString();
            _error = _installedHere ? L.T("Setup.InstalledButFailed") :
                ex.Message.StartsWith("Setup.", StringComparison.Ordinal) ? L.T(ex.Message) : UiMessages.ErrorSummary(ex);
            try
            {
                _service = await Task.Run(ServiceAdministration.Query);
                if (_attemptedInstall && _service.Installed) MarkChanged();
            }
            catch { /* Unknown state is not reported as success. Original error stays in details. */ }
        }
        finally { IsBusy = false; Render(); }
    }
    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (IsBusy) return;
        _acknowledged = false; _review = null;
        if (_intent == "install") { _page = Page.Folders; Render(); }
        else CloseRequested?.Invoke(this, EventArgs.Empty);
    }
    private void Render()
    {
        _body.Children.Clear();
        _step.Text = _preview ? L.T("Setup.Preview") : L.T("Setup.Elevated");
        _title.Text = L.T(_page switch
        {
            Page.Folders => "Setup.Title", Page.Reset => "Setup.ResetTitle", Page.Review => _intent == "install" ? "Setup.ReadyTitle" : "Setup." + _intent + ".Title",
            Page.Working or Page.Checking => _workingKey, Page.Done => _doneTitle, _ => "Setup.ErrorTitle"
        });
        _subtitle.Text = L.T(_page switch
        {
            Page.Folders => "Setup.ChooseHelp", Page.Reset => _state?.Exists == true ? "Setup.ResetHelp" : "Setup.FirstTimeStore", Page.Review => _intent == "install" ? "Setup.ReviewHelp" : "Setup." + _intent + ".Help",
            Page.Done => _doneMessage, Page.Error => "Setup.ErrorHelp", _ => "Setup.Wait"
        });
        _footerNote.Text = L.T(_page == Page.Working ? "Setup.DoNotClose" : "Setup.AuditBoundary");
        _back.Visibility = (_page is Page.Review or Page.Reset) && _intent == "install" ? Visibility.Visible : Visibility.Collapsed;
        _back.IsEnabled = !IsBusy;
        _close.Content = L.T("Setup.Cancel"); _close.IsEnabled = !IsBusy;
        _close.Visibility = _page == Page.Done ? Visibility.Collapsed : Visibility.Visible;
        _primary.Visibility = _page is Page.Working or Page.Checking ? Visibility.Collapsed : Visibility.Visible;
        _primary.Content = L.T(_page switch
        {
            Page.Folders => "Setup.Next", Page.Reset => _state?.Exists == true ? "Setup.ResetAction" : "Setup.CreateAction",
            Page.Review => _intent == "install" ? (_startAfter ? "Setup.InstallAndStart" : "Setup.InstallOnly") : "Setup." + _intent + ".Action",
            Page.Done => "Setup.Done", _ => "Setup.Retry"
        });
        switch (_page)
        {
            case Page.Folders: RenderFolders(); break;
            case Page.Review: RenderReview(); break;
            case Page.Reset: RenderReset(); break;
            case Page.Working: case Page.Checking:
                _body.Children.Add(new ProgressBar { IsIndeterminate = true, Height = 5, Margin = new Thickness(0, 22, 0, 20) });
                _body.Children.Add(Text(L.T("Setup.WaitDetails"), 14, "SecondaryBrush")); break;
            case Page.Done:
                AddCard("check", "Setup.Result", _subtitle.Text, "SuccessBrush");
                if (_archive.Length > 0) AddCard("folder", "Setup.OldData", L.T("Setup.OldDataHelp"), "InfoBrush");
                break;
            case Page.Error:
                AddCard("alert", "Setup.WhatHappened", _error, "WarningBrush");
                _body.Children.Add(Text(L.T("Setup.RetryHelp"), 14, "SecondaryBrush")); break;
        }
        _technical.Text = TechnicalText();
        _details.Visibility = _page is Page.Folders or Page.Working or Page.Checking ? Visibility.Collapsed : Visibility.Visible;
        UpdatePrimary();
        AutomationProperties.SetName(_primary, _primary.Content?.ToString() ?? "");
    }
    private void RenderFolders()
    {
        if (_archive.Length > 0) AddCard("check", "Setup.SettingsPrepared", L.T("Setup.ContinueReview"), "SuccessBrush");
        var label = Text(L.T("Setup.Folders"), 16, "TextBrush", true); label.Margin = new Thickness(0, 6, 0, 12); _body.Children.Add(label);
        if (_folders.Count == 0) AddCard("folder", "Setup.NoFolders", L.T("Setup.NoFoldersHelp"), "InfoBrush");
        foreach (string path in _folders.ToArray())
        {
            var row = new Grid { Margin = new Thickness(0, 0, 0, 8) };
            row.ColumnDefinitions.Add(new()); row.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
            row.Children.Add(Text(path, 14, "TextBrush"));
            var remove = new Button { Content = L.T("Setup.RemoveFolder"), Padding = new Thickness(12, 5, 12, 5), MinHeight = 32 };
            Grid.SetColumn(remove, 1); row.Children.Add(remove);
            remove.Click += (_, _) => { _folders.Remove(path); _review = null; Render(); }; _body.Children.Add(row);
        }
        var add = new Button { Content = L.T("Setup.AddFolder"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 18) };
        add.Click += (_, _) =>
        {
            if (_preview || IsBusy) return;
            var dialog = new OpenFolderDialog { Title = L.T("Setup.Folders"), Multiselect = true };
            var owner = Window.GetWindow(this) ?? throw new InvalidOperationException("Setup window unavailable.");
            if (dialog.ShowDialog(owner) == true)
                foreach (var path in dialog.FolderNames)
                    if (_folders.Count < 64 && !_folders.Contains(path, StringComparer.OrdinalIgnoreCase)) _folders.Add(path);
            _review = null; Render();
        }; _body.Children.Add(add);
        var auto = Check("Setup.Automatic", _automatic); auto.Checked += (_, _) => _automatic = true; auto.Unchecked += (_, _) => _automatic = false; _body.Children.Add(auto);
        var start = Check("Setup.StartAfter", _startAfter); start.Checked += (_, _) => _startAfter = true; start.Unchecked += (_, _) => _startAfter = false; _body.Children.Add(start);
    }
    private void RenderReview()
    {
        if (_intent == "install")
        {
            AddCard("folder", "Setup.SelectedFolders", string.Join(Environment.NewLine, _folders), "InfoBrush");
            AddCard("server", "Setup.InstallPlan", L.T(_startAfter ? "Setup.PlanStart" : "Setup.PlanNoStart"), "AccentBrush");
            _body.Children.Add(Text(L.T(_automatic ? "Setup.AutoOn" : "Setup.AutoOff"), 14, "SecondaryBrush"));
        }
        else
        {
            AddCard(_intent == "stop" ? "info" : "server", "Setup.CurrentStatus",
                _service is null ? L.T("T037") : UiMessages.State(_service.State), "InfoBrush");
            if (_intent is "stop" or "restart" or "uninstall")
            {
                var consent = Check("Setup." + _intent + ".Consent", _acknowledged);
                consent.Checked += (_, _) => { _acknowledged = true; UpdatePrimary(); };
                consent.Unchecked += (_, _) => { _acknowledged = false; UpdatePrimary(); }; _body.Children.Add(consent);
            }
            if (!SetupReviewPolicy.CanControl(_review, _intent, true, false))
                AddCard("alert", "Setup.ActionUnavailable", L.T("Setup.ControlUnavailable"), "WarningBrush");
        }
    }
    private void RenderReset()
    {
        if (_state?.Exists == true)
        {
            AddCard("file", "Setup.Documents", L.T("Setup.DocumentsHelp"), "SuccessBrush");
            AddCard("rules", "Setup.Rules", L.T("Setup.RulesHelp"), "WarningBrush");
            AddCard("history", "Setup.OldData", L.T("Setup.OldDataHelp"), "InfoBrush");
            _body.Children.Add(Text(L.T("Setup.NoMalwareClaim"), 13, "SecondaryBrush"));
        }
        else _body.Children.Add(Text(L.T("Setup.FirstTimeStore"), 14, "SecondaryBrush"));
        var check = Check(_state?.Exists == true ? "Setup.ResetConsent" : "Setup.CreateConsent", _acknowledged);
        check.Name = "SetupResetConsent";
        check.Checked += (_, _) => { _acknowledged = true; UpdatePrimary(); };
        check.Unchecked += (_, _) => { _acknowledged = false; UpdatePrimary(); }; _body.Children.Add(check);
    }
    private void UpdatePrimary()
    {
        _primary.IsEnabled = !IsBusy && (_page switch
        {
            Page.Folders => _folders.Count is > 0 and <= 64,
            Page.Reset => !_preview && SetupReviewPolicy.CanReset(_review, _acknowledged, IsBusy),
            Page.Review => !_preview && (_intent == "install" ? SetupReviewPolicy.CanInstall(_review, IsBusy) : SetupReviewPolicy.CanControl(_review, _intent, _acknowledged, IsBusy)),
            Page.Done => true, Page.Error => !_preview, _ => false
        });
    }
    private string TechnicalText()
    {
        string service = _service is null ? "" : L.F("Admin.State", UiMessages.State(_service.State), _service.Account, UiMessages.State(_service.StartMode), _service.Pid, _service.ImagePath, _service.Error);
        string state = _state is null ? "" : L.F("State.Status", L.T(!_state.Exists ? "State.Missing" : (_state.PrivateAcl && !_state.LegacyUntrusted) ? "State.Valid" : "State.Unsafe"),
            _state.Path, _state.OwnerSid, UiMessages.YesNo(_state.InheritanceProtected), string.Join(Environment.NewLine,
            _state.Entries.Select(a => L.F("State.AclEntry", a.Type, a.Sid, a.Rights, UiMessages.YesNo(a.Inherited)))));
        return string.Join("\n\n", new[] { service, state, _archive, _errorDetails }.Where(x => !string.IsNullOrEmpty(x)));
    }
    private void AddCard(string icon, string titleKey, string description, string tone)
    {
        var row = new Grid(); row.ColumnDefinitions.Add(new() { Width = new GridLength(36) }); row.ColumnDefinitions.Add(new());
        var image = new Controls.SvgIcon { Kind = icon, Width = 22, Height = 22, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 10, 0) };
        image.SetResourceReference(Controls.SvgIcon.StrokeProperty, tone); row.Children.Add(image);
        var words = new StackPanel(); Grid.SetColumn(words, 1); row.Children.Add(words);
        words.Children.Add(Text(L.T(titleKey), 15, "TextBrush", true));
        var note = Text(description, 14, "SecondaryBrush"); note.Margin = new Thickness(0, 5, 0, 0); words.Children.Add(note);
        var card = new Border { CornerRadius = new CornerRadius(10), Padding = new Thickness(16), Margin = new Thickness(0, 0, 0, 12), BorderThickness = new Thickness(1), Child = row };
        card.SetResourceReference(Border.BackgroundProperty, "SurfaceBrush"); card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush"); _body.Children.Add(card);
    }
    private static TextBlock Text(string text, double size, string brush, bool bold = false)
    {
        var block = new TextBlock { Text = text, FontSize = size, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal, TextWrapping = TextWrapping.Wrap };
        block.SetResourceReference(TextBlock.ForegroundProperty, brush); return block;
    }
    private static CheckBox Check(string key, bool value)
    {
        var caption = Text(L.T(key), 14, "TextBrush"); caption.MaxWidth = 480;
        return new CheckBox { Content = caption, IsChecked = value, Margin = new Thickness(0, 8, 0, 8), HorizontalAlignment = HorizontalAlignment.Left };
    }
    internal void SetPreviewScenario(string scenario)
    {
        if (!_preview) throw new InvalidOperationException("Synthetic scene only.");
        _service = new(true, _intent != "install" && _intent != "state-repair", _intent is "stop" or "restart" ? "Running" : "Stopped", "", "LocalSystem", "Manual", 0, null);
        _state = new(@"C:\ProgramData\RansomGuardV03", true, scenario != "reset", "S-1-5-32-544", true, "PreviewRevision", []);
        if (_folders.Count == 0) _folders.Add(@"C:\Users\Example\Documents");
        _review = ReviewSnapshot(true, true); _acknowledged = false;
        _page = scenario switch { "folders" => Page.Folders, "reset" => Page.Reset, "working" => Page.Working,
            "done" => Page.Done, "error" => Page.Error, _ => Page.Review };
        _doneTitle = "Setup.InstalledRunning"; _doneMessage = "Setup.CheckOverview";
        _error = L.T("Setup.InstalledButFailed"); _errorDetails = "Preview only. No native operation was requested.";
        _details.IsExpanded = false; Render();
    }
    internal object AssertPreviewLayout()
    {
        if (!_preview || Applied || _details.IsExpanded) throw new InvalidOperationException("Unexpected administrative preview state.");
        if ((_page is Page.Reset or Page.Review) && _primary.IsEnabled) throw new InvalidOperationException("Preview cannot apply operations.");
        var owner = Window.GetWindow(this) ?? throw new InvalidOperationException("Preview owner unavailable.");
        foreach(var button in new[] { _primary, _close })
        {
            if (!button.IsVisible) continue;
            var bounds = button.TransformToAncestor(owner).TransformBounds(new Rect(new Point(), button.RenderSize));
            if (bounds.Left < 0 || bounds.Top < 0 || bounds.Right > owner.ActualWidth + 1 || bounds.Bottom > owner.ActualHeight + 1)
                throw new InvalidOperationException("A setup action button is outside the window.");
        }
        return new { page = _page.ToString(), technicalDetailsCollapsed = true, tokenTextEntry = false,
            nativeMutations = false, title = _title.Text, primary = _primary.Content?.ToString(), primaryEnabled = _primary.IsEnabled,
            footerButtonsInsideWindow = true };
    }
}
