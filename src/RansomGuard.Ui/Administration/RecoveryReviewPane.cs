using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using RansomGuard.Management;

namespace RansomGuard.Ui.Administration;

/// <summary>
/// Short-lived elevated, read-only production recovery review.
/// Preview mode is synthetic-only and never queries ProgramData, SCM, rollback evidence, or native state.
/// </summary>
internal sealed class RecoveryReviewPane : UserControl
{
    private readonly bool _preview;
    private readonly ComboBox _sessions = new()
    {
        DisplayMemberPath = nameof(ProductionRecoverySessionSummary.SessionId),
        MinWidth = 360,
        HorizontalAlignment = HorizontalAlignment.Stretch
    };
    private readonly Button _refresh = new() { Margin = new Thickness(0, 0, 8, 0) };
    private readonly Button _plan = new() { Margin = new Thickness(0, 0, 8, 0) };
    private readonly Button _close = new();
    private readonly TextBlock _status = Text("", 13, "SecondaryBrush");
    private readonly StackPanel _sessionBody = new();
    private readonly StackPanel _planBody = new();
    private ProductionRecoverySessionSummary[] _sessionRows = [];
    private ProductionRecoveryPlanSummary? _currentPlan;

    internal bool IsBusy { get; private set; }
    internal event EventHandler? CloseRequested;

    internal RecoveryReviewPane(bool preview)
    {
        _preview = preview;

        _refresh.Content = L.T("RecoveryReview.Refresh");
        _plan.Content = L.T("RecoveryReview.BuildPlan");
        _close.Content = L.T("RecoveryReview.Close");

        var root = new Grid();
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new());
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });

        var header = new StackPanel { Margin = new Thickness(24, 22, 24, 12) };
        header.Children.Add(Text(L.T("RecoveryReview.Title"), 24, "TextBrush", true));
        header.Children.Add(Text(
            preview ? L.T("RecoveryReview.Preview") : L.T("RecoveryReview.Subtitle"),
            14,
            "SecondaryBrush"));
        root.Children.Add(header);

        var body = new StackPanel { Margin = new Thickness(24, 8, 24, 20) };
        body.Children.Add(Text(L.T("RecoveryReview.Sessions"), 16, "TextBrush", true));
        body.Children.Add(_sessions);

        var commands = new WrapPanel { Margin = new Thickness(0, 10, 0, 12) };
        commands.Children.Add(_refresh);
        commands.Children.Add(_plan);
        body.Children.Add(commands);

        body.Children.Add(_sessionBody);
        body.Children.Add(_planBody);

        var scroll = new ScrollViewer
        {
            Content = body,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };
        Grid.SetRow(scroll, 1);
        root.Children.Add(scroll);

        var footer = new StackPanel { Margin = new Thickness(24, 8, 24, 20) };
        footer.Children.Add(_status);
        footer.Children.Add(new Border { Height = 8, Background = Brushes.Transparent });
        footer.Children.Add(_close);
        Grid.SetRow(footer, 2);
        root.Children.Add(footer);

        Content = root;

        _sessions.SelectionChanged += (_, _) =>
        {
            _currentPlan = null;
            RenderSelectedSession();
            RenderPlan();
            UpdateButtons();
        };
        _refresh.Click += async (_, _) => await LoadAsync();
        _plan.Click += async (_, _) => await BuildSelectedPlanAsync();
        _close.Click += (_, _) => CloseRequested?.Invoke(this, EventArgs.Empty);
        UpdateButtons();
    }

    internal async Task LoadAsync()
    {
        if (_preview)
        {
            SetPreviewScenario("sessions");
            return;
        }

        await BusyAsync(async () =>
        {
            _currentPlan = null;
            _sessionRows = await Task.Run(ProductionRecoveryAdministration.ListSessions);
            _sessions.ItemsSource = _sessionRows;
            _sessions.SelectedIndex = _sessionRows.Length == 0 ? -1 : 0;
            _status.Text = _sessionRows.Length == 0
                ? L.T("RecoveryReview.NoSessions")
                : L.F("RecoveryReview.SessionCount", _sessionRows.Length);
            RenderSelectedSession();
            RenderPlan();
        });
    }

    private async Task BuildSelectedPlanAsync()
    {
        if (_sessions.SelectedItem is not ProductionRecoverySessionSummary selected || !selected.CanPlan)
            return;

        if (_preview)
        {
            SetPreviewScenario("plan");
            return;
        }

        await BusyAsync(async () =>
        {
            _currentPlan = await Task.Run(() => ProductionRecoveryAdministration.BuildPlan(selected.SessionId));
            _status.Text = L.T("RecoveryReview.PlanReady");
            RenderPlan();
        });
    }

    private async Task BusyAsync(Func<Task> work)
    {
        if (IsBusy) return;
        IsBusy = true;
        UpdateButtons();
        _status.Text = L.T("RecoveryReview.Working");
        try
        {
            await work();
        }
        catch (Exception ex)
        {
            _currentPlan = null;
            _status.Text = UiMessages.ErrorSummary(ex);
            RenderPlan();
        }
        finally
        {
            IsBusy = false;
            UpdateButtons();
        }
    }

    private void RenderSelectedSession()
    {
        _sessionBody.Children.Clear();
        if (_sessions.SelectedItem is not ProductionRecoverySessionSummary selected)
        {
            _sessionBody.Children.Add(Card(
                L.T("RecoveryReview.NoSelection"),
                L.T("RecoveryReview.SelectSession"),
                "InfoBrush"));
            return;
        }

        var description = string.Join(Environment.NewLine, new[]
        {
            L.F("RecoveryReview.Lifecycle", selected.LifecycleState),
            L.F("RecoveryReview.Held", UiMessages.YesNo(selected.IsHeld)),
            L.F("RecoveryReview.Created", FormatDate(selected.CreatedUtc)),
            L.F("RecoveryReview.Completed", FormatDate(selected.CompletedUtc)),
            L.F("RecoveryReview.Faulted", FormatDate(selected.FaultedUtc)),
            L.F("RecoveryReview.Evidence", selected.LastRecordSha256),
            selected.Note
        });

        _sessionBody.Children.Add(Card(
            selected.SessionId,
            description,
            selected.CanPlan ? "SuccessBrush" : "InfoBrush"));

        if (!selected.CanPlan)
            _sessionBody.Children.Add(Card(
                L.T("RecoveryReview.NotEligible"),
                selected.Note,
                "WarningBrush"));
    }

    private void RenderPlan()
    {
        _planBody.Children.Clear();
        if (_currentPlan is null) return;

        _planBody.Children.Add(Text(L.T("RecoveryReview.PlanTitle"), 16, "TextBrush", true));
        _planBody.Children.Add(Card(
            _currentPlan.PlanId,
            string.Join(Environment.NewLine, new[]
            {
                L.F("RecoveryReview.PlanLifecycle", _currentPlan.LifecycleState),
                L.F("RecoveryReview.PlanEvidence", _currentPlan.JournalEvidenceSha256),
                L.F("RecoveryReview.Planned", _currentPlan.PlannedUtc.ToLocalTime().ToString("g", L.Culture)),
                L.F("RecoveryReview.Counts",
                    _currentPlan.ReadyCount,
                    _currentPlan.ReviewCount,
                    _currentPlan.BlockedCount,
                    _currentPlan.InformationalCount),
                _currentPlan.SafetyNote
            }),
            "AccentBrush"));

        foreach (var action in _currentPlan.Actions)
        {
            var path = string.IsNullOrWhiteSpace(action.RelatedPath)
                ? action.PrimaryPath
                : action.PrimaryPath + Environment.NewLine + action.RelatedPath;
            var detail = string.Join(Environment.NewLine, new[]
            {
                L.F("RecoveryReview.ActionState", action.Index, action.Kind, action.State),
                path,
                L.F("RecoveryReview.ActionEvidence", action.EvidenceSequence, action.EvidenceRecordSha256),
                action.Reason
            }.Where(x => !string.IsNullOrWhiteSpace(x)));
            _planBody.Children.Add(Card(
                L.F("RecoveryReview.Action", action.Index),
                detail,
                action.State == "Ready" ? "SuccessBrush" : action.State == "Blocked" ? "WarningBrush" : "InfoBrush"));
        }

        if (_currentPlan.ActionsTruncated)
            _planBody.Children.Add(Card(
                L.T("RecoveryReview.Truncated"),
                L.F("RecoveryReview.TruncatedHelp", _currentPlan.TotalActions, _currentPlan.Actions.Length),
                "WarningBrush"));
    }

    private void UpdateButtons()
    {
        _refresh.IsEnabled = !IsBusy;
        _plan.IsEnabled = !IsBusy &&
            _sessions.SelectedItem is ProductionRecoverySessionSummary { CanPlan: true };
        _close.IsEnabled = !IsBusy;
    }

    private static string FormatDate(DateTime? value) =>
        value is null ? L.T("RecoveryReview.None") : value.Value.ToLocalTime().ToString("g", L.Culture);

    private static Border Card(string title, string description, string tone)
    {
        var words = new StackPanel();
        words.Children.Add(Text(title, 15, "TextBrush", true));
        var detail = Text(description, 13, "SecondaryBrush");
        detail.Margin = new Thickness(0, 5, 0, 0);
        words.Children.Add(detail);

        var card = new Border
        {
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(16),
            Margin = new Thickness(0, 0, 0, 12),
            BorderThickness = new Thickness(1),
            Child = words
        };
        card.SetResourceReference(Border.BackgroundProperty, "SurfaceBrush");
        card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        _ = tone; // Tone is intentionally descriptive only until recovery review gets dedicated icons.
        return card;
    }

    private static TextBlock Text(string text, double size, string brush, bool bold = false)
    {
        var block = new TextBlock
        {
            Text = text,
            FontSize = size,
            FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
            TextWrapping = TextWrapping.Wrap
        };
        block.SetResourceReference(TextBlock.ForegroundProperty, brush);
        return block;
    }

    internal void SetPreviewScenario(string scenario)
    {
        if (!_preview) throw new InvalidOperationException("Synthetic scene only.");

        _sessionRows =
        [
            new(
                "production-20260926-001",
                "Completed",
                true,
                DateTime.UtcNow.AddHours(-3),
                DateTime.UtcNow.AddHours(-2),
                null,
                new string('A', 64),
                true,
                L.T("RecoveryReview.PreviewCompleted")),
            new(
                "production-20260926-002",
                "Active",
                false,
                DateTime.UtcNow.AddMinutes(-20),
                null,
                null,
                new string('B', 64),
                false,
                L.T("RecoveryReview.PreviewActive"))
        ];
        _sessions.ItemsSource = _sessionRows;
        _sessions.SelectedIndex = scenario == "active" ? 1 : 0;

        _currentPlan = scenario == "plan"
            ? new ProductionRecoveryPlanSummary(
                "production-20260926-001",
                "Completed",
                "plan-preview-001",
                new string('C', 64),
                DateTime.UtcNow,
                1,
                1,
                1,
                0,
                3,
                false,
                [
                    new(0, "FullFile", "Ready", @"C:\Users\Example\Documents\report.docx", "", new string('D', 64), 11, false, L.T("RecoveryReview.PreviewReady")),
                    new(1, "Rename", "Review", @"C:\Users\Example\Documents\draft.txt", @"C:\Users\Example\Documents\draft.locked", new string('E', 64), 12, true, L.T("RecoveryReview.PreviewReview")),
                    new(2, "Delete", "Blocked", @"C:\Users\Example\Documents\old.xlsx", "", new string('F', 64), 13, false, L.T("RecoveryReview.PreviewBlocked"))
                ],
                L.T("RecoveryReview.PreviewSafety"))
            : null;

        _status.Text = L.T("RecoveryReview.Preview");
        RenderSelectedSession();
        RenderPlan();
        UpdateButtons();
    }

    internal object AssertPreviewLayout()
    {
        if (!_preview || IsBusy)
            throw new InvalidOperationException("Unexpected recovery-review preview state.");
        if (_sessionRows.Length == 0)
            throw new InvalidOperationException("Recovery-review preview must use synthetic sessions.");
        return new
        {
            preview = true,
            syntheticSessions = _sessionRows.Length,
            planVisible = _currentPlan is not null,
            nativeStateQueries = false,
            mutationControls = false,
            planEnabled = _plan.IsEnabled
        };
    }
}
