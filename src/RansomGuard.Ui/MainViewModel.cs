using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows.Input;
using System.Windows;
using System.Windows.Threading;
using RansomGuard.Core;

namespace RansomGuard.Ui;

internal sealed partial class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly LocalApiClient _api = new();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly List<IncidentRow> _allIncidents = new();
    private UiPreferences _preferences = UiPreferences.Load();
    private string _rulesFingerprint = "";
    private ScopedRuleSetDto? _scopedRuleSet;
    public ObservableCollection<ScopedRuleRow> ScopedRules { get; } = new();
    public bool HasScopedRules => ScopedRules.Count > 0;
    public string ScopedRulesState => !IsConnected ? L.T("T000") :
        _scopedRuleSet?.StoreState switch
        {
            "Loaded" => L.F("T001", ScopedRules.Count),
            "Empty" => L.T("T002"),
            "UnavailableOrInvalid" => L.T("T003"),
            _ => L.T("T004")
        };
    private GuardStatusDto? _status;
    private DiagnosticsDto? _diagnostics;
    private string _selectedPage = "overview", _search = "", _filter = "All", _error = "", _errorDetail = "";
    private string _connectionState = "connecting", _toast = "";
    private IncidentRow? _selectedIncident;
    private bool _disposed;
    private DateTime? _lastRefresh;
    private Task? _liveTask;
    private readonly object _connectionGate = new();
    private CancellationTokenSource? _connection;
    private RecoverySummaryDto? _recovery;
    private long _liveSequence;
    private string _liveInstance = "";
    public string RecoveryStateText
    {
        get
        {
            string value=(_recovery?.State??"NotStarted") switch
            {
                "NotStarted"=>L.T("T006"),
                "ScanningDump"=>L.T("T007"),
                "ValidatingCandidates"=>L.T("T008"),
                "WritingVerifiedCopies"=>L.T("T009"),
                "RecoveredAllSelected"=>L.T("T010"),
                "KeyNotFound"=>L.T("T011"),
                "UnsupportedFormat"=>L.T("T012"),
                _=>UiMessages.State(_recovery?.State)
            };
            return !IsConnected&&_recovery is not null ? L.T("T013")+value : value;
        }
    }
    public string RecoveryAlgorithm => _recovery?.Algorithm ?? L.T("T014");
    public string RecoveryCounts => _recovery is null ? "0 / 0" : $"{_recovery.DecryptedFiles} / {_recovery.SelectedFiles}";
    public string RecoveryNote => _recovery?.Note is string note ? UiMessages.Message(note) : L.T("Recovery.Default");
    public string LiveStatus => IsConnected ? L.F("Live.Status", _liveSequence) : L.T("Live.Disconnected");

    private string _period = "All";
    public bool IsPreview { get; }
    public ObservableCollection<IncidentRow> Incidents { get; } = new();
    public ObservableCollection<IncidentRow> RecentIncidents { get; } = new();
    public ObservableCollection<FolderRow> Folders { get; } = new();
    public ObservableCollection<FolderRow> OverviewFolders { get; } = new();
    public ObservableCollection<DiagnosticRow> DiagnosticRows { get; } = new();
    public LanguageOption[] Filters => [new("All", L.T("T005")), new("Audit", L.T("T016")), new("Lab", L.T("T017"))];
    public LanguageOption[] Periods => [new("All", L.T("T015")), new("Today", L.T("T018")), new("SevenDays", L.T("T019"))];
    public double[] TextScales { get; } = [1.0, 1.1, 1.2];
    public ICommand RefreshCommand { get; }
    public ICommand NavigateCommand { get; }
    public ICommand ThemeCommand { get; }
    public ICommand ClearSelectionCommand { get; }
    public event PropertyChangedEventHandler? PropertyChanged;

    public MainViewModel(bool preview = false)
    {
        IsPreview = preview;
        L.Select(_preferences.Language);
        RefreshCommand = new RelayCommand(async _ => await RefreshAsync(), () => !IsBusy);
        NavigateCommand = new RelayCommand(p => SelectedPage = p?.ToString() ?? "overview");
        ThemeCommand = new RelayCommand(p => ThemeChoice = p?.ToString() ?? "Dark");
        ClearSelectionCommand = new RelayCommand(_ => SelectedIncident = null);
        ThemeManager.Apply(_preferences.Theme, _preferences.TextScale);
        if (IsPreview) LoadPreview();
    }
    public LanguageOption[] Languages { get; } = [new("uk-UA", "Українська"), new("en-US", "English")];
    public System.Windows.Markup.XmlLanguage UiLanguage => System.Windows.Markup.XmlLanguage.GetLanguage(L.Language);
    public string LanguageChoice
    {
        get => _preferences.Language;
        set
        {
            if (!L.Supported(value) || value == _preferences.Language) return;
            string? selected = SelectedIncident?.CaseId;
            _preferences = _preferences with { Language = value };
            L.Select(value);
            if (IsPreview) LoadPreview();
            else
            {
                FilterIncidents();
                var folderPaths = Folders.Select(x=>x.Path).ToArray();
                Folders.Clear(); foreach (string path in folderPaths) Folders.Add(new FolderRow(path));
                OverviewFolders.Clear(); foreach (var row in Folders.Take(4)) OverviewFolders.Add(row);
                RecentIncidents.Clear(); foreach (var row in _allIncidents.Take(5)) RecentIncidents.Add(new IncidentRow(row.Source));
                _rulesFingerprint = "";
                if (_diagnostics is not null) BuildDiagnostics(_diagnostics);
                if (IsConnected) ApplyMonitoringStatus();
                else if (HasError) Error = L.T("Live.Lost");
            }
            SelectedIncident = selected is null ? null : Incidents.FirstOrDefault(x => x.CaseId == selected);
            Toast = "";
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
            if (!IsPreview && !_preferences.Save()) Toast = L.T("Language.SaveFailed");
        }
    }
    public string SelectedPage { get => _selectedPage; set { if (Set(ref _selectedPage,value)) Raise(nameof(PageTitle),nameof(PageDescription)); } }
    public string PageTitle => SelectedPage switch { "incidents" => L.T("T020"), "folders" => L.T("T021"), "recovery" => L.T("T022"),
        "diagnostics" => L.T("T023"), "rules" => L.T("T024"), "settings" => L.T("T025"), "about" => L.T("T026"), _ => L.T("T027") };
    public string PageDescription => SelectedPage switch {
        "incidents" => L.T("T028"),
        "folders" => L.T("T029"),
        "recovery" => L.T("T030"),
        "rules" => L.T("T031"),
        "diagnostics" => L.T("T032"),
        "settings" => L.T("T033"),
        "about" => L.T("T034"),
        _ => L.T("T035") };
    public string Version => typeof(MainViewModel).Assembly.GetName().Version?.ToString() ?? "0.7.1.0";
    public string RootCountCaption => L.F("Folders.Count", RootCount);
    public string CanaryCountCaption => L.F("Canary.Count", CanaryCount);
    public string UiVersionCaption => L.F("About.UIVersion", Version);
    public string ServiceVersionCaption => L.F("About.ServiceVersion", ServiceVersion);
    public string ServiceVersion => IsConnected ? _status?.Version ?? "—" : "—";
    public string ConnectionState { get => _connectionState; private set { if(Set(ref _connectionState,value)) RaiseComputed(); } }
    public bool IsConnected => ConnectionState is "connected" or "preview" or "degraded";
    public bool IsMonitorRunning => IsConnected && MonitoringHealth.IsRunning(_status?.Monitor);
    public bool HasMonitorFault => IsConnected && _status?.Monitor?.State == "Failed";
    public string FolderState => IsMonitorRunning ? L.T("T016") : HasMonitorFault ? L.T("T036") : L.T("T037");
    public bool IsBusy => false;
    public bool HasData => _status is not null;
    public bool IsStale => HasData && !IsConnected;
    public bool HasError => Error.Length > 0;
    public string Error { get => _error; private set { if(Set(ref _error,value)) Raise(nameof(HasError)); } }
    public string ErrorDetail { get => _errorDetail; private set => Set(ref _errorDetail,value); }
    public string Toast { get => _toast; set { if(Set(ref _toast,value)) Raise(nameof(HasToast)); } }
    public bool HasToast => Toast.Length > 0;
    public string ConnectionText => ConnectionState switch { "connected" => L.T("T038"), "degraded" => L.T("T038"), "preview" => L.T("T039"), "connecting" => L.T("T040"), _ => L.T("T041") };
    public string ConnectionHint => IsConnected ? L.T("T042") : L.T("T043");
    public string HeroTitle => HasMonitorFault ? L.T("T044") : IsMonitorRunning ? L.T("T045") : IsConnected ? L.T("T046") : IsBusy ? L.T("T047") : L.T("T048");
    public string HeroBody => HasMonitorFault
        ? L.T("T049")
        : IsMonitorRunning
        ? L.T("T050")
        : L.T("T051");
    public string ModeBadge => HasMonitorFault ? L.T("T052") : IsMonitorRunning ? L.T("T053") : L.T("T054");
    public string ServiceValue => IsConnected ? L.T("T055") : L.T("T056");
    public string Uptime => IsConnected && _status is not null ? FormatDuration(_status.UptimeSeconds) : "—";
    public string RootCount => IsConnected ? (_status?.ProtectedRootCount.ToString() ?? "—") : "—";
    public string CanaryCount => IsConnected ? (_status?.CanaryCount.ToString() ?? "—") : "—";
    public string IncidentCount => IsConnected ? (_status?.IncidentCount.ToString() ?? "—") : "—";
    public string DriverValue => !IsConnected ? L.T("T037") : _status?.Minifilter.State switch
    { "NotInstalled" => L.T("T057"), "Stopped" => L.T("T058"), "Running" => L.T("T059"), "StartPending" => L.T("T060"), _ => L.T("T037") };
    public string DriverNote => IsConnected && _status?.Minifilter.Running == true
        ? L.T("T061")
        : L.T("T062");
    public string P95 => IsMonitorRunning && _diagnostics?.Telemetry.ObservedUtc is not null ? L.F("T063", _diagnostics.Telemetry.P95Ms) : "—";
    public string Heartbeat => IsConnected ? _status?.LastHeartbeatUtc?.ToLocalTime().ToString("HH:mm:ss") ?? L.T("T064") : "—";
    public string LastRefresh => _lastRefresh is null ? L.T("T065") : L.F("T066", _lastRefresh.Value.ToLocalTime()) + (IsStale ? L.T("T067") : "");
    public string FooterNote => IsPreview ? L.T("T068") : L.T("T069");
    public string EventSummary => L.F("T070", Incidents.Count, _allIncidents.Count) + (IsStale ? L.T("T071") : "");
    public string EventCoverage => L.T("T072");
    public bool HasIncidents => Incidents.Count > 0;
    public bool HasRecent => RecentIncidents.Count > 0;
    public bool HasFolders => Folders.Count > 0 && IsConnected;
    public string EmptyTitle => HasMonitorFault ? L.T("T073") : IsConnected ? L.T("T074") : L.T("T075");
    public string EmptyBody => HasMonitorFault ? L.T("T076") : IsConnected ? L.T("T077") : L.T("T078");
    public string FolderHint => HasMonitorFault ? L.T("T079") : !IsConnected ? L.T("T080")
        : HasFolders ? L.T("T081")
        : L.T("T082");

    public string ConnectionCaption => HasMonitorFault ? L.T("T083") : IsPreview ? L.T("T084") : IsConnected ? L.T("T085") : L.T("T086");
    public string ModeValue => HasMonitorFault ? L.T("T087") : IsMonitorRunning ? L.T("T088") : IsConnected ? L.T("T089") : L.T("T037");
    public string ModeDetail => HasMonitorFault ? L.F("T090", _status?.Monitor?.ErrorCode)
        : IsMonitorRunning ? L.T("T091") : IsConnected ? L.T("T092") : L.T("T093");
    public string DriverSummary => IsConnected ? L.T("T094") : L.T("T093");
    public string StartedText => IsConnected && _status is not null ? L.F("T095", _status.ServiceStartedUtc.ToLocalTime()) : L.T("T093");
    public string HeartbeatRelative {
        get {
            if(!IsConnected || _status?.LastHeartbeatUtc is not DateTime heartbeat) return L.T("T037");
            double seconds=Math.Max(0,(DateTime.UtcNow-heartbeat).TotalSeconds);
            if(seconds<10)return L.T("T096");
            return seconds<60 ? L.F("T097", seconds) : L.F("T098", Math.Floor(seconds/60));
        }
    }
    public string HeartbeatDate => IsConnected ? _status?.LastHeartbeatUtc?.ToLocalTime().ToString("G", L.Culture) ?? L.T("T099") : L.T("T093");
    public string ResolvedPathsValue => IsMonitorRunning && _diagnostics?.Telemetry.ObservedUtc is not null ? _diagnostics.Telemetry.PathsResolved.ToString("N0") : "—";
    public string AuditCount => IsConnected ? _allIncidents.Count(x=>x.Source.Action=="AuditOnly").ToString() : "—";
    public string LabCount => IsConnected ? _allIncidents.Count(x=>x.IsLab).ToString() : "—";
    public string FooterSummary => HasMonitorFault ? L.T("T100") : IsPreview ? L.T("T101") : IsStale ? L.T("T102") : L.T("T103");

    public string Search { get => _search; set { if(Set(ref _search,value)) FilterIncidents(); } }
    public string Filter { get => _filter; set { if(value is not ("All" or "Audit" or "Lab")) return; if(Set(ref _filter,value)) FilterIncidents(); } }
    public string Period { get => _period; set { if(value is not ("All" or "Today" or "SevenDays")) return; if(Set(ref _period,value)) FilterIncidents(); } }
    public IncidentRow? SelectedIncident { get => _selectedIncident; set { if(Set(ref _selectedIncident,value)) Raise(nameof(HasSelection)); } }
    public bool HasSelection => SelectedIncident is not null;
    public string ThemeChoice
    {
        get => _preferences.Theme;
        set { if(value is not ("Dark" or "Light" or "System") || value==_preferences.Theme) return; _preferences=_preferences with {Theme=value}; ApplyPreferences(); Raise(nameof(ThemeChoice)); }
    }
    public double TextScale
    {
        get => _preferences.TextScale;
        set { if(value is < 1 or > 1.2 || value==_preferences.TextScale) return; _preferences=_preferences with {TextScale=value}; ApplyPreferences(); Raise(nameof(TextScale)); }
    }
    public void ReapplySystemTheme() => ThemeManager.Apply(_preferences.Theme, _preferences.TextScale);
    private void ApplyPreferences()
    {
        ReapplySystemTheme();
        if (!IsPreview && !_preferences.Save()) Toast=L.T("T104");
    }
    public void StartLive()
    {
        if(_disposed||IsPreview||_liveTask is not null)return;
        _liveTask=Task.Run(()=>LiveLoopAsync(_lifetime.Token));
    }
    public Task RefreshAsync()
    {
        // Manual refresh renews the subscription; no periodic status polling.
        if(_disposed||IsPreview)return Task.CompletedTask;
        lock(_connectionGate)_connection?.Cancel();
        StartLive();
        return Task.CompletedTask;
    }
    private async Task LiveLoopAsync(CancellationToken token)
    {
        int failures=0;
        while(!token.IsCancellationRequested)
        {
            using var connection=CancellationTokenSource.CreateLinkedTokenSource(token);
            lock(_connectionGate)_connection=connection;
            try
            {
                await _api.SubscribeAsync(async frame=>
                {
                    await Application.Current.Dispatcher.InvokeAsync(()=>
                    {
                        if(!_disposed)ApplyLiveFrame(frame);
                    },DispatcherPriority.DataBind,token);
                    failures=0;
                },connection.Token).ConfigureAwait(false);
            }
            catch(OperationCanceledException) when(token.IsCancellationRequested){break;}
            catch(Exception ex) when(ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException
                or JsonException or System.ComponentModel.Win32Exception or ArgumentException)
            {
                if(!token.IsCancellationRequested)
                    await Application.Current.Dispatcher.InvokeAsync(()=>
                    {
                        if(_disposed)return;
                        ConnectionState="offline";
                        Error=L.T("Live.Lost");
                        ErrorDetail=$"{ex.GetType().Name}: {ex.Message}";
                        Raise(nameof(LiveStatus));
                    },DispatcherPriority.DataBind,token);
            }
            finally{lock(_connectionGate)if(ReferenceEquals(_connection,connection))_connection=null;}
            if(token.IsCancellationRequested)break;
            // User-requested renewal is immediate. Otherwise retry with capped backoff.
            if(!connection.IsCancellationRequested)
            {
                failures=Math.Min(failures+1,5);
                try{await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(10000,250*(1<<failures))),token).ConfigureAwait(false);}
                catch(OperationCanceledException){break;}
            }
        }
    }
    private void ApplyLiveFrame(LiveFrame frame)
    {
        _liveSequence=frame.Sequence;_liveInstance=frame.InstanceId;
        _status=frame.Status;_lastRefresh=DateTime.UtcNow;
        if(frame.Recovery is not null)_recovery=frame.Recovery;
        // Collection rebuilds happen only for the changed section, not for heartbeat frames.
        if(frame.Diagnostics is not null){_diagnostics=frame.Diagnostics;BuildDiagnostics(frame.Diagnostics);}
        if(frame.Incidents is not null)
        {
            string? selected=SelectedIncident?.CaseId;
            _allIncidents.Clear();
            _allIncidents.AddRange(frame.Incidents.Take(50).OrderByDescending(x=>x.CapturedUtc).Select(x=>new IncidentRow(x)));
            FilterIncidents();
            if(selected is not null)SelectedIncident=Incidents.FirstOrDefault(x=>x.CaseId==selected);
            RecentIncidents.Clear();foreach(var row in _allIncidents.Take(5))RecentIncidents.Add(row);
        }
        var roots=(frame.Status.MonitoredRoots??Array.Empty<string>()).Where(x=>!string.IsNullOrWhiteSpace(x)).Take(100).ToArray();
        if(!Folders.Select(x=>x.Path).SequenceEqual(roots,StringComparer.OrdinalIgnoreCase))
        {
            Folders.Clear();foreach(var path in roots)Folders.Add(new FolderRow(path));
            OverviewFolders.Clear();foreach(var folder in Folders.Take(4))OverviewFolders.Add(folder);
        }
        ConnectionState=MonitoringHealth.IsRunning(frame.Status.Monitor)?"connected":"degraded";
        ApplyMonitoringStatus();
        Raise(nameof(LiveStatus),nameof(RecoveryStateText),nameof(RecoveryAlgorithm),nameof(RecoveryCounts),nameof(RecoveryNote));
    }
    private void ApplyMonitoringStatus()
    {
        var monitor = _status?.Monitor;
        if (monitor is { State: "Failed" })
        {
            Error=L.F("T105", monitor.ErrorCode);
            ErrorDetail=$"{monitor.ErrorCode}: {monitor.ErrorMessage}\n{monitor.RecoveryHint}";
        }
        else if (!MonitoringHealth.IsRunning(monitor))
        {
            Error=L.T("T106");
            ErrorDetail=monitor is null ? L.T("T107") : UiMessages.State(monitor.State);
        }
        else { Error=""; ErrorDetail=""; }
        RaiseComputed();
    }
    private void ApplySnapshot(GuardStatusDto status, IncidentSummaryDto[] incidents, DiagnosticsDto diagnostics)
    {
        _status=status; _diagnostics=diagnostics; _lastRefresh=DateTime.UtcNow;
        string? selected=SelectedIncident?.CaseId;
        _allIncidents.Clear();
        _allIncidents.AddRange(incidents.Where(x => x is not null).Take(50).OrderByDescending(x=>x.CapturedUtc).Select(x=>new IncidentRow(x)));
        FilterIncidents();
        if(selected is not null) SelectedIncident=Incidents.FirstOrDefault(x=>x.CaseId==selected);
        RecentIncidents.Clear();
        foreach(var row in _allIncidents.Take(5)) RecentIncidents.Add(row);
        Folders.Clear();
        foreach(var path in (status.MonitoredRoots ?? Array.Empty<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Take(100))
            Folders.Add(new FolderRow(path));
        OverviewFolders.Clear();
        foreach(var folder in Folders.Take(4)) OverviewFolders.Add(folder);
        BuildDiagnostics(diagnostics);
        RaiseComputed();
    }
    private void FilterIncidents()
    {
        Incidents.Clear();
        var start=Period=="Today" ? DateTime.Today : Period=="SevenDays" ? DateTime.Today.AddDays(-6) : DateTime.MinValue;
        foreach(var row in _allIncidents.Where(x =>
            (string.IsNullOrWhiteSpace(Search) || x.Searchable.Contains(Search,StringComparison.OrdinalIgnoreCase)) &&
            (Filter=="All" || (Filter=="Lab" ? x.IsLab : !x.IsLab)) && x.Source.CapturedUtc.ToLocalTime()>=start))
            Incidents.Add(new IncidentRow(row.Source));
        if(SelectedIncident is not null && !Incidents.Contains(SelectedIncident)) SelectedIncident=null;
        Raise(nameof(HasIncidents),nameof(EventSummary));
    }
    private void BuildDiagnostics(DiagnosticsDto d)
    {
        _scopedRuleSet=d.ScopedRules;
        string fingerprint=JsonSerializer.Serialize(d.ScopedRules?.Rules)+d.ScopedRules?.StoreDigest+d.ScopedRules?.StoreState;
        if(fingerprint!=_rulesFingerprint)
        {
            _rulesFingerprint=fingerprint;
            ScopedRules.Clear();
            foreach(var row in (d.ScopedRules?.Rules ?? Array.Empty<ScopedRuleSummaryDto>()).Take(128)) ScopedRules.Add(new ScopedRuleRow(row));
        }
        Raise(nameof(ScopedRulesState),nameof(HasScopedRules));
        var t=d.Telemetry;
        bool observed=MonitoringHealth.IsRunning(d.Monitor) && t.ObservedUtc is not null;
        string Count(long value)=>observed ? value.ToString("N0") : L.T("T037");
        string Ms(double value)=>observed ? L.F("T108", value) : L.T("T037");
        DiagnosticRows.Clear();
        DiagnosticRows.Add(new(L.T("T109"), UiMessages.State(d.Monitor?.State), L.T("T110")));
        DiagnosticRows.Add(new(L.T("T087"), d.Monitor?.ErrorCode ?? "—", d.Monitor?.ErrorMessage is string monitorError ? UiMessages.Message(monitorError) : L.T("T111")));
        DiagnosticRows.Add(new(L.T("T112"), d.Monitor?.SessionName ?? "—", L.T("T113")));
        if (d.Monitor?.RecoveryHint is string hint)
            DiagnosticRows.Add(new(L.T("T114"), L.T("T023"), UiMessages.Message(hint)));
        DiagnosticRows.Add(new(L.T("T115"),d.Runtime,L.T("T116")));
        DiagnosticRows.Add(new(L.T("T117"),d.Os,L.T("T118")));
        DiagnosticRows.Add(new(L.T("T119"),observed ? t.EventsLost?.ToString("N0") ?? L.T("T037") : L.T("T037"),L.T("T120")));
        DiagnosticRows.Add(new(L.T("T121"),Count(t.QueueDropped),L.T("T122")));
        DiagnosticRows.Add(new(L.T("T123"),Count(t.PathsUnresolved),L.T("T124")));
        DiagnosticRows.Add(new(L.T("T125"),Count(t.PathsResolved),L.T("T126")));
        DiagnosticRows.Add(new(L.T("T127"),Ms(t.P50Ms),L.T("T128")));
        DiagnosticRows.Add(new(L.T("T129"),Ms(t.P95Ms),L.T("T128")));
        DiagnosticRows.Add(new(L.T("T130"),$"{Ms(t.P99Ms)} / {Ms(t.MaxMs)}",L.T("T131")));
        DiagnosticRows.Add(new(L.T("T132"),Count(t.IncidentQueueDropped),L.T("T133")));
        DiagnosticRows.Add(new(L.T("T134"),Count(t.TruncatedWindows),L.T("T135")));
    }
    public string DiagnosticSummary() => JsonSerializer.Serialize(new {
        uiVersion=Version, demo=IsPreview, connection=ConnectionState, liveSequence=_liveSequence, liveInstance=_liveInstance, lastSuccessfulRefreshUtc=_lastRefresh,
        status=_status, diagnostics=_diagnostics, error=ErrorDetail
    },new JsonSerializerOptions {WriteIndented=true});
    public string ExportVisibleEvents() => JsonSerializer.Serialize(new {
        product="RansomGuard", uiVersion=Version, demo=IsPreview, exportedUtc=DateTime.UtcNow,
        stale=IsStale, scope=EventCoverage, items=Incidents.Select(x=>x.Source).ToArray()
    },new JsonSerializerOptions {WriteIndented=true});
    private void LoadPreview()
    {
        var now=DateTime.UtcNow;
        var monitor=new MonitoringHealthDto("Running",now,"DEMO-NOT-A-REAL-SESSION");
        ApplySnapshot(
            new GuardStatusDto("RansomGuard","0.7.1.0",now.AddMinutes(-48),2880,"AuditOnly",false,false,
                new("NotInstalled",false,false,"Demo"),3,6,5,now,"Demo",
                [@"C:\Users\Demo\Desktop",@"C:\Users\Demo\Documents",@"C:\Users\Demo\Pictures"], monitor),
            [
                new("DEMO-003",now.AddMinutes(-3),4201,"RansomGuard.Simulator.exe",100,"Review",3,18,2,0,
                    "NoEmbeddedSignatureOrCatalogOnly","Unknown","LabOnly",[L.T("T136")]),
                new("DEMO-002",now.AddMinutes(-12),8704,"example-editor.exe",65,"Review",8,24,3,0,
                    "Unknown","Unknown","AuditOnly",[L.T("T137")]),
                new("DEMO-001",now.AddMinutes(-26),4912,"example-backup.exe",50,"Review",14,48,0,0,
                    "Valid","Unknown","AuditOnly",[L.T("T138")]),
                new("DEMO-004",now.AddMinutes(-32),5112,"sample-import.exe",45,"Review",4,12,1,0,
                    "Unknown","Unknown","AuditOnly",[L.T("Preview.NoScan")]),
                new("DEMO-005",now.AddMinutes(-40),6220,"sample-sync.exe",40,"Review",6,18,0,0,
                    "Unknown","Unknown","AuditOnly",[L.T("Preview.NoScan")])
            ],
            new DiagnosticsDto("0.7.1.0",".NET 10","Windows 11 · demo",true,LocalApiContract.PipeName,"Read-only demo",
                new(now,0,0,0,0,0,12480,124,210,980,1430,2100),["Demo"], monitor,
                    new ScopedRuleSetDto("Loaded",1,"DEMO-NOT-REAL",now,
                        [new("DEMO-RULE","UI preview only","example-backup.exe",new string('0',64),true,now.AddHours(8),["Write"],1,
                            "AnnotateOnly",false,"Configured",null,"NotChecked",0,0)],"Synthetic UI fixture only")));
        ConnectionState="preview"; Error=""; ErrorDetail="";
    }
    public void SetPreviewEtwFailure()
    {
        var status = _status;
        var diagnostics = _diagnostics;
        if (!IsPreview || status is null || diagnostics is null) return;
        var fault=MonitoringHealth.Failed(new System.Runtime.InteropServices.COMException(
            "Synthetic ERROR_NO_SYSTEM_RESOURCES; no ETW operation performed.", unchecked((int)0x800705AA)),
            "DEMO-NOT-A-REAL-SESSION", DateTime.UtcNow);
        ApplySnapshot(status with { Monitor=fault, ProtectionMode="MonitoringUnavailable", LastHeartbeatUtc=DateTime.UtcNow },
            _allIncidents.Select(x=>x.Source).ToArray(),
            diagnostics with { Monitor=fault, Telemetry=new(null,null,0,0,0,0,0,0,0,0,0,0) });
        ConnectionState="degraded";
        ApplyMonitoringStatus();
    }
    public void RestorePreview()
    {
        if (IsPreview) LoadPreview();
    }
    internal void SetPreviewRecovery(bool recovered)
    {
        if(!IsPreview)return;
        _recovery=recovered?new("RecoveredAllSelected","AES-256-GCM",true,10,10,10,
            L.T("Preview.NoDump"),DateTime.UtcNow):
            new("KeyNotFound",null,false,0,0,10,L.T("Preview.NoKey"),DateTime.UtcNow);
        RaiseComputed();
    }
    internal void SetPreviewRules(string state)
    {
        if(!IsPreview || _diagnostics is not DiagnosticsDto diagnostics || _status is not GuardStatusDto status) return;
        var previous=diagnostics.ScopedRules;
        var rows=state=="UnavailableOrInvalid" ? Array.Empty<ScopedRuleSummaryDto>() :
            (previous?.Rules ?? Array.Empty<ScopedRuleSummaryDto>()).Select(row=>row with {State="Expired",ExpiresUtc=DateTime.UtcNow.AddHours(-1)}).ToArray();
        ApplySnapshot(status,_allIncidents.Select(x=>x.Source).ToArray(),diagnostics with
        {ScopedRules=new(state,2,"DEMO-"+state,DateTime.UtcNow,rows,"Synthetic rule state only")});
        ConnectionState="preview";
    }
    public void SetPreviewOffline()
    {
        if(!IsPreview) return;
        ConnectionState="offline"; Error=L.T("T139"); ErrorDetail=L.T("Preview.NoRequest");
    }
    private void RaiseComputed() => Raise(nameof(RootCountCaption),nameof(CanaryCountCaption),nameof(UiVersionCaption),nameof(ServiceVersionCaption),nameof(ScopedRulesState),nameof(HasScopedRules),nameof(LiveStatus),nameof(RecoveryStateText),nameof(RecoveryAlgorithm),nameof(RecoveryCounts),nameof(RecoveryNote),nameof(IsMonitorRunning),nameof(HasMonitorFault),nameof(FolderState),nameof(IsConnected),nameof(IsStale),nameof(HasData),nameof(ConnectionText),nameof(ConnectionHint),
        nameof(HeroTitle),nameof(HeroBody),nameof(ModeBadge),nameof(ServiceValue),nameof(Uptime),nameof(RootCount),nameof(CanaryCount),
        nameof(IncidentCount),nameof(DriverValue),nameof(DriverNote),nameof(P95),nameof(Heartbeat),nameof(LastRefresh),nameof(HasFolders),
        nameof(FolderHint),nameof(EmptyTitle),nameof(EmptyBody),nameof(HasRecent),nameof(ServiceVersion),nameof(EventSummary),nameof(ConnectionCaption),nameof(ModeValue),nameof(ModeDetail),nameof(DriverSummary),
        nameof(StartedText),nameof(HeartbeatRelative),nameof(HeartbeatDate),nameof(ResolvedPathsValue),nameof(AuditCount),nameof(LabCount),nameof(FooterSummary));
    private static string FormatDuration(double seconds)
    {
        var t=TimeSpan.FromSeconds(Math.Clamp(double.IsFinite(seconds)?seconds:0,0,315360000));
        return t.TotalDays>=1 ? L.F("T140", (int)t.TotalDays, t.Hours) : $"{(int)t.TotalHours:00}:{t.Minutes:00}:{t.Seconds:00}";
    }
    private bool Set<T>(ref T field,T value,[CallerMemberName]string? name=null)
    {
        if(EqualityComparer<T>.Default.Equals(field,value))return false;
        field=value; PropertyChanged?.Invoke(this,new(name)); return true;
    }
    private void Raise(params string[] names) { foreach(var n in names) PropertyChanged?.Invoke(this,new(n)); }
    public void Dispose() { if(_disposed)return; _disposed=true; _lifetime.Cancel(); lock(_connectionGate)_connection?.Cancel(); }
}
