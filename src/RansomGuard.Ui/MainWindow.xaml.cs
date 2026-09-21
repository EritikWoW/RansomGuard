using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;

namespace RansomGuard.Ui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    internal MainViewModel Model => _vm;

    public MainWindow() : this(new MainViewModel()) { }
    internal MainWindow(MainViewModel vm)
    {
        _vm=vm;
        InitializeComponent();
        DataContext=_vm;
        var work=SystemParameters.WorkArea;
        Width=Math.Min(1600,Math.Max(360,work.Width-32));
        Height=Math.Min(910,Math.Max(360,work.Height-32));
        // Do not force an off-screen minimum on displays using large Windows scaling.
        MinWidth=Math.Min(1024,Math.Max(360,work.Width-24));
        MinHeight=Math.Min(650,Math.Max(360,work.Height-24));
        _vm.PropertyChanged+=OnModelChanged;
        Loaded+=OnLoaded;
        PreviewKeyDown+=OnPreviewKeyDown;
        SystemParameters.StaticPropertyChanged+=OnSystemParametersChanged;
        SystemEvents.UserPreferenceChanged+=OnUserPreferenceChanged;
        Closed+=OnClosed;
    }
    private void OnLoaded(object sender,RoutedEventArgs e)
    {
        UpdateOverviewLayout();
        if(!_vm.IsPreview) { _vm.StartLive(); _ = RefreshManagedService(); }
    }
    private void OnClosed(object? sender,EventArgs e)
    {
        SystemParameters.StaticPropertyChanged-=OnSystemParametersChanged;
        SystemEvents.UserPreferenceChanged-=OnUserPreferenceChanged;
        _vm.PropertyChanged-=OnModelChanged;
        _vm.Dispose();
    }
    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if(e.PropertyName == nameof(MainViewModel.SelectedPage) && _vm.SelectedPage == "settings") _ = RefreshManagedService();
        if(e.PropertyName == nameof(MainViewModel.IsConnected) && _lastServiceConnection != _vm.IsConnected)
        { _lastServiceConnection = _vm.IsConnected; _ = RefreshManagedService(); }
        if(e.PropertyName == nameof(MainViewModel.TextScale) || string.IsNullOrEmpty(e.PropertyName))
            Dispatcher.BeginInvoke(new Action(UpdateOverviewLayout));
    }
    private void MainContent_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateOverviewLayout();
    internal void ApplyResponsiveLayoutForTest() => UpdateOverviewLayout();
    private void UpdateOverviewLayout()
    {
        // Preserve the reference's four-card and 2x2 composition at desktop sizes.
        // At narrow widths, reflow instead of shrinking text or clipping controls.
        if(MainContent is null || OverviewPanels is null || StatusCards is null || RecentTable is null) return;
        bool stacked=MainContent.ActualWidth < 980 || (MainContent.ActualWidth < 1120 && _vm.TextScale > 1.1);
        SidebarColumn.Width=new GridLength(ActualWidth < 1420 ? 232 : 260);
        HeaderConnection.Visibility=MainContent.ActualWidth < 850 ? Visibility.Collapsed : Visibility.Visible;
        StatusCards.Columns=stacked ? 2 : 4;
        OverviewPanels.ColumnDefinitions[0].Width=new GridLength(stacked ? 1 : 1.4,GridUnitType.Star);
        OverviewPanels.ColumnDefinitions[1].Width=new GridLength(stacked ? 0 : 18);
        OverviewPanels.ColumnDefinitions[2].Width=stacked ? new GridLength(0) : new GridLength(1,GridUnitType.Star);
        OverviewPanels.RowDefinitions[3].Height=new GridLength(stacked ? 18 : 0);
        OverviewPanels.RowDefinitions[5].Height=new GridLength(stacked ? 18 : 0);
        SetPanel(ActivityCard,0,0,stacked);
        SetPanel(LocationsCard,stacked ? 2 : 0,stacked ? 0 : 2,stacked);
        SetPanel(RecentCard,stacked ? 4 : 2,0,stacked);
        SetPanel(SafetyCard,stacked ? 6 : 2,stacked ? 0 : 2,stacked);
        RecentTable.RowHeight=36*_vm.TextScale;
        RecentTable.MaxHeight=34+5*RecentTable.RowHeight+6;
    }
    private static void SetPanel(FrameworkElement panel,int row,int column,bool spanning)
    {
        Grid.SetRow(panel,row); Grid.SetColumn(panel,column); Grid.SetColumnSpan(panel,spanning ? 3 : 1);
    }
    private void OnUserPreferenceChanged(object? sender,UserPreferenceChangedEventArgs e)
    { if(_vm.ThemeChoice=="System")Dispatcher.Invoke(_vm.ReapplySystemTheme); }
    private void OnSystemParametersChanged(object? sender,PropertyChangedEventArgs e)
    {
        if(e.PropertyName=="HighContrast") Dispatcher.Invoke(_vm.ReapplySystemTheme);
    }
    private void OnPreviewKeyDown(object sender,KeyEventArgs e)
    {
        if(e.Key==Key.Escape) { _vm.SelectedIncident=null; e.Handled=true; }
        if(e.Key==Key.F && Keyboard.Modifiers==ModifierKeys.Control) { _vm.SelectedPage="incidents"; EventSearch.Focus(); e.Handled=true; }
    }
    private void Minimize_Click(object sender,RoutedEventArgs e) => SystemCommands.MinimizeWindow(this);
    private void Maximize_Click(object sender,RoutedEventArgs e)
    {
        if(WindowState==WindowState.Maximized)SystemCommands.RestoreWindow(this); else SystemCommands.MaximizeWindow(this);
    }
    private void Close_Click(object sender,RoutedEventArgs e) => Close();
    private void Recent_SelectionChanged(object sender,SelectionChangedEventArgs e)
    {
        if(sender is DataGrid grid && grid.SelectedItem is IncidentRow row)
        { _vm.SelectedPage="incidents"; _vm.SelectedIncident=row; grid.SelectedItem=null; }
    }
    private void CopyDiagnostics_Click(object sender,RoutedEventArgs e)
    {
        try { Clipboard.SetText(_vm.DiagnosticSummary()); _vm.Toast=L.T("T141"); }
        catch(System.Runtime.InteropServices.ExternalException) { _vm.Toast=L.T("T142"); }
    }
    private void Export_Click(object sender,RoutedEventArgs e)
    {
        var dialog=new SaveFileDialog {Title=L.T("T143"),Filter="JSON (*.json)|*.json",FileName=$"ransomguard-events-{DateTime.Now:yyyyMMdd-HHmmss}.json",AddExtension=true,OverwritePrompt=true};
        if(dialog.ShowDialog(this)!=true)return;
        try
        {
            File.WriteAllText(dialog.FileName,_vm.ExportVisibleEvents(),new UTF8Encoding(false));
            _vm.Toast=L.T("T144");
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { _vm.Toast=L.T("T145")+ex.Message; }
    }
}
