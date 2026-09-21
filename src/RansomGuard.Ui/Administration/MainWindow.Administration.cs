using System.Windows;
using System.Windows.Controls;
using RansomGuard.Management;
using RansomGuard.Ui.Administration;
namespace RansomGuard.Ui;
public partial class MainWindow
{
    private bool _serviceQueryBusy;
    private bool _lastServiceConnection;
    private async Task RefreshManagedService()
    {
        if (_vm.IsPreview || _serviceQueryBusy) return;
        _serviceQueryBusy = true;
        try { _vm.SetServiceStatus(await Task.Run(ServiceAdministration.Query)); }
        catch (Exception ex) { _vm.Toast = L.T("Admin.Unavailable") + " " + UiMessages.ErrorSummary(ex); }
        finally { _serviceQueryBusy = false; }
    }
    private async void ServiceRefresh_Click(object sender, RoutedEventArgs e) => await RefreshManagedService();
    private async void Admin_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string action }) await RunAdmin(action, null);
    }
    private async void AdminRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string action, DataContext: ScopedRuleRow rule }) await RunAdmin(action, rule.Id);
    }
    private async Task RunAdmin(string action, string? id)
    {
        if (!_vm.CanAdminister) return;
        _vm.SetAdminBusy(true);
        try
        {
            bool changed = await AdminLauncher.OpenAsync(action, id, _vm.ThemeChoice, _vm.LanguageChoice);
            _vm.Toast = changed ? L.T("Admin.Applied") : L.T("Admin.Cancelled");
            await RefreshManagedService();
            await _vm.RefreshAsync();
        }
        catch (Exception ex) { _vm.Toast = UiMessages.ErrorSummary(ex); }
        finally { _vm.SetAdminBusy(false); }
    }
}
