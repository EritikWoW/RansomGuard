using RansomGuard.Management;
namespace RansomGuard.Ui;
internal sealed partial class MainViewModel
{
    private bool _adminBusy;
    private ManagedServiceStatus? _managedService;
    public bool CanAdminister => !IsPreview && !_adminBusy;
    public bool CanInstallService => CanAdminister && _managedService is { QuerySucceeded: true, Installed: false };
    public bool CanStartService => CanAdminister && _managedService is { Installed: true, State: "Stopped" };
    public bool CanStopService => CanAdminister && _managedService is { Installed: true, State: "Running" };
    public bool CanUninstallService => CanAdminister && _managedService is { Installed: true, State: "Stopped" };
    public string ManagedServiceText => IsPreview ? L.T("T169") : _managedService?.State switch
    {
        "NotInstalled" => L.T("T170"), "Running" => L.T("T171"), "Stopped" => L.T("T172"),
        "StartPending" => L.T("T173"), "StopPending" => L.T("T174"), _ => L.T("T175")
    };
    public string ManagedServiceDetails => IsPreview ? L.T("Preview.Only") : _managedService is null ? L.T("T176") :
        string.Join("\n", new[] { _managedService.ImagePath, _managedService.Account, UiMessages.State(_managedService.StartMode), _managedService.Error }.Where(s => !string.IsNullOrEmpty(s)));
    internal void SetAdminBusy(bool value) { _adminBusy = value; RaiseAdmin(); }
    internal void SetServiceStatus(ManagedServiceStatus value) { _managedService = value; RaiseAdmin(); }
    private void RaiseAdmin() => Raise(nameof(CanAdminister), nameof(CanInstallService), nameof(CanStartService), nameof(CanStopService), nameof(CanUninstallService), nameof(ManagedServiceText), nameof(ManagedServiceDetails));
}
