using System.Windows;

namespace RansomGuard.Ui;
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        L.Select(UiPreferences.Load().Language);
        L.ValidateResources();
        if(e.Args.Length > 0 && e.Args[0] == "--admin-ui")
        {
            try
            {
                if(e.Args.Length != 5) throw new ArgumentException("Invalid administrator window arguments.");
                string? id = e.Args[2] == "-" ? null : e.Args[2];
                RansomGuard.Core.AdminContract.ValidateIntent(e.Args[1], id);
                if(e.Args[3] is not ("Dark" or "Light" or "System")) throw new ArgumentException("Invalid theme.");
                RansomGuard.Management.RuleAdministration.DemandAdministrator();
                L.Select(e.Args[4]);
                ThemeManager.Apply(e.Args[3], 1.0);
                var adminWindow = new Administration.AdminWindow(e.Args[1], id);
                MainWindow = adminWindow;
                adminWindow.Closed += (_,_) => Shutdown(adminWindow.Applied ? 0 : 2);
                adminWindow.Show();
            }
            catch(Exception ex)
            { MessageBox.Show(UiMessages.ErrorSummary(ex) + "\n\n" + L.T("Admin.TechnicalDetails") + "\n" + ex.Message, L.T("T184"), MessageBoxButton.OK, MessageBoxImage.Error); Shutdown(3); }
            return;
        }
        bool smoke=e.Args.Contains("--ui-selftest",StringComparer.Ordinal);
        bool preview=smoke || e.Args.Contains("--preview",StringComparer.Ordinal);
        if(smoke) UiSmokeTest.BeginCapture();
        var model=new MainViewModel(preview);
        var window=new MainWindow(model);
        MainWindow=window;
        if(smoke)
        {
            int outputIndex=Array.IndexOf(e.Args,"--out");
            string output=outputIndex>=0 && outputIndex+1<e.Args.Length ? e.Args[outputIndex+1]
                : System.IO.Path.Combine(System.IO.Path.GetTempPath(),"RansomGuard-UI-smoketest-"+Guid.NewGuid().ToString("N"));
            window.ShowInTaskbar=false;
            window.Loaded+=async (_,_) => await UiSmokeTest.RunAsync(window,output);
        }
        window.Show();
    }
}
