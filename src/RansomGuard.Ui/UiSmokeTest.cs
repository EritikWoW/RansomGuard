using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace RansomGuard.Ui;

/// <summary>Windows-only UI exercise. Synthetic viewmodel, no service/ETW/driver connection.</summary>
internal static class UiSmokeTest
{
    private sealed class BindingLog : TraceListener
    {
        public List<string> Errors {get;}=new();
        public override void Write(string? message) { if(!string.IsNullOrEmpty(message))Errors.Add(message); }
        public override void WriteLine(string? message) => Write(message);
    }
    private static BindingLog? _startupLog;
    private static SourceLevels _previousLevel;
    public static void BeginCapture()
    {
        if (_startupLog is not null) return;
        var source = PresentationTraceSources.DataBindingSource;
        _previousLevel = source.Switch.Level;
        _startupLog = new BindingLog();
        source.Listeners.Add(_startupLog);
        source.Switch.Level = SourceLevels.Error;
    }
    public static async Task RunAsync(MainWindow window,string directory)
    {
        var captures=new List<string>();
        var layouts=new Dictionary<string,object>();
        var refinements=new Dictionary<string,object>();
        BeginCapture();
        var listener=_startupLog!;
        var source=PresentationTraceSources.DataBindingSource;
        string? failure=null;
        string reportDirectory=directory;
        try
        {
            Directory.CreateDirectory(directory);
            window.Width=1600; window.Height=910;
            _=Administration.PackageIdentity.ServiceSha256(); // Real publication must bind the service image. No file/SCM access here.
            L.ValidateResources();
            if (MainWindow.StatusColumnsFor(1300, 1.0) != 4 ||
                MainWindow.StatusColumnsFor(1050, 1.0) != 4 ||
                MainWindow.StatusColumnsFor(760, 1.2) != 2)
                throw new InvalidOperationException("Responsive overview policy does not match the desktop/compact contract.");
            window.Model.Filter="Audit"; window.Model.Period="Today";
            window.Model.LanguageChoice="en-US";
            window.Model.LanguageChoice="uk-UA";
            if(window.Model.Filter!="Audit" || window.Model.Period!="Today")
                throw new InvalidOperationException("Changing language must not reset filter semantics.");
            window.Model.Filter="All"; window.Model.Period="All";
            foreach (string language in new[] { "uk-UA", "en-US" })
            {
                directory=Path.Combine(reportDirectory,language);
                Directory.CreateDirectory(directory);
                window.Model.LanguageChoice=language;
                window.Model.RestorePreview();
                window.Width=1600; window.Height=910;
                var xmlLanguage = window.Model.UiLanguage.IetfLanguageTag;
                var currentUiCulture = CultureInfo.CurrentUICulture.Name;
                var currentCulture = CultureInfo.CurrentCulture.Name;
                if (!string.Equals(L.Language, language, StringComparison.Ordinal) ||
                    !string.Equals(xmlLanguage, language, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(currentUiCulture, language, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(currentCulture, language, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        $"Selected UI culture was not applied. requested={language}; L={L.Language}; XmlLanguage={xmlLanguage}; CurrentUICulture={currentUiCulture}; CurrentCulture={currentCulture}");
            foreach(string theme in new[]{"Dark","Light"})
            {
                window.Model.ThemeChoice=theme;
                foreach(string page in new[]{"overview","incidents","folders","rules","recovery","diagnostics","settings","about"})
                {
                    window.Model.SelectedPage=page;
                    await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                    window.UpdateLayout();
                    window.UpdateLayout();
                    refinements[$"{language}-{theme}-{page}"]=CheckUiRefinement(window,page);
                    if(page=="overview") layouts[$"{language}-{theme}-reference-1600"]=OverviewLayout(window);
                    Save(window,Path.Combine(directory,$"{theme}-{page}.png"));
                    captures.Add($"{language}/{theme}-{page}.png");
                    if(page=="overview" && window.FindName("ActivityCard") is FrameworkElement card)
                    {
                        SaveElement(card,Path.Combine(directory,$"{theme}-activity-card.png"));
                        captures.Add($"{language}/{theme}-activity-card.png");
                        ActivityIconChecks.RenderChecks(window,directory,theme);
                    }
                }
                foreach(string ruleState in new[]{"Loaded","UnavailableOrInvalid"})
                {
                    window.Model.SetPreviewRules(ruleState);window.Model.SelectedPage="rules";
                    await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);window.UpdateLayout();
                    if(ruleState=="UnavailableOrInvalid" && window.Model.HasScopedRules)
                        throw new InvalidOperationException("Invalid rules must not leave an active-looking cached rule list.");
                    string ruleFile=$"{theme}-rules-{ruleState}.png";Save(window,Path.Combine(directory,ruleFile));captures.Add(language+"/"+ruleFile);
                    window.Model.RestorePreview();
                }
                foreach(bool recovered in new[]{false,true})
                {
                    window.Model.SelectedPage="recovery";window.Model.SetPreviewRecovery(recovered);
                    await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);window.UpdateLayout();
                    string file=$"{theme}-recovery-{(recovered?"success":"not-found")}.png";
                    Save(window,Path.Combine(directory,file));captures.Add(language+"/"+file);
                    if(recovered && window.Model.RecoveryCounts!="10 / 10")throw new InvalidOperationException("Recovery summary binding model failed.");
                }
                window.Model.SetPreviewEtwFailure(); window.Model.SelectedPage="overview";
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                window.UpdateLayout();
                if (!window.Model.IsConnected || !window.Model.HasMonitorFault ||
                    window.Model.IsMonitorRunning || window.Model.ModeValue != L.T("T087") ||
                    window.Model.ResolvedPathsValue != "—" || !window.Model.HasError ||
                    window.Model.FolderState == L.T("T016"))
                    throw new InvalidOperationException("Failed ETW must not be shown as active observation or lost IPC.");
                Save(window,Path.Combine(directory,$"{theme}-etw-unavailable.png"));
                captures.Add($"{language}/{theme}-etw-unavailable.png");
                window.Model.RestorePreview();
                window.Width=1060; window.Height=720;
                window.Model.TextScale=1.2; window.Model.SelectedPage="overview";
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                window.UpdateLayout();
                window.UpdateLayout();
                Save(window,Path.Combine(directory,$"{theme}-compact-large-text.png"));
                captures.Add($"{language}/{theme}-compact-large-text.png");
                window.Model.TextScale=1; window.Width=1335; window.Height=902;
                window.Model.SelectedPage="overview";
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                window.UpdateLayout();
                window.UpdateLayout();
                layouts[$"{language}-{theme}-user-1335"]=OverviewLayout(window);
                Save(window,Path.Combine(directory,$"{theme}-overview-1335.png"));
                captures.Add($"{language}/{theme}-overview-1335.png");
                window.Width=1600; window.Height=910;
                foreach(string action in new[]{"add","edit","disable","remove","install","start","stop","restart","uninstall","state-repair"})
                {
                    string? id=RansomGuard.Core.AdminContract.NeedsRuleId(action) ? new string('a',32) : null;
                    var dialog=new Administration.AdminWindow(action,id,preview:true) { ShowInTaskbar=false };
                    dialog.Show();
                    await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                    dialog.UpdateLayout();
                    string adminFile=$"{theme}-admin-{action}.png";
                    Save(dialog,Path.Combine(directory,adminFile));captures.Add(language+"/"+adminFile);
                    if(dialog.Applied)throw new InvalidOperationException("Synthetic administration preview changed state.");
                    if(dialog.SetupPane is { } setup)
                    {
                        refinements[$"{language}-{theme}-admin-{action}"] = setup.AssertPreviewLayout();
                        if(action == "install")
                        {
                            foreach(string scene in new[]{"review","reset","working","done","error"})
                            {
                                setup.SetPreviewScenario(scene);
                                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle); dialog.UpdateLayout();
                                refinements[$"{language}-{theme}-setup-{scene}"] = setup.AssertPreviewLayout();
                                string file=$"{theme}-setup-{scene}.png";
                                Save(dialog,Path.Combine(directory,file)); captures.Add(language+"/"+file);
                            }
                            dialog.Width=660; dialog.Height=580;
                            setup.SetPreviewScenario("reset");
                            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);dialog.UpdateLayout();
                            Save(dialog,Path.Combine(directory,$"{theme}-setup-reset-compact.png"));
                            captures.Add(language+"/"+$"{theme}-setup-reset-compact.png");
                        }
                    }
                    dialog.Close();
                }
            }
            window.Model.SetPreviewOffline(); window.Model.SelectedPage="overview";
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            window.UpdateLayout(); Save(window,Path.Combine(directory,"Offline.png")); captures.Add(language+"/Offline.png");
            }
            directory=reportDirectory;
            if(listener.Errors.Count>0)failure="WPF binding errors were recorded.";
        }
        catch(Exception ex) {failure=ex.ToString();}
        finally {source.Listeners.Remove(listener); source.Switch.Level=_previousLevel; _startupLog=null;}
        try
        {
            Directory.CreateDirectory(reportDirectory);
            File.WriteAllText(Path.Combine(reportDirectory,"ui-smoke-test.json"),
                JsonSerializer.Serialize(new {ok=failure is null,version=window.Model.Version,
                    syntheticOnly=true,serviceConnected=false,kernelLoaded=false,languages=new[]{"uk-UA","en-US"},
                    highContrast=SystemParameters.HighContrast,captures,layouts,refinements,bindingErrors=listener.Errors,error=failure},
                    new JsonSerializerOptions{WriteIndented=true}),new UTF8Encoding(false));
        }
        catch(Exception) {failure ??= "Unable to write UI smoke-test report.";}
        Application.Current.Shutdown(failure is null ? 0 : 2);
    }
    private static object CheckUiRefinement(MainWindow window,string page)
    {
        if(window.FindName("ThemeSettingsPanel") is not FrameworkElement selector ||
           window.FindName("SettingsPage") is not FrameworkElement settings ||
           window.FindName("ActivityCard") is not FrameworkElement activity ||
           window.FindName("ActivityTriggersIcon") is not Image)
            throw new InvalidOperationException("Missing UI refinement control.");
        var themeButtons=LogicalDescendants(window).OfType<ButtonBase>()
            .Where(b=>ReferenceEquals(b.Command,window.Model.ThemeCommand)).ToArray();
        if(themeButtons.Length!=3 || themeButtons.Any(b=>!HasLogicalAncestor(b,selector)))
            throw new InvalidOperationException("Theme controls must exist only in Settings.");
        if(!HasLogicalAncestor(selector,settings) || selector.IsVisible!=(page=="settings"))
            throw new InvalidOperationException("Theme selector has incorrect page visibility.");
        if(activity.IsVisible!=(page=="overview"))
            throw new InvalidOperationException("Activity overview must remain on Overview.");
        if (window.FindName("LanguageSelector") is not ComboBox languages ||
            !HasLogicalAncestor(languages,settings) || languages.IsVisible != (page == "settings") || languages.Items.Count != 2)
            throw new InvalidOperationException("The two-language selector must be confined to Settings.");
        var icons=ActivityIconChecks.CheckResources(window);
        return new {themeOnlyInSettings=true,activityOnlyInOverview=true,icons};
    }
    private static IEnumerable<DependencyObject> LogicalDescendants(DependencyObject parent)
    {
        // Collapsed pages may not yet have visual templates; inspect their XAML
        // logical children instead, without forcing hidden pages to render.
        foreach(var item in LogicalTreeHelper.GetChildren(parent))
        {
            if(item is not DependencyObject child) continue;
            yield return child;
            foreach(var descendant in LogicalDescendants(child)) yield return descendant;
        }
    }
    private static bool HasLogicalAncestor(DependencyObject child,DependencyObject ancestor)
    {
        for(DependencyObject? current=child;current is not null;current=LogicalTreeHelper.GetParent(current))
            if(ReferenceEquals(current,ancestor)) return true;
        return false;
    }
    private static object OverviewLayout(MainWindow window)
    {
        var bounds=new Dictionary<string,object>();
        foreach(string name in new[]{"StatusCards","ActivityCard","LocationsCard","RecentCard","SafetyCard"})
        {
            if(window.FindName(name) is not FrameworkElement panel)
                throw new InvalidOperationException("Missing reference-layout panel: "+name);
            Rect rect=panel.TransformToAncestor(window).TransformBounds(new Rect(new Point(0,0),panel.RenderSize));
            if(rect.Width<=0 || rect.Height<=0) throw new InvalidOperationException("Empty panel: "+name);
            bounds[name]=new {x=rect.X,y=rect.Y,width=rect.Width,height=rect.Height};
        }

        if(window.FindName("StatusCards") is not System.Windows.Controls.Primitives.UniformGrid cards)
            throw new InvalidOperationException("Reference desktop status-card grid is missing.");

        double contentWidth=window.MainContent.ActualWidth;
        int expectedColumns=MainWindow.StatusColumnsFor(contentWidth,window.Model.TextScale);
        if(cards.Columns!=expectedColumns)
            throw new InvalidOperationException(
                $"Responsive status-card layout mismatch. ActualWidth={window.ActualWidth:F1}; MainContentWidth={contentWidth:F1}; Columns={cards.Columns}; ExpectedColumns={expectedColumns}; TextScale={window.Model.TextScale:F2}.");

        bool stacked=expectedColumns==2;
        if(window.FindName("LocationsCard") is not FrameworkElement locations)
            throw new InvalidOperationException("Reference locations panel is missing.");
        int expectedLocationColumn=stacked ? 0 : 2;
        if(System.Windows.Controls.Grid.GetColumn(locations)!=expectedLocationColumn)
            throw new InvalidOperationException(
                $"Responsive locations-panel layout mismatch. Column={System.Windows.Controls.Grid.GetColumn(locations)}; ExpectedColumn={expectedLocationColumn}; MainContentWidth={contentWidth:F1}; TextScale={window.Model.TextScale:F2}.");

        return new {
            windowWidth=window.ActualWidth,
            windowHeight=window.ActualHeight,
            mainContentWidth=contentWidth,
            statusColumns=cards.Columns,
            stacked,
            bounds
        };
    }
    private static void SaveElement(FrameworkElement element,string path)
    {
        int width=(int)Math.Ceiling(element.ActualWidth),height=(int)Math.Ceiling(element.ActualHeight);
        var bitmap=new RenderTargetBitmap(width,height,96,96,PixelFormats.Pbgra32);
        var visual=new DrawingVisual();
        using(var dc=visual.RenderOpen())
            dc.DrawRectangle(new VisualBrush(element),null,new Rect(0,0,width,height));
        bitmap.Render(visual);
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        encoder.Save(output);
    }
    private static void Save(Window window,string path)
    {
        // Capture at 96dpi in DIPs to keep output deterministic across monitor scaling.
        int width=(int)Math.Ceiling(window.ActualWidth),height=(int)Math.Ceiling(window.ActualHeight);
        var bitmap=new RenderTargetBitmap(width,height,96,96,PixelFormats.Pbgra32);
        bitmap.Render(window);
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var output=new FileStream(path,FileMode.Create,FileAccess.Write,FileShare.None);
        encoder.Save(output);
    }
}
