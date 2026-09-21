using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Media;
using System.Xml;
using System.Xml.Linq;

namespace RansomGuard.Ui.Controls;

/// <summary>Renders the bundled, path-only SVG set as native WPF vectors. Never loads a URI or user file.</summary>
public sealed class SvgIcon : FrameworkElement
{
    public static readonly DependencyProperty KindProperty = DependencyProperty.Register(
        nameof(Kind), typeof(string), typeof(SvgIcon),
        new FrameworkPropertyMetadata("shield", FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(SvgIcon),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));
    // SVG source-unit width. Defaults preserve every existing icon; the user-supplied
    // shield uses its original one-unit outline rather than the previous 1.75-unit pen.
    public static readonly DependencyProperty StrokeThicknessProperty = DependencyProperty.Register(
        nameof(StrokeThickness), typeof(double), typeof(SvgIcon),
        new FrameworkPropertyMetadata(1.75, FrameworkPropertyMetadataOptions.AffectsRender),
        static value => value is double width && double.IsFinite(width) && width >= 0 && width <= 24);
    public double StrokeThickness
    { get => (double)GetValue(StrokeThicknessProperty); set => SetValue(StrokeThicknessProperty, value); }
    public string Kind { get => (string)GetValue(KindProperty); set => SetValue(KindProperty, value); }
    public Brush Stroke { get => (Brush)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }
    private static readonly ConcurrentDictionary<string, Geometry[]> Cache = new(StringComparer.Ordinal);
    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal)
    { "shield", "shield-x", "shield-eye", "grid", "activity", "folder", "history", "sliders", "pulse", "info",
      "sun", "moon", "refresh", "server", "cpu", "alert", "check", "search", "chevron", "download",
      "copy", "clock", "link", "unplug", "lock", "file", "close", "minus", "maximize", "restore", "arrow", "layers", "monitor", "home", "gear", "rules", "chart", "heartbeat", "flask", "picture" };
    public SvgIcon() { Width = 20; Height = 20; IsHitTestVisible = false; SnapsToDevicePixels = true; }
    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        // Snapshot the property once and normalize null before validation/cache lookup.
        string requestedKind = Kind ?? string.Empty;
        string name = Allowed.Contains(requestedKind) ? requestedKind : "shield";
        var shapes = Cache.GetOrAdd(name, Load);
        double size = Math.Min(ActualWidth, ActualHeight), scale = size / 24.0;
        if (scale <= 0) return;
        dc.PushTransform(new TranslateTransform((ActualWidth-size)/2, (ActualHeight-size)/2));
        dc.PushTransform(new ScaleTransform(scale, scale));
        var pen = new Pen(Stroke, StrokeThickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round };
        foreach (var geometry in shapes) dc.DrawGeometry(null, pen, geometry);
        dc.Pop(); dc.Pop();
    }
    private static Geometry[] Load(string name)
    {
        using Stream? stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"RansomGuard.Ui.Assets.Icons.{name}.svg");
        if (stream is null) throw new InvalidOperationException($"Bundled icon resource is missing: {name}");
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 32768 });
        var document = XDocument.Load(reader);
        XNamespace ns = "http://www.w3.org/2000/svg";
        var result = new List<Geometry>();
        foreach (var path in document.Root?.Elements(ns+"path") ?? Enumerable.Empty<XElement>())
        {
            var geometry = Geometry.Parse((string?)path.Attribute("d") ?? "");
            geometry.Freeze(); result.Add(geometry);
        }
        return result.ToArray();
    }
}
