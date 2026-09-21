using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace RansomGuard.Ui;

/// <summary>Only called by the synthetic Windows UI test. No service or filesystem monitoring.</summary>
internal static class ActivityIconChecks
{
    private sealed record Spec(string Element, string Key, int Parts, string[] Colors);
    private static readonly Spec[] Specs =
    [
        new("ActivityPathsIcon", "ActivityDocumentImage", 4, ["#D6E6F9", "#00E5BC", "#1D70B8"]),
        new("ActivityTriggersIcon", "ActivityShieldImage", 3, ["#EF4444", "#FFFFFF"]),
        new("ActivityAuditIcon", "ActivityWarningImage", 3, ["#F5A623"]),
        new("ActivityLabIcon", "ActivitySuccessImage", 2, ["#79E58E", "#145C32"])
    ];

    public static Dictionary<string, object> CheckResources(MainWindow window)
    {
        var results = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var spec in Specs)
        {
            if (window.FindName(spec.Element) is not Image image ||
                image.Source is not DrawingImage source ||
                source.Drawing is not DrawingGroup group)
                throw new InvalidOperationException("Missing native activity vector: " + spec.Element);
            if (image.Width != 28 || image.Height != 28 || image.Stretch != Stretch.Uniform)
                throw new InvalidOperationException("Activity icons must uniformly fit 28 DIP boxes.");
            if (!ReferenceEquals(source, window.FindResource(spec.Key)))
                throw new InvalidOperationException("Wrong activity resource: " + spec.Element);
            if (group.Children.Count != spec.Parts || group.Children.Any(x => x is not GeometryDrawing))
                throw new InvalidOperationException("Activity geometry count changed: " + spec.Key);
            var colors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (GeometryDrawing part in group.Children.Cast<GeometryDrawing>())
            {
                if (part.Brush is SolidColorBrush fill) colors.Add(Hex(fill.Color));
                if (part.Pen?.Brush is SolidColorBrush stroke) colors.Add(Hex(stroke.Color));
            }
            if (!colors.SetEquals(spec.Colors))
                throw new InvalidOperationException("Original SVG colors changed: " + spec.Key);
            Rect bounds = group.Bounds;
            if (bounds.IsEmpty || !double.IsFinite(bounds.Width) || !double.IsFinite(bounds.Height) ||
                bounds.Width <= 0 || bounds.Height <= 0)
                throw new InvalidOperationException("Invalid painted vector bounds: " + spec.Key);
            double ratio = bounds.Width / bounds.Height;
            if (ratio < 0.70 || ratio > 1.10)
                throw new InvalidOperationException("Activity vector aspect ratio out of range: " + spec.Key);
            results[spec.Element] = new { kind = "NativeVector", boxDip = 28, uniform = true,
                paintedWidth = bounds.Width, paintedHeight = bounds.Height, colors = colors.ToArray() };
        }
        return results;
    }

    public static void RenderChecks(MainWindow window, string directory, string theme)
    {
        // Check 100%, 150% and 200% effective raster sizes without changing system DPI.
        foreach (int size in new[] { 28, 42, 56 })
        foreach (var spec in Specs)
        {
            if (window.FindResource(spec.Key) is not DrawingImage source)
                throw new InvalidOperationException("Activity drawing missing: " + spec.Key);
            double scale = size / Math.Max(source.Width, source.Height);
            double width = source.Width * scale, height = source.Height * scale;
            int canvas = size + 4;
            var visual = new DrawingVisual();
            using (DrawingContext dc = visual.RenderOpen())
                dc.DrawImage(source, new Rect((canvas - width) / 2, (canvas - height) / 2, width, height));
            var bitmap = new RenderTargetBitmap(canvas, canvas, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(visual);
            int stride = canvas * 4;
            var pixels = new byte[stride * canvas];
            bitmap.CopyPixels(pixels, stride, 0);
            int minX = canvas, minY = canvas, maxX = -1, maxY = -1;
            for (int y = 0; y < canvas; y++)
            for (int x = 0; x < canvas; x++)
            {
                if (pixels[y * stride + x * 4 + 3] < 24) continue;
                minX = Math.Min(minX, x); minY = Math.Min(minY, y);
                maxX = Math.Max(maxX, x); maxY = Math.Max(maxY, y);
            }
            int extent = Math.Max(maxX - minX + 1, maxY - minY + 1);
            if (minX <= 0 || minY <= 0 || maxX >= canvas - 1 || maxY >= canvas - 1 ||
                extent < size - 1 || extent > size + 2)
                throw new InvalidOperationException("Clipped/empty/undersized activity icon: " + spec.Key);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var output = new FileStream(Path.Combine(directory, $"{theme}-{spec.Element}-{size}.png"),
                FileMode.CreateNew, FileAccess.Write, FileShare.None);
            encoder.Save(output);
        }
    }
    private static string Hex(Color color) => $"#{color.R:X2}{color.G:X2}{color.B:X2}";
}
