using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using RansomGuard.Core;

int passed = 0;
void Check(bool ok, string label)
{
    if (!ok) throw new InvalidOperationException(label);
    passed++; Console.WriteLine("PASS: " + label);
}
Dictionary<string,string> Read(string language)
{
    using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("Resources."+language+".json")
        ?? throw new IOException("Missing embedded language catalog.");
    using var document=JsonDocument.Parse(stream);
    var result=new Dictionary<string,string>(StringComparer.Ordinal);
    foreach(var p in document.RootElement.EnumerateObject())
        if(!result.TryAdd(p.Name,p.Value.GetString()??throw new IOException("Null translation.")))
            throw new IOException("Duplicate translation key: "+p.Name);
    return result;
}
var uk=Read("uk-UA");var en=Read("en-US");
Check(uk.Keys.Order(StringComparer.Ordinal).SequenceEqual(en.Keys.Order(StringComparer.Ordinal)),"same localization keys");
Check(uk.Count>350,"main window and administration catalogs present");
foreach(string key in uk.Keys)
{
    Check(!string.IsNullOrWhiteSpace(uk[key]) && !string.IsNullOrWhiteSpace(en[key]),"nonempty translation "+key);
    var a=CompositeFormat.Parse(uk[key]);var b=CompositeFormat.Parse(en[key]);
    Check(a.MinimumArgumentCount==b.MinimumArgumentCount,"format arity "+key);
    string Slots(string value)=>string.Join(",",Regex.Matches(value,@"(?<!\{)\{(\d+)(?:[,:][^}]+)?\}(?!\})")
        .Select(m=>m.Groups[1].Value).Order(StringComparer.Ordinal));
    Check(Slots(uk[key])==Slots(en[key]),"format slots "+key);
    Check(key=="Language.Ukrainian" || !Regex.IsMatch(en[key],@"[\u0400-\u04ff]"),"English text not Russian "+key);
}
Check(CultureInfo.GetCultureInfo("uk-UA").TwoLetterISOLanguageName=="uk","Ukrainian culture");
Check(CultureInfo.GetCultureInfo("en-US").TwoLetterISOLanguageName=="en","English culture");
Check(uk["Language.Ukrainian"]!=en["Language.English"],"native language names differ");
Check(uk["T027"]!=en["T027"],"overview translated");
Check(uk["State.Title"]!=en["State.Title"],"state recovery translated");
Check(uk["State.Confirm"].Contains("QUARANTINE",StringComparison.Ordinal) && en["State.Confirm"].Contains("QUARANTINE",StringComparison.Ordinal),"review token remains invariant");
foreach(string locale in new[]{"uk-UA","en-US"})
{
    CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo(locale);
    CultureInfo.CurrentUICulture=CultureInfo.GetCultureInfo(locale);
    Check(AdminContract.Confirmation("install")=="INSTALL","locale does not alter install token "+locale);
    Check(AdminContract.Confirmation("state-repair")=="QUARANTINE","locale does not alter recovery token "+locale);
    Check(AdminContract.Confirmation("add",new string('A',64))=="TRUST AAAAAAAAAAAA","locale does not alter hash confirmation "+locale);
    AdminContract.ValidateIntent("state-repair",null);
}
Console.WriteLine($"All {passed} localization resource/contract checks passed. No Windows UI, ACL, service or recovery operation was executed.");
