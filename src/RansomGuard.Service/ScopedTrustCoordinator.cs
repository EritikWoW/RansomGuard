using RansomGuard.Core;
namespace RansomGuard.Service;

internal sealed class ScopedTrustCoordinator
{
    private readonly ScopedRuleStore _rules;
    private readonly SecureStore _store;
    private readonly RuntimeState _runtime;
    private readonly ScopedRepeatTracker _repeats = new(); // Accessed only by the incident consumer.
    private readonly object _observedGate = new();
    private readonly Dictionary<string, (DateTime Utc, string Result, long Matched, long Quieted)> _observed = new();
    public ScopedTrustCoordinator(SecureStore store, RuntimeState runtime)
    { _store = store; _runtime = runtime; _rules = new(store); }
    public void Publish()
    {
        var snapshot = _rules.Load();
        DateTime now = DateTime.UtcNow;
        lock (_observedGate)
        {
            foreach (string id in _observed.Keys.Where(id => !snapshot.Rules.Any(r => r.Id == id)).ToArray()) _observed.Remove(id);
            var summaries = snapshot.Rules.Select(rule =>
            {
                _observed.TryGetValue(rule.Id, out var last);
                return new ScopedRuleSummaryDto(rule.Id, rule.Name, Path.GetFileName(rule.ImagePath), rule.Sha256,
                    rule.Enabled, rule.ExpiresUtc, rule.Operations, rule.Roots.Length, rule.Effect, rule.Instance is not null,
                    !rule.Enabled ? "Disabled" : now < rule.CreatedUtc ? "ClockInvalid" : now >= rule.ExpiresUtc ? "Expired" : "Configured",
                    last.Utc == default ? null : last.Utc, last.Result ?? "NotChecked", last.Matched, last.Quieted);
            }).ToArray();
            _runtime.UpdateScopedRules(new(snapshot.State, snapshot.Revision, snapshot.Digest, now, summaries,
                snapshot.State == "UnavailableOrInvalid" ? "Store integrity/read failed: no preference applies. See administrator diagnostics." :
                    "Monitoring and scores unchanged. Rules are rechecked on matching incidents; list status is not process safety."));
        }
    }
    public async Task<ScopedTrustDecision> EvaluateAsync(RiskSignal risk, ImageEvidence image, bool healthy,
        bool confirmedCanary, bool contentChanged, bool isLab, ImageInspector inspector, CancellationToken token)
    {
        var snapshot = _rules.Load();
        if (snapshot.State == "UnavailableOrInvalid")
        { _repeats.Revoke(risk.Process); return ScopedTrustDecision.No("RuleStoreUnavailableOrInvalid"); }
        var candidates = snapshot.Rules.Where(r => WinPaths.Equal(r.ImagePath, risk.ImagePath)).ToArray();
        if (candidates.Length == 0)
        { _repeats.Revoke(risk.Process); return ScopedTrustDecision.No("NoRuleForExactImagePath"); }
        if (isLab || risk.CanaryCandidate || risk.Evidence.Any(e => e.CanaryCandidate) || confirmedCanary || contentChanged || !healthy)
        {
            _repeats.Revoke(risk.Process);
            string why = isLab ? "LabNeverExempted" : confirmedCanary || risk.CanaryCandidate || risk.Evidence.Any(e => e.CanaryCandidate)
                ? "CanaryOverridesRule" : contentChanged ? "ContentEvidenceOverridesRule" : "TelemetryNotHealthy";
            foreach (var r in candidates) Observe(r.Id, why, false, false);
            return ScopedTrustDecision.No(why);
        }
        // Overlapping rules are not unioned: one complete rule must cover ALL evidence.
        ScopedTrustDecision last = ScopedTrustDecision.No("NoMatchingRule");
        using var proof = await ScopedRuleVerifier.OpenAsync(risk, image, Array.Empty<string>(), _store.Root, inspector.Lookup, token);
        foreach (var rule in candidates.OrderBy(r => r.Effect == "QuietRepeat" ? 1 : 0))
        {
            var now = DateTime.UtcNow;
            if (!rule.Enabled || now >= rule.ExpiresUtc || now < rule.CreatedUtc)
            { last = ScopedTrustDecision.No(!rule.Enabled ? "Disabled" : "ExpiredOrClockInvalid", rule.Id); Observe(rule.Id, last.Reason, false, false); continue; }
            try { ScopedRuleVerifier.CheckScopes(rule.Roots, _store.Root); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            { last=ScopedTrustDecision.No("ScopeUnavailableOrRedirected",rule.Id); Observe(rule.Id,last.Reason,false,false); continue; }
            last = ScopedTrustPolicy.Evaluate(rule, risk, proof.Evidence, healthy, confirmedCanary, contentChanged, isLab, DateTime.UtcNow);
            // A revocation/change during hashing invalidates the decision; no stale in-memory grants.
            if (_rules.Load().Digest != snapshot.Digest) last = ScopedTrustDecision.No("RuleStoreChangedDuringVerification", rule.Id);
            last=last with {RulesDigest=snapshot.Digest,CheckedUtc=DateTime.UtcNow};
            _store.Audit(new {Utc=DateTime.UtcNow,Event="ScopedRuleEvaluated",risk.Process,RuleId=rule.Id,RulesDigest=snapshot.Digest,
                last.Applies,last.Reason,FreshImageSha256=proof.Evidence.Image.Status=="Hashed"?proof.Evidence.Image.Sha256:null,
                proof.Evidence.IdentityVerified,proof.Evidence.PathsChecked,proof.Evidence.VerifiedUtc,
                SignatureStatus=proof.Evidence.Image.Signature.Status,VerificationError=proof.Evidence.Error});
            if (last.Applies)
            {
                bool quiet = _repeats.ShouldQuiet(rule, risk, snapshot.Revision, DateTime.UtcNow);
                last = last with { NotificationQuieted = quiet };
                Observe(rule.Id, last.Reason, true, quiet);
                return last;
            }
            string reason = proof.Evidence.Error is null ? last.Reason : "IdentityOrPathUnavailable";
            Observe(rule.Id, reason, false, false);
        }
        _repeats.Revoke(risk.Process);
        return last;
    }
    private void Observe(string id, string result, bool matched, bool quieted)
    {
        lock (_observedGate)
        {
            _observed.TryGetValue(id, out var previous);
            _observed[id] = (DateTime.UtcNow, result, previous.Matched + (matched ? 1 : 0), previous.Quieted + (quieted ? 1 : 0));
        }
        Publish();
    }
}

internal sealed class ScopedTrustPublisher(ScopedTrustCoordinator coordinator) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        await Task.Yield();
        try
        {
            while (!token.IsCancellationRequested)
            { coordinator.Publish(); await Task.Delay(TimeSpan.FromSeconds(2), token); }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
}
