using System.Text.Json;
using RansomGuard.Core;
using RansomGuard.Rollback;

namespace RansomGuard.Service;

internal sealed class WindowsServiceBootstrap : BackgroundService
{
    private readonly ILogger<WindowsServiceBootstrap> _log;
    private readonly IHostApplicationLifetime _outerLifetime;

    public WindowsServiceBootstrap(
        ILogger<WindowsServiceBootstrap> log,
        IHostApplicationLifetime outerLifetime)
    {
        _log = log;
        _outerLifetime = outerLifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RunRuntimeAsync(stoppingToken).ConfigureAwait(false);
            if (!stoppingToken.IsCancellationRequested)
            {
                if (Environment.ExitCode == 0)
                    Environment.ExitCode = 8;
                _log.LogCritical(
                    "Inner RansomGuard runtime stopped while the SCM service was still expected to run.");
                _outerLifetime.StopApplication();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Environment.ExitCode = 1;
            _log.LogCritical(ex,
                "Windows Service bootstrap failed after SCM startup; stopping the outer service host.");
            _outerLifetime.StopApplication();
        }
    }

    private async Task RunRuntimeAsync(CancellationToken stoppingToken)
    {
        SecureStore store;
        GuardSettings settings;
        ProtectionStateMachine protection;
        ProtectionPackageAdmission? protectionPackage = null;
        ContentSampler samples;

        // Match the proven pre-SCM bootstrap ordering: protect only trusted state generation
        // initialization with StateMaintenanceGate. The main-thread instance mutex already blocks
        // recovery/replacement for the full Windows Service lifetime, so signature/catalog admission
        // must not run while holding the global state-maintenance mutex.
        using (StateMaintenanceGate.Acquire())
        {
            store = new SecureStore();
        }
        store.Audit(new
        {
            Type = "ServiceBootstrapStateStoreReady",
            Utc = DateTime.UtcNow,
            Root = store.Root
        });

        var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        FileSafety.NoReparse(configPath);
        if (new FileInfo(configPath).Length > 65536)
            throw new IOException("Configuration exceeds size limit.");

        settings = JsonSerializer.Deserialize<GuardSettings>(
            File.ReadAllText(configPath),
            new JsonSerializerOptions
            {
                UnmappedMemberHandling =
                    System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
            }) ?? throw new InvalidOperationException("Missing settings.");
        settings.Validate();

        if (settings.ProtectedRoots.Length == 0)
            throw new InvalidOperationException(
                "Set explicit ProtectedRoots before installing the service. It must not guess the active user's folders.");

        store.Audit(new
        {
            Type = "ServiceBootstrapSettingsValidated",
            Utc = DateTime.UtcNow,
            RequestedMode = settings.Mode,
            ProtectedRoot = settings.ProtectedRoots[0]
        });

        var rollbackRepository = new RollbackRepository(store.Rollback);
        rollbackRepository.VerifyAll();
        store.Audit(new
        {
            Type = "ServiceBootstrapRollbackVerified",
            Utc = DateTime.UtcNow,
            Sessions = rollbackRepository.SessionIds().Length
        });

        protection = new ProtectionStateMachine(settings.Mode);
        protection.MarkRollbackReady();
        if (string.Equals(settings.Mode, "Enforce", StringComparison.Ordinal))
        {
            store.Audit(new
            {
                Type = "ServiceBootstrapProtectionAdmissionStarting",
                Utc = DateTime.UtcNow
            });
            protectionPackage = ProtectionPackageVerifier.Inspect(
                AppContext.BaseDirectory, ProductInfo.Version);
            store.Audit(new
            {
                Type = "ServiceBootstrapProtectionAdmissionFinished",
                Utc = DateTime.UtcNow,
                Admission = protectionPackage
            });
            if (!protectionPackage.ReadyForLifecycle)
                protection.MarkUnavailable(
                    "Protection package admission: " + protectionPackage.Reason);
        }

        store.Audit(new
        {
            Type = "RollbackStoreReady",
            Utc = DateTime.UtcNow,
            Root = store.Rollback,
            Sessions = rollbackRepository.SessionIds().Length,
            RequestedMode = settings.Mode,
            Protection = protection.Snapshot(),
            ProtectionPackage = protectionPackage
        });

        samples = new ContentSampler();
        foreach (var file in settings.CanaryFiles)
        {
            if (!settings.ProtectedRoots.Any(r => WinPaths.Under(file, r)))
                throw new InvalidOperationException(
                    "Canary must lie inside an explicit monitored root.");
            samples.Register(file);
        }

        // This is intentionally a normal inner Generic Host, not another WindowsServiceLifetime.
        // SCM is already owned by the outer host in Program.cs.
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = Array.Empty<string>(),
            ContentRootPath = AppContext.BaseDirectory
        });

        var runtime = new RuntimeState(protection.Snapshot());
        builder.Services.AddSingleton(runtime);

        if (string.Equals(settings.Mode, "Enforce", StringComparison.Ordinal) &&
            protectionPackage?.ReadyForLifecycle == true)
        {
            var admittedPackage = protectionPackage;
            builder.Services.AddHostedService(sp => new ProductionProtectionLifecycle(
                sp.GetRequiredService<ILogger<ProductionProtectionLifecycle>>(),
                settings,
                store,
                admittedPackage,
                protection,
                runtime,
                sp.GetRequiredService<IHostApplicationLifetime>(),
                AppContext.BaseDirectory));
        }

        var scopedTrust = new ScopedTrustCoordinator(store, runtime);
        builder.Services.AddHostedService(_ => new ScopedTrustPublisher(scopedTrust));
        builder.Services.AddHostedService(sp => new GuardWorker(
            sp.GetRequiredService<ILogger<GuardWorker>>(),
            sp.GetRequiredService<IHostApplicationLifetime>(),
            settings,
            store,
            new ImageInspector(store),
            samples,
            lab: null,
            runtime,
            scopedTrust));
        builder.Services.AddHostedService(sp => new ReadOnlyPipeServer(
            sp.GetRequiredService<ILogger<ReadOnlyPipeServer>>(),
            runtime,
            settings));

        using var innerHost = builder.Build();
        await innerHost.RunAsync(stoppingToken).ConfigureAwait(false);
    }
}
