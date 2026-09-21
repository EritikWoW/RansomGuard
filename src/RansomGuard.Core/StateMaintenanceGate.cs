namespace RansomGuard.Core;

// Synchronous, thread-affine lease; never retain it across await.
public sealed class StateMaintenanceGate : IDisposable
{
    private readonly Mutex _mutex;
    private bool _owned;
    private StateMaintenanceGate(Mutex mutex) { _mutex = mutex; _owned = true; }
    public static StateMaintenanceGate Acquire()
    {
        var mutex = new Mutex(false, @"Global\RansomGuardV03-StateMaintenance");
        bool owns;
        try { try { owns = mutex.WaitOne(0); } catch (AbandonedMutexException) { owns = true; } }
        catch { mutex.Dispose(); throw; }
        if (!owns) { mutex.Dispose(); throw new InvalidOperationException("StateBusy: another state-management operation is active."); }
        return new(mutex);
    }
    public void Dispose() { if (_owned) { _owned = false; _mutex.ReleaseMutex(); _mutex.Dispose(); } }
}
