using System.Threading.Channels;
namespace RansomGuard.Core;

// Coalesce wake-ups, NOT incidents. Readers take the latest atomic retained snapshot.
// No subscriber can block the ETW/detection producer or allocate an unlimited queue.
public sealed class ChangePulse
{
    private readonly object _gate = new();
    private readonly HashSet<Subscription> _subscriptions = new();
    public Subscription Subscribe()
    {
        lock (_gate)
        {
            if (_subscriptions.Count >= 4) throw new IOException("Live subscriber limit reached.");
            var s = new Subscription(this); _subscriptions.Add(s); return s;
        }
    }
    public void Signal()
    { lock (_gate) foreach (var s in _subscriptions) s.Queue.Writer.TryWrite(true); }
    public sealed class Subscription : IDisposable
    {
        private readonly ChangePulse _owner;
        internal readonly Channel<bool> Queue = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
        { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.DropOldest,
          AllowSynchronousContinuations = false });
        internal Subscription(ChangePulse owner) { _owner = owner; }
        public async Task WaitAsync(TimeSpan timeout, CancellationToken token)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(timeout);
            try { await Queue.Reader.ReadAsync(deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
            while (Queue.Reader.TryRead(out _)) { }
        }
        public void Dispose()
        { lock (_owner._gate) { _owner._subscriptions.Remove(this); Queue.Writer.TryComplete(); } }
    }
}
