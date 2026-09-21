# UI architecture (0.6.3.0)

WPF/MVVM with existing assets, themes, layout, accessibility and synthetic rendering
tests. LocalApiClient uses protocol-v2 length-prefixed JSON on a persistent local
pipe. MainViewModel receives asynchronously and dispatches state changes to WPF.
MainWindow has no polling DispatcherTimer. System-theme changes use Windows events.
Refresh renews the subscription; recovery is status-only in UI.

Collection sections are replaced only when their section revision changes. Initial
connect is a full snapshot. A sequence gap forces reconnection; the latest 50
incident summaries are provided, not an unbounded history. Connection timeout makes
state unknown; previous recovery results are marked as last observed results.

NETWORK/ANONYMOUS denied; four fixed client workers; write/read/frame bounds. Individual
pipe data rights and SECURITY_IDENTIFICATION avoid granting UI server-instance or
impersonation privileges. Server image is queried using limited process rights;
no service stop/config mutation/driver action/recovery-key data in UI protocol.
