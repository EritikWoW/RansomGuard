# UI acceptance checks

The build must fail on compile warnings/errors, missing resources or WPF binding
errors. Source-only checks cannot prove WPF rendering.

Windows test (automatic in build_windows.cmd):
- all pages, both themes, small-window/large-text and offline state;
- theme selectors exist exclusively on Settings;
- ActivityCard stays on Overview;
- metric boxes are 28x28 DIPs, Stretch=Uniform, linked to native DrawingImage;
- document fill/fold/outline colors are D6E6F9/00E5BC/1D70B8;
- shield fill/outline is EF4444, cross is white;
- warning is F5A623; check/circle is 145C32/79E58E;
- native painting is nonempty and not clipped at 28/42/56 pixel effective sizes;
- saved Dark-activity-card.png and Light-activity-card.png are real WPF captures;
- no UI smoke test connects to the service or starts the encryption simulator.

Manual check after build: navigate to Settings and change themes, return to
Overview, resize, inspect labels at 125/150/200% Windows display scaling. Check
live (not preview) disconnection reports unavailable/stale, never protected.
