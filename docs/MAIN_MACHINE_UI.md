# Main-machine UI workflow, 0.6.3.0

See [UI_ADMINISTRATION.md](UI_ADMINISTRATION.md). Normal startup is UI/RansomGuard.Ui.exe,
not a console manager. Service installation and controlled start/stop live in Settings;
trust editing lives in Rules. A short-lived elevated dialog asks for review.

Kernel driver operations are NOT available. Do not disable existing Windows protection.
SCM Running is separate from ETW health. Failed monitoring remains clearly unavailable.
