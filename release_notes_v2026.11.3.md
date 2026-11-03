# AutoCommand — v2026.11.3

This release makes AutoCommand usable on the smallest screens Windows runs on.
A refresh install of Windows 11 often sits at 800×600 on the Basic Display
Adapter until GPU drivers land — and until now the main window opened at a
fixed 1200×750 there, clipped past the screen edge with its title-bar buttons
unreachable. The window now adapts to whatever screen it finds, and remembers
what you did with it.

## What changed

- **Adaptive startup sizing.** At launch the window measures its monitor's
  work area (per-monitor, DPI-correct): persisted geometry is restored and
  clamped to the current screen, screens too small for the designed 1200×750
  start MAXIMIZED so the title bar and every pane are reachable, and larger
  displays keep the design size — the fluid layout already uses the extra
  room. A resolution jump after drivers install self-corrects: the window is
  re-clamped live when the work area changes, no restart needed.
- **Placement persists.** Final size, position and maximized state are saved
  to `%LOCALAPPDATA%\AutoCommand\window_state.txt` (the same plain-text idiom
  as rain_panel.txt) and restored next launch — clamped, so a saved window
  can never come back straddling a screen it no longer fits.
- **Dialogs can never exceed their monitor.** Every popup (block confirms,
  Traffic Peek, PID Inquiry, Blocked Rules, the WSL diagnosis, …) caps at
  92% of its screen, and MinWidth floors wider than the screen are lowered —
  Traffic Peek demanded an 880px-wide window, which an 800px panel could
  never show at all.
- **Small screens start lean.** On narrow launches the sidebar starts folded
  to its icons (the burger expands it as before), so every horizontal pixel
  goes to content. The resize floor is now 640×420 — below 800×600 because
  the work area is smaller than the panel (the taskbar takes a strip, and
  125% scaling on a tiny panel yields an effective 640×480 desktop).
- **Per-monitor DPI awareness.** The app manifest declares PerMonitorV2, so
  when that refresh install gets its real driver and a high-DPI panel, the
  UI renders crisp on the monitor it is on instead of bitmap-stretching.
- **QA hook.** Set `AUTOCOMMAND_FORCE_WORKAREA=800x600` to simulate the
  small-screen path on a dev machine — no test bench required.
