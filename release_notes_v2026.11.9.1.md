# v2026.11.9.1 — the rain survives a screen nap

Same-day follow-up to v2026.11.9. One fix.

## The bug

A v2026.11.3.4 install on this machine logged two crashes
(`crash.log`, 2026-11-08 21:55 and 2026-11-09 19:49):

```
System.InvalidOperationException: Cannot call this method while the image is unlocked.
   at System.Windows.Media.Imaging.WriteableBitmap.Unlock()
   at AutoCommand.Matrix.MatrixRenderer.Frame(...) MatrixRenderer.cs:line 480
```

The Matrix rain pane draws through a `WriteableBitmap` with a textbook
`Lock() … try { draw } finally { Unlock() }` on the single UI thread —
yet `Unlock()` found the bitmap already unlocked. Explanation: when the
render device is lost (display sleep/wake, session lock, monitor mode
change), WPF recreates the bitmap's GPU texture and resets its lock
bookkeeping. The next frame's Lock/Unlock then throws. The global
dispatcher handler kept the process alive, but every later tick aborted
mid-draw — the pane froze until restart. Both timestamps match display
sleep/wake events.

## The fix

Every `Lock`/`Unlock` site in the renderer (the rain frame pass and the
three ambient/etch passes, on both bitmaps) now goes through
`LockSurface`/`UnlockSurface`, which recognize the device-loss state,
replace both surfaces at the current size (`RebuildSurfaces` — fresh
bitmaps, clean rain slate, full ambient repaint), and let the next tick
draw into the healthy surface. A reentrancy guard keeps a still-lost
device from recursing through the ambient repaint. After a display
wake-up the pane now blinks once and rebuilds instead of dying.

Deliberately NOT a switch to GlyphRun/text rendering: the per-cell
log-curve wake alpha, the cinema per-pixel fade and the atlas
bloom/shadow cells have no text-path equivalent. The bitmap is the
right tool; it needed to tolerate the one WPF state reset it can hit.

## Verification

- `dotnet build` Debug + Release — 0 errors.
- Full strict suite gate on GitHub CI — green for this commit
  (run 42753388671). `RainSelfTest` remains a manual visual harness by
  design (a window with no exit path); a desk run after display
  sleep/wake is the visual confirmation for this fix.
