using System;
using System.Windows;
using System.Windows.Threading;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// The shared refresh engine behind AutoCommand's polling tabs. Owns the
    /// four things every tab used to hand-roll: the DispatcherTimer, the
    /// reentrancy guard, the Task.Run hop off the UI thread, and the single
    /// marshal back to the dispatcher.
    ///
    /// The timer is gated on the host's visibility: every tab view is
    /// constructed at startup (MainWindow.xaml declares them all), so a
    /// constructor-time Start() used to tick for the whole app session even
    /// for tabs never opened. Here the loop starts when the host first
    /// becomes visible, triggers one immediate pass on every (re)show — the
    /// same refresh-on-entry the old Loaded += handlers gave — and stops the
    /// moment the tab is hidden again.
    ///
    /// Work runs on the thread pool and must not touch UI state; Apply runs
    /// on the UI thread. A faulted Work skips that pass silently (never take
    /// the tab down) and still releases the guard.
    /// </summary>
    public sealed class RefreshLoop
    {
        private readonly FrameworkElement _host;
        private readonly Func<object> _work;
        private readonly Action<object> _apply;
        private readonly Action _onBegin;
        private readonly DispatcherTimer _timer;
        private bool _busy;

        private RefreshLoop(FrameworkElement host, TimeSpan interval,
                            Func<object> work, Action<object> apply, Action onBegin)
        {
            _host = host;
            _work = work;
            _apply = apply;
            _onBegin = onBegin;
            _timer = new DispatcherTimer { Interval = interval };
            _timer.Tick += (_, _) => Trigger();
        }

        public static RefreshLoop Start<T>(FrameworkElement host, TimeSpan interval,
                                           Func<System.Collections.Generic.List<T>> work,
                                           Action<System.Collections.Generic.List<T>> apply,
                                           Action onBegin = null)
        {
            var loop = new RefreshLoop(host, interval, () => work(), r => apply((System.Collections.Generic.List<T>)r), onBegin);
            host.IsVisibleChanged += (_, _) =>
            {
                if (host.IsVisible) { loop.Trigger(); loop._timer.Start(); }
                else loop._timer.Stop();
            };
            if (host.IsVisible) { loop.Trigger(); loop._timer.Start(); }
            return loop;
        }

        /// <summary>One pass now, honoring the same guard as ticks. Safe to
        /// call from the UI thread (e.g. after a user action).</summary>
        public void Trigger()
        {
            if (_busy) return;
            _busy = true;
            _onBegin?.Invoke();
            System.Threading.Tasks.Task.Run(() => _work())
                .ContinueWith(t => _host.Dispatcher.BeginInvoke(new Action(() =>
                {
                    _busy = false;
                    if (t.IsFaulted) return; // engines log their own failures; skip the pass
                    _apply(t.Result);
                })));
        }

        /// <summary>Stop permanently (host going away). Hidden-tab pauses are
        /// handled by the visibility gate and do not need this.</summary>
        public void Stop() => _timer.Stop();

        /// <summary>
        /// Minimal drop-in visibility gate for a view that keeps its own
        /// timer and tick logic (the Start path above is for views built on
        /// the loop). While the host is hidden the timer is stopped; on
        /// (re)show it starts again. Takes a field accessor so lazily created
        /// timers work; call once, from the constructor.
        ///
        /// Only valid when the tick reads a service-side snapshot — pausing
        /// it must never pause data accumulation. The counter-example: a poll that
        /// detects spawns by DIFFING the live process set between ticks must
        /// not be gated - a paused tick loses the spawn events that happened
        /// while hidden.
        /// </summary>
        public static void GateVisibility(FrameworkElement host, Func<DispatcherTimer> timer, Action onShow = null)
        {
            host.IsVisibleChanged += (_, _) =>
            {
                var t = timer();
                if (t == null) return;
                if (host.IsVisible)
                {
                    onShow?.Invoke();
                    t.Start();
                }
                else
                {
                    t.Stop();
                }
            };
            if (!host.IsVisible) timer()?.Stop(); // ctor-time Start() on a never-shown tab
        }
    }
}
