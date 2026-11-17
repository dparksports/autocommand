using System;
using System.Diagnostics;
using Windows.UI.Notifications;
using Windows.Data.Xml.Dom;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Displays Windows 10/11 Toast Notifications (Action Center) for security alerts.
    /// Uses the WinRT ToastNotification API — requires no extra NuGet packages and 
    /// works on net10.0-windows10.0.19041.0+.
    /// Notifications appear in the Action Center even when AutoCommand is minimized.
    /// </summary>
    public sealed class TrayNotifier : IDisposable
    {
        private const string AppId = "AutoCommand.SecurityTool";
        private bool _disposed;
        private readonly string _iconPath;

        // Fired when user interaction with a toast is needed (e.g. bring window forward)
        public event Action ToastActivated;

        public TrayNotifier(string iconPath = null)
        {
            // No tray icon is shown — WinRT toasts handle their own presentation —
            // but the icon feeds the AUMID registration below.
            _iconPath = iconPath;
            EnsureToastIdentityRegistered();
        }

        /// <summary>
        /// Registers the AppUserModelId the toasts are shown under. Unpackaged
        /// desktop apps have NO toast identity until this key exists — without
        /// it CreateToastNotifier().Show() throws on essentially every install
        /// (the zip ships no shortcut with an AUMID), every security alert
        /// silently no-oped into a Debug.WriteLine. HKCU under Classes is
        /// user-scope (no elevation needed), and the toast still works if the
        /// registration fails — it just falls into the visible fallback.
        /// </summary>
        private void EnsureToastIdentityRegistered()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(
                    @"Software\Classes\AppUserModelId\" + AppId);
                if (key == null) return;
                key.SetValue("DisplayName", "AutoCommand", Microsoft.Win32.RegistryValueKind.String);
                if (!string.IsNullOrEmpty(_iconPath) && System.IO.File.Exists(_iconPath))
                    key.SetValue("IconUri", _iconPath, Microsoft.Win32.RegistryValueKind.String);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"TrayNotifier.EnsureToastIdentityRegistered: {ex.Message}");
            }
        }

        /// <summary>
        /// Shows a Windows Toast notification with a security warning.
        /// Appears in the Action Center even if the app is minimized.
        /// </summary>
        public void ShowSecurityAlert(string title, string message, int durationMs = 10000) =>
            ShowSecurityAlert(title, message, durationMs, null);

        /// <summary>
        /// Same toast, with a per-toast activation callback (fired alongside
        /// the global ToastActivated event) so a specific toast can do more
        /// than bring the window forward — e.g. select the tab it came from.
        /// The callback may fire on a WinRT thread: marshal to the UI thread
        /// inside it.
        /// </summary>
        public void ShowSecurityAlert(string title, string message, int durationMs, Action onActivated)
        {
            if (_disposed) return;
            try
            {
                // Build the Toast XML template
                string xmlPayload = $@"
<toast>
  <visual>
    <binding template=""ToastGeneric"">
      <text>{EscapeXml(title)}</text>
      <text>{EscapeXml(message)}</text>
    </binding>
  </visual>
  <actions>
    <action content=""Review"" arguments=""review"" activationType=""foreground""/>
    <action content=""Dismiss"" arguments=""dismiss"" activationType=""background""/>
  </actions>
</toast>";

                var toastXml = new XmlDocument();
                toastXml.LoadXml(xmlPayload);

                var toast = new ToastNotification(toastXml);
                toast.Activated += (s, e) =>
                {
                    ToastActivated?.Invoke();
                    try { onActivated?.Invoke(); } catch { /* a toast handler must never crash the app */ }
                };

                var notifier = ToastNotificationManager.CreateToastNotifier(AppId);
                notifier.Show(toast);
            }
            catch (Exception ex)
            {
                // Toast may fail if no app identity is registered — fall back silently.
                Debug.WriteLine($"TrayNotifier.ShowSecurityAlert: {ex.Message}");
                FallbackAlert(title, message);
            }
        }

        /// <summary>
        /// Fallback when the WinRT toast API still fails: the alert goes to a
        /// durable local log (not just Debug, which is invisible in Release
        /// builds) so a suppressed security alert is diagnosable afterwards.
        /// </summary>
        private void FallbackAlert(string title, string message)
        {
            Debug.WriteLine($"[SECURITY ALERT] {title}: {message}");
            try
            {
                string dir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AutoCommand");
                System.IO.Directory.CreateDirectory(dir);
                string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\ttoast-fallback\t{title}\t{message}{Environment.NewLine}";
                System.IO.File.AppendAllText(System.IO.Path.Combine(dir, "security-alerts.log"), line);
            }
            catch { /* best-effort — never let the fallback throw */ }
        }

        /// <summary>Updates tray tooltip — no-op for toast-only implementation.</summary>
        public void SetStatus(string status) { }

        private static string EscapeXml(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            return s.Replace("&", "&amp;")
                    .Replace("<", "&lt;")
                    .Replace(">", "&gt;")
                    .Replace("\"", "&quot;")
                    .Replace("'", "&apos;");
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}
