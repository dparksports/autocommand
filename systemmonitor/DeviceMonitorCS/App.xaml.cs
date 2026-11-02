using System.Configuration;
using System.Data;
using System.Windows;

namespace DeviceMonitorCS;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            MessageBox.Show($"Critical Error: {args.ExceptionObject}", "Crash", MessageBoxButton.OK, MessageBoxImage.Error);
        };

        DispatcherUnhandledException += (s, args) =>
        {
            MessageBox.Show($"Error: {args.Exception.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        // Prevent automatic shutdown when the Privacy window closes
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        // Privacy Consent Check
        if (!DeviceMonitorCS.Services.AnalyticsService.Instance.HasUserConsented)
        {
            var privacyWin = new DeviceMonitorCS.Views.PrivacyConsentWindow();
            bool? result = privacyWin.ShowDialog();

            if (result == true)
            {
                DeviceMonitorCS.Services.AnalyticsService.Instance.IsAnalyticsEnabled = true;
            }
            else
            {
                // User Quit or Closed Window without Agreement
                Shutdown();
                return;
            }
        }
        
        // Security Audit Wizard (First Run)
        if (DeviceMonitorCS.Services.SettingsManager.Instance.IsFirstRun)
        {
            var wizard = new DeviceMonitorCS.Views.SecurityAuditWizardView();
            bool? wizResult = wizard.ShowDialog();
            
            // Note: Wizard handles updating IsFirstRun to false on completion/skip.
        }

        // Show Main Window
        var mainWindow = new MainWindow();
        MainWindow = mainWindow; // Set as the Application's Main Window
        mainWindow.Show();
        
        // Restore standard shutdown behavior
        ShutdownMode = ShutdownMode.OnMainWindowClose;
    }
}

