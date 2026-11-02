using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;

namespace DeviceMonitorCS.Services
{
    public class AnalyticsService
    {
        private static AnalyticsService _instance;
        public static AnalyticsService Instance => _instance ?? (_instance = new AnalyticsService());

        // Removed hardcoded constraints
        private const string GaUrl = "https://www.google-analytics.com/mp/collect";
        
        private readonly HttpClient _httpClient;
        private string _clientId;
        private bool _isAnalyticsEnabled;

        // Configuration
        private FirebaseConfig _config;
        private string _telemetryStatus = "Initializing...";
        public string TelemetryStatus
        {
            get => _telemetryStatus;
            private set
            {
                if (_telemetryStatus != value)
                {
                    _telemetryStatus = value;
                    StatusChanged?.Invoke(value);
                }
            }
        }
        public event Action<string> StatusChanged;

        public bool IsAnalyticsEnabled 
        { 
            get => _isAnalyticsEnabled;
            set
            {
                if (_isAnalyticsEnabled != value)
                {
                    _isAnalyticsEnabled = value;
                    SaveSettings();
                    UpdateStatus();
                }
            }
        }

        public bool HasUserConsented => File.Exists(GetSettingsPath()); // Check if user has made ANY choice

        private AnalyticsService()
        {
            _httpClient = new HttpClient();
            LoadConfig();
            LoadSettings();
            _clientId = GetOrGenerateClientId();
            UpdateStatus();
        }

        private void LoadConfig()
        {
            try
            {
                // Prioritize local file for Portable Directory mode (same logic as FirebaseTelemetryService)
                string localPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firebase_config.json");
                if (File.Exists(localPath))
                {
                    string json = File.ReadAllText(localPath);
                    _config = JsonSerializer.Deserialize<FirebaseConfig>(json);
                    return;
                }

                // Fallback to Embedded Resource
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                var resourceName = "DeviceMonitorCS.firebase_config.json";

                using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream != null)
                    {
                        using (StreamReader reader = new StreamReader(stream))
                        {
                            string json = reader.ReadToEnd();
                            _config = JsonSerializer.Deserialize<FirebaseConfig>(json);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading Firebase config: {ex.Message}");
            }
        }

        private void UpdateStatus()
        {
            if (!IsAnalyticsEnabled)
            {
                TelemetryStatus = "Disabled (User Opt-out)";
                return;
            }

            if (_config == null || string.IsNullOrEmpty(_config.MeasurementId) || string.IsNullOrEmpty(_config.ApiSecret))
            {
                TelemetryStatus = "Error: Mising Configuration";
                return;
            }

            TelemetryStatus = "Active";
        }

        private string GetBaseDataDir() => @"C:\ProgramData\Auto-Command";

        private string GetSettingsPath()
        {
            return Path.Combine(GetBaseDataDir(), "analytics_settings.txt");
        }

        private void LoadSettings()
        {
            try 
            {
                string path = GetSettingsPath();
                if (File.Exists(path))
                {
                    _isAnalyticsEnabled = bool.Parse(File.ReadAllText(path));
                }
                else
                {
                    _isAnalyticsEnabled = false; // Default to false until explicit opt-in
                }
            }
            catch { _isAnalyticsEnabled = false; }
        }

        private void SaveSettings()
        {
            try
            {
                string folder = GetBaseDataDir();
                if (!Directory.Exists(folder)) Directory.CreateDirectory(folder);
                File.WriteAllText(GetSettingsPath(), _isAnalyticsEnabled.ToString());
            }
            catch {}
        }

        private string GetOrGenerateClientId()
        {
             var folder = GetBaseDataDir();
             var path = Path.Combine(folder, "client_id.txt");
             if (File.Exists(path)) return File.ReadAllText(path);
             
             var newId = Guid.NewGuid().ToString();
             if (!Directory.Exists(folder)) Directory.CreateDirectory(folder);
             File.WriteAllText(path, newId);
             return newId;
        }

        public async Task LogEventAsync(string eventName, Dictionary<string, string> parameters)
        {
            var objParams = parameters?.ToDictionary(k => k.Key, v => (object)v.Value);
            await LogEventAsync(eventName, (object)objParams);
        }

        public async Task LogEventAsync(string eventName, object parameters = null)
        {
            if (!IsAnalyticsEnabled) return;

             if (_config == null || string.IsNullOrEmpty(_config.MeasurementId) || string.IsNullOrEmpty(_config.ApiSecret))
            {
                UpdateStatus(); // Updates to error state
                return;
            }

            try
            {
                var dictParams = parameters as Dictionary<string, object>;
                if (dictParams == null && parameters != null)
                {
                    // Convert anonymous object to dictionary
                    var json = System.Text.Json.JsonSerializer.Serialize(parameters);
                    dictParams = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                }

                // PII Sanitization
                if (dictParams != null)
                {
                    var keys = dictParams.Keys.ToList();
                    foreach(var key in keys)
                    {
                        if (dictParams[key] is string val)
                        {
                            dictParams[key] = SanitizePii(val);
                        }
                    }
                }

                var payload = new
                {
                    client_id = _clientId,
                    user_properties = new
                    {
                        app_stage = new { value = "beta" } // Requirement 2: User Property
                    },
                    events = new[]
                    {
                        new
                        {
                            name = eventName,
                            @params = dictParams ?? new Dictionary<string, object>()
                        }
                    }
                };

                // Send Fire-and-Forget
                var content = new StringContent(System.Text.Json.JsonSerializer.Serialize(payload), System.Text.Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{GaUrl}?measurement_id={_config.MeasurementId}&api_secret={_config.ApiSecret}", content);

                if (!response.IsSuccessStatusCode)
                {
                    TelemetryStatus = $"Error: {response.StatusCode}";
                }
                else
                {
                     // Keep "Active" unless we want "Last Sent: <Time>"
                     if (TelemetryStatus.StartsWith("Error")) TelemetryStatus = "Active";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Analytics Error: {ex.Message}");
                TelemetryStatus = "Connection Error";
            }
        }

        private string SanitizePii(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            // Email Regex
            string emailPattern = @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}";
            if (System.Text.RegularExpressions.Regex.IsMatch(input, emailPattern)) return "REDACTED_EMAIL";

            // Credit Card (Simple Luhn check approximation - 13-19 digits)
            string ccPattern = @"\b(?:\d[ -]*?){13,16}\b"; 
            if (System.Text.RegularExpressions.Regex.IsMatch(input, ccPattern)) return "REDACTED_CC";

            return input;
        }
    }

    // Config DTO
    public class FirebaseConfig
    {
        public string measurementId { get; set; }
        public string apiSecret { get; set; }
        
        public string MeasurementId => measurementId;
        public string ApiSecret => apiSecret;
    }
}
