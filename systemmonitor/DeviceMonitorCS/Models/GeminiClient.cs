using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DeviceMonitorCS.Models
{
    public class GeminiClient : IDisposable
    {
        private static readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        private readonly string _apiKey;
        private bool _disposed;

        public GeminiClient(string apiKey)
        {
            _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        }

        public async Task<string> AnalyzeThreatAsync(string threatType, string details)
        {
            string prompt = $"A security event was detected on a Windows PC. Type: '{threatType}'. Details: '{details}'. Explain this to a non-technical user in one short, reassuring sentence, and suggest a simple action.";
            return await AskAsync(prompt);
        }

        public async Task<string> AskAsync(string question, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(question))
                return "Error: question is empty.";

            var url = $"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={_apiKey}";

            var requestBody = new
            {
                contents = new[]
                {
                    new
                    {
                        parts = new[]
                        {
                            new { text = question }
                        }
                    }
                }
            };

            HttpResponseMessage response;
            try
            {
                response = await _http.PostAsJsonAsync(url, requestBody, cancellationToken);
            }
            catch (Exception ex)
            {
                return $"Error sending request: {ex.Message}";
            }

            if (!response.IsSuccessStatusCode)
            {
                return $"Error: {response.ReasonPhrase} (Status: {response.StatusCode})";
            }

            string json;
            try
            {
                json = await response.Content.ReadAsStringAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                return $"Error reading response: {ex.Message}";
            }

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                // Check for prompt feedback (block before generation)
                if (root.TryGetProperty("promptFeedback", out var promptFeedback))
                {
                    if (promptFeedback.TryGetProperty("blockReason", out var blockReason))
                    {
                        return $"Error: Prompt blocked by safety filters. Reason: {blockReason}";
                    }
                }

                if (!root.TryGetProperty("candidates", out var candidates) || candidates.GetArrayLength() == 0)
                    return "Error: No candidates returned in Gemini response.";

                var firstCandidate = candidates[0];

                // Check for finish reason (block during generation)
                if (firstCandidate.TryGetProperty("finishReason", out var finishReasonProp))
                {
                    var finishReason = finishReasonProp.GetString();
                    if (finishReason != "STOP")
                    {
                        // If there is no content, this is the primary error
                        if (!firstCandidate.TryGetProperty("content", out _))
                        {
                            return $"Error: Generation stopped. Reason: {finishReason}";
                        }
                    }
                }

                if (!firstCandidate.TryGetProperty("content", out var content) ||
                    !content.TryGetProperty("parts", out var parts) || parts.GetArrayLength() == 0)
                    return "Error: Unexpected Gemini response format (missing content/parts).";

                var firstPart = parts[0];
                if (!firstPart.TryGetProperty("text", out var textProp))
                    return "Error: Unexpected Gemini response format (missing text).";

                return textProp.GetString() ?? "";
            }
            catch (JsonException jex)
            {
                return $"Error parsing Gemini response JSON: {jex.Message}";
            }
            catch (Exception ex)
            {
                return $"Unexpected error processing Gemini response: {ex.Message}";
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            // HttpClient is static; we do not dispose it here to avoid affecting other instances.
            _disposed = true;
        }
    }
}
