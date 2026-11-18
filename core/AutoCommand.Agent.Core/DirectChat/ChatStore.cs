using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace AutoCommand.Agent.Core.DirectChat
{
    /// <summary>The Ask-AutoCommand configuration as the user left it.
    /// Everything inspectable lives in settings.json (house rule: plain,
    /// readable state); the one secret — the Z.ai API key — lives DPAPI-
    /// encrypted in key.bin and NEVER in the JSON, the same split as the
    /// intercept CA (ca.pfx) next door.</summary>
    public sealed class ChatSettings
    {
        /// <summary>coding | standard | bigmodel | custom — see ChatStore's
        /// URL table. Default is the Coding Plan endpoint: glm-5.3-flash is
        /// included in that subscription, and it is the access this feature
        /// was built against.</summary>
        public string EndpointPreset { get; set; } = "coding";
        public string CustomBaseUrl { get; set; } = "";
        public string Model { get; set; } = ChatStore.DefaultModel;
        /// <summary>Whether mutating tools are offered to the model at all.
        /// Off by default: a chat that can only read cannot change the
        /// machine even if the model goes wrong; on, every mutating call
        /// still goes through the AgentConfirmWindow.</summary>
        public bool AllowMutating { get; set; } = false;
        /// <summary>Set by the consent dialog: the user accepted that
        /// conversation text and tool results go to the model provider.
        /// No consent, no network — the send path checks this too.</summary>
        public bool Consent { get; set; } = false;
    }

    /// <summary>Load/save for the direct-chat feature's state under
    /// %LOCALAPPDATA%\AutoCommand\chat. Static like every other store in
    /// this codebase; RootOverride lets the self-test point the whole thing
    /// at a temp directory.</summary>
    public static class ChatStore
    {
        public const string DefaultModel = "glm-5.3-flash";
        public const string CodingPlanBaseUrl = "https://api.z.ai/api/coding/paas/v4";
        public const string StandardBaseUrl = "https://api.z.ai/api/paas/v4";
        public const string BigModelBaseUrl = "https://open.bigmodel.cn/api/paas/v4";

        /// <summary>Self-tests only — redirected root, cleared afterwards.</summary>
        public static string RootOverride { get; set; }

        private static string Root =>
            RootOverride ?? Path.Combine(
                AutoCommand.Engines.Core.Identity.autocommand().DataRoot, "chat");

        public static string SettingsPath => Path.Combine(Root, "settings.json");
        public static string KeyPath => Path.Combine(Root, "key.bin");

        /// <summary>The endpoint a preset names. Unknown preset → Coding
        /// Plan default (a hand-edited settings.json cannot redirect chat
        /// traffic to an arbitrary URL by typo alone; "custom" is the
        /// explicit, deliberate escape hatch).</summary>
        public static string ResolveBaseUrl(ChatSettings s)
        {
            if (s == null) return CodingPlanBaseUrl;
            return s.EndpointPreset switch
            {
                "standard" => StandardBaseUrl,
                "bigmodel" => BigModelBaseUrl,
                "custom" => string.IsNullOrWhiteSpace(s.CustomBaseUrl) ? CodingPlanBaseUrl : s.CustomBaseUrl.Trim(),
                _ => CodingPlanBaseUrl
            };
        }

        /// <summary>The function-tool list the model sees for these settings:
        /// mutators included only when the user offered them, then converted
        /// from the registry's MCP descriptors to OpenAI shape.</summary>
        public static JsonArray ChatToolsForSettings(ChatSettings s) =>
            GlmChatClient.OpenAiToolsFromDescriptors(AgentToolRegistry.Descriptors(s?.AllowMutating ?? false));

        // ── settings.json ─────────────────────────────────────────────────

        public static ChatSettings Load()
        {
            var s = new ChatSettings();
            try
            {
                if (!File.Exists(SettingsPath)) return s;
                if (JsonNode.Parse(File.ReadAllText(SettingsPath)) is not JsonObject o) return s;
                s.EndpointPreset = o["endpointPreset"]?.ToString() ?? s.EndpointPreset;
                s.CustomBaseUrl = o["customBaseUrl"]?.ToString() ?? "";
                s.Model = o["model"]?.ToString() ?? s.Model;
                s.AllowMutating = o["allowMutating"] is JsonValue m && m.TryGetValue<bool>(out var am) && am;
                s.Consent = o["consent"] is JsonValue c && c.TryGetValue<bool>(out var con) && con;
            }
            catch { /* corrupt settings → defaults; the file is user-editable */ }
            return s;
        }

        public static void Save(ChatSettings s)
        {
            try
            {
                Directory.CreateDirectory(Root);
                var o = new JsonObject
                {
                    ["endpointPreset"] = s.EndpointPreset,
                    ["customBaseUrl"] = s.CustomBaseUrl ?? "",
                    ["model"] = s.Model,
                    ["allowMutating"] = s.AllowMutating,
                    ["consent"] = s.Consent
                };
                File.WriteAllText(SettingsPath, o.ToJsonString());
            }
            catch { /* persistence best-effort, same contract as the pref files */ }
        }

        // ── the API key (DPAPI, port of InterceptCaService's crypt32 calls) ──

        public static bool HasApiKey() => File.Exists(KeyPath);

        public static void SaveApiKey(string key)
        {
            Directory.CreateDirectory(Root);
            var cipher = Protect(Encoding.UTF8.GetBytes(key ?? ""));
            File.WriteAllBytes(KeyPath, cipher);
        }

        /// <summary>The raw key, or null when absent/unreadable (moved to
        /// another user profile, corrupt file) — callers treat null as
        /// "no key", which routes the user back to the setup panel.</summary>
        public static string LoadApiKey()
        {
            try
            {
                if (!File.Exists(KeyPath)) return null;
                var plain = Unprotect(File.ReadAllBytes(KeyPath));
                var key = Encoding.UTF8.GetString(plain);
                return key.Length == 0 ? null : key;
            }
            catch { return null; }
        }

        // DPAPI via raw crypt32 P/Invoke rather than the ProtectedData
        // package — this assembly carries no NuGet dependencies, and the
        // codebase already P/Invokes wininet/setupapi the same way
        // (InterceptCaService, where this port comes from).

        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

        private static byte[] Protect(byte[] plain)
        {
            var inBlob = new DATA_BLOB();
            var outBlob = new DATA_BLOB();
            inBlob.pbData = Marshal.AllocHGlobal(plain.Length);
            try
            {
                Marshal.Copy(plain, 0, inBlob.pbData, plain.Length);
                inBlob.cbData = plain.Length;
                if (!CryptProtectData(ref inBlob, "AutoCommand chat key", IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob))
                    throw new CryptographicException("CryptProtectData failed");
                try
                {
                    var cipher = new byte[outBlob.cbData];
                    Marshal.Copy(outBlob.pbData, cipher, 0, outBlob.cbData);
                    return cipher;
                }
                finally { LocalFree(outBlob.pbData); }
            }
            finally { Marshal.FreeHGlobal(inBlob.pbData); }
        }

        private static byte[] Unprotect(byte[] cipher)
        {
            var inBlob = new DATA_BLOB();
            var outBlob = new DATA_BLOB();
            inBlob.pbData = Marshal.AllocHGlobal(cipher.Length);
            try
            {
                Marshal.Copy(cipher, 0, inBlob.pbData, cipher.Length);
                inBlob.cbData = cipher.Length;
                if (!CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob))
                    throw new CryptographicException("CryptUnprotectData failed");
                try
                {
                    var plain = new byte[outBlob.cbData];
                    Marshal.Copy(outBlob.pbData, plain, 0, outBlob.cbData);
                    return plain;
                }
                finally { LocalFree(outBlob.pbData); }
            }
            finally { Marshal.FreeHGlobal(inBlob.pbData); }
        }
    }
}
