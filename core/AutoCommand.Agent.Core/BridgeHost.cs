using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AutoCommand.Engines.Bridge;
using AutoCommand.Engines.Core;

namespace AutoCommand.Agent.Core
{
    /// <summary>
    /// App-side composition for the F# AI-bridge engine (Engines.Bridge):
    /// adapts the C# AgentToolRegistry to the engine's IAgentTools seam,
    /// constructs the engine and the MCP client catalog with AutoCommand's
    /// identity/MCP id/proxy name, and exposes both through the C# static
    /// facades the app already calls (AgentBridgeService.Instance /
    /// McpClientCatalog) so every call site compiles unchanged. The engine
    /// carries no app values; this file is the only place they appear.
    /// </summary>
    public static class BridgeHost
    {
        private sealed class ToolAdapter : IAgentTool
        {
            private readonly AgentToolRegistry.Tool _tool;
            public ToolAdapter(AgentToolRegistry.Tool tool) { _tool = tool; }

            public string Name => _tool.Name;
            public bool Mutating => _tool.Mutating;

            public string ConfirmDetail(string argsJson)
            {
                var confirm = _tool.ConfirmDetail;
                if (confirm == null) return null;
                var args = JsonNode.Parse(argsJson ?? "{}") as JsonObject ?? new JsonObject();
                return confirm(args);
            }

            public string Invoke(string argsJson)
            {
                var args = JsonNode.Parse(argsJson ?? "{}") as JsonObject ?? new JsonObject();
                return _tool.Handler(args);
            }
        }

        private sealed class ToolRegistryAdapter : IAgentTools
        {
            public IList<string> Names(bool allowMutating) =>
                new List<string>(AgentToolRegistry.Names(allowMutating));

            public string ListTools(bool allowMutating) =>
                AgentToolRegistry.Descriptors(allowMutating).ToJsonString();

            public IAgentTool Find(string name, bool allowMutating)
            {
                var tool = AgentToolRegistry.Find(name, allowMutating);
                return tool == null ? null : new ToolAdapter(tool);
            }

            public string BuildMonitorSnapshot() =>
                AgentToolRegistry.BuildMonitorSnapshot().ToJsonString();
        }

        /// <summary>Call once at startup (the app or a headless host), before
        /// any session can start. Installs the engine and its tool adapter;
        /// hosts with a UI install the confirm seam separately
        /// (AgentBridgeService.Ui).</summary>
        public static void Wire()
        {
            AutoCommand.Engines.Bridge.AgentBridgeService.Shared =
                new AutoCommand.Engines.Bridge.AgentBridgeService(
                    Identity.autocommand(), new ToolRegistryAdapter());
        }
    }

    /// <summary>
    /// C# facade over the F# bridge engine — the app's static call sites
    /// (Instance, AgentDir, RecentActivity) compile unchanged.
    /// </summary>
    public static class AgentBridgeService
    {
        public static AutoCommand.Engines.Bridge.AgentBridgeService Instance =>
            AutoCommand.Engines.Bridge.AgentBridgeService.Shared;

        public static string AgentDir => Instance.AgentDir;

        public static List<string> RecentActivity => Instance.RecentActivity();
    }

    /// <summary>
    /// C# facade over the F# MCP client catalog — the app's static call
    /// sites (Catalog, IsDetected, Register, ResolveAndInstallProxy,
    /// PreflightProxy, FindStaleRegistrations) compile unchanged.
    /// </summary>
    public static class McpClientCatalog
    {
        private static AutoCommand.Engines.Bridge.McpClientCatalog Engine { get; } =
            new AutoCommand.Engines.Bridge.McpClientCatalog(
                Identity.autocommand(), "autocommand", "AutoCommand.AgentProxy.exe");

        public static IReadOnlyList<McpClientRegistration> Catalog => Engine.Catalog;

        public static bool IsDetected(McpClientRegistration client) => Engine.IsDetected(client);

        // F# engine tuples surface as System.Tuple — C# callers deconstruct
        // (var (a, b) = …) identically.
        public static System.Tuple<bool, string> Register(McpClientRegistration client, string proxyPath) =>
            Engine.Register(client, proxyPath);

        public static System.Tuple<string, string> ResolveAndInstallProxy() =>
            Engine.ResolveAndInstallProxy();

        // internal overload the self-test drives (InternalsVisibleTo)
        internal static System.Tuple<string, string> ResolveAndInstallProxy(
            string appVersion, string root, IEnumerable<string> sourceDirs) =>
            Engine.ResolveAndInstallProxy(appVersion, root, sourceDirs);

        public static System.Tuple<bool, string> PreflightProxy(string proxyExe) =>
            Engine.PreflightProxy(proxyExe);

        public static bool IsRegistered(McpClientRegistration client) => Engine.IsRegistered(client);

        public static System.Tuple<bool, string> Unregister(McpClientRegistration client) =>
            Engine.Unregister(client);

        public static List<AutoCommand.Engines.Bridge.RegistrationOutcome> RegisterDetectedClients(
            string proxyPath, IEnumerable<McpClientRegistration> clients = null) =>
            Engine.RegisterDetectedClients(proxyPath, clients);

        public static List<AutoCommand.Engines.Bridge.StaleMcpRegistration> FindStaleRegistrations(
            string currentProxyPath, IEnumerable<McpClientRegistration> clients = null) =>
            Engine.FindStaleRegistrations(currentProxyPath, clients);

        // junction plumbing the self-test drives (InternalsVisibleTo)
        internal static bool EnsureCurrentJunction(string root, string targetDir) =>
            Engine.EnsureCurrentJunction(root, targetDir);
    }
}
