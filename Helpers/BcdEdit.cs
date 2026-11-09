using System;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Parses bcdedit /enum output. The naive substring test the app used
    /// ("contains 'debug' AND 'yes") matched `recoveryenabled Yes` plus any
    /// debug-family line (`debug No`, `hypervisordebug Off`) — a permanent
    /// false "debug ON" verdict that re-ran `bcdedit /debug off` every 30
    /// seconds and re-alerted on perfectly healthy machines. The value of
    /// the loader's own `debug` line is what counts, and the match is
    /// anchored so no other value name can supply the words.
    /// </summary>
    public static class BcdEdit
    {
        /// <summary>True only when the current loader entry's `debug` line
        /// reads Yes/true/on (case-insensitive; bcdedit's English values).</summary>
        public static bool ParseDebugOn(string bcdEnumOutput)
        {
            if (string.IsNullOrEmpty(bcdEnumOutput)) return false;
            foreach (var raw in bcdEnumOutput.Split('\n'))
            {
                string line = raw.Trim();
                if (!line.StartsWith("debug", StringComparison.OrdinalIgnoreCase))
                    continue; // skips hypervisordebug, debugtype, recoveryenabled...
                string value = line["debug".Length..].Trim();
                if (value.StartsWith("yes", StringComparison.OrdinalIgnoreCase)
                    || value.StartsWith("true", StringComparison.OrdinalIgnoreCase)
                    || value.StartsWith("on", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }
}
