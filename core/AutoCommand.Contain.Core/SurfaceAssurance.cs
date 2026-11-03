using System;

namespace AutoCommand.Contain.Core
{
    /// <summary>What the machine actually looks like for the SSTP and kernel-debug
    /// attack surfaces, probed by the caller (SecurityEnforcer). Pure data — the
    /// probes stay in the app layer; this shape exists so the verdict evaluation
    /// can be tested offline with synthetic states.</summary>
    public sealed class SurfaceState
    {
        // SSTP surface
        public bool SstpServiceInstalled;
        public bool SstpServiceRunning;
        public int SstpStartValue = -1;         // registry Start value; -1 = unknown/unreadable
        public bool SstpMiniportsPresent;        // any SSTP-family WAN miniport enumerated

        // Kernel-debug surface
        public bool BcdDebugOn;                  // bcdedit shows debug yes
        public bool KdnicActive;                 // working KDNIC adapter present
    }

    /// <summary>One surface's verified answer: is the machine actually clean right
    /// now — independent of any preference file.</summary>
    public sealed class SurfaceVerdict
    {
        public string Surface;                   // "SSTP service" | "Kernel debug"
        public bool Clean;                       // machine truth: nothing to attack
        public bool Allowed;                     // user allow-listed (drift recorded, NOT remediated)
        public string Summary;                   // one-line, user-facing
        public DateTime VerifiedUtc;
    }

    /// <summary>
    /// The "are SSTP / kernel debug actually off and removed?" evaluators.
    ///
    /// Pure functions over a probed SurfaceState — no service, registry, WMI or
    /// bcdedit calls here, so the verdict logic is provable offline. The probe
    /// (ServiceController, registry Start value, WAN-miniport enumeration, bcdedit)
    /// lives in SecurityEnforcer; it fills a SurfaceState and calls in.
    ///
    /// Key property: the verdict is computed from the machine, never from the
    /// allow-list files — a whitelisted-but-drifted surface reports
    /// Clean=false with Allowed=true, so the UI can say exactly what is true.
    /// </summary>
    public static class SurfaceAssurance
    {
        public const string SstpSurfaceName = "SSTP service";
        public const string KdnetSurfaceName = "Kernel debug";

        /// <summary>Desired (clean) SSTP state: service present but stopped, startup
        /// type Disabled (Start=4), and no SSTP-family WAN miniports enumerated.</summary>
        public static SurfaceVerdict EvaluateSstp(SurfaceState s, bool allowed)
        {
            var v = new SurfaceVerdict
            {
                Surface = SstpSurfaceName,
                Allowed = allowed,
                VerifiedUtc = DateTime.UtcNow,
            };

            if (!s.SstpServiceInstalled)
            {
                v.Clean = true;
                v.Summary = "SstpSvc not installed - nothing to attack";
                return v;
            }

            bool serviceDown = !s.SstpServiceRunning && s.SstpStartValue == 4;
            v.Clean = serviceDown && !s.SstpMiniportsPresent;

            if (v.Clean)
            {
                v.Summary = "stopped + Disabled (Start=4), no SSTP miniports present";
            }
            else if (s.SstpStartValue == -1)
            {
                v.Summary = "startup type unreadable - treat as NOT clean";
            }
            else
            {
                string what = "";
                if (s.SstpServiceRunning) what = "service running";
                else if (s.SstpStartValue != 4) what = "startup type not Disabled (Start=" + s.SstpStartValue + ")";
                else what = "no drift";
                if (s.SstpMiniportsPresent)
                    what = what == "no drift" ? "SSTP miniports present" : what + " + SSTP miniports present";
                else if (what == "no drift")
                    what = "miniport presence unknown";
                v.Summary = what;
            }
            return v;
        }

        /// <summary>Desired (clean) kernel-debug state: no 'debug yes' in the BCD for
        /// the current boot, and no working KDNIC adapter present.</summary>
        public static SurfaceVerdict EvaluateKdnet(SurfaceState s, bool allowed)
        {
            var v = new SurfaceVerdict
            {
                Surface = KdnetSurfaceName,
                Allowed = allowed,
                VerifiedUtc = DateTime.UtcNow,
            };

            v.Clean = !s.BcdDebugOn && !s.KdnicActive;
            if (v.Clean)
                v.Summary = "kernel debug off in the BCD, no KDNIC adapter present";
            else if (s.BcdDebugOn && s.KdnicActive)
                v.Summary = "kernel debug ON in the BCD + active KDNIC adapter";
            else if (s.BcdDebugOn)
                v.Summary = "kernel debug ON in the BCD";
            else
                v.Summary = "active KDNIC adapter present";
            return v;
        }
    }
}
