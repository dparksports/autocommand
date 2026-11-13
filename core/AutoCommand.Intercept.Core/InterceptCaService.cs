using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace AutoCommand.Intercept.Core
{
        /// <summary>
        /// The intercept CA and its leaf minting. Layer 3's dangerous part,
        /// caged: one RSA-2048 CA per install ("CN=AutoCommand Intercept CA"),
        /// persisted under %LOCALAPPDATA%\AutoCommand\intercept so sessions
        /// reuse it, installed into the MACHINE Root store only while an
        /// intercept session runs and removed when it ends. Leaf certificates
        /// are minted per hostname, cached briefly — a session never generates
        /// hundreds of keys.
        ///
        /// The persisted PFX is DPAPI-encrypted (current user): the key backs a
        /// CA that is trusted machine-wide during sessions, so the file at rest
        /// must not be raw-exportable key material any same-user process could
        /// lift and reuse. The directory itself is created admin/SYSTEM-only
        /// (see EnsureRealDirHardened) so the sibling crash-recovery journal —
        /// replay input for elevated netsh calls — cannot be forged by a
        /// non-elevated process. Nothing here ever touches LSASS or Schannel
        /// internals: the CA is the standard, user-visible mechanism, auditable
        /// in certmgr as "AutoCommand Intercept CA" whenever it is trusted.
        /// </summary>
    internal static class InterceptCaService
    {
        private const string CaSubject = "CN=AutoCommand Intercept CA,O=AutoCommand";

        private static string _dirOverride;

        /// <summary>Test seam: the self-test points the CA dir (and with it
        /// the journal path) at a temp directory, never at real user state.</summary>
        internal static string DirOverride
        {
            get => _dirOverride;
            set => _dirOverride = value;
        }

        internal static string Dir
        {
            get
            {
                if (_dirOverride != null) return _dirOverride;
                EnsureRealDirHardened();
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AutoCommand", "intercept");
            }
        }

        private static bool _hardenAttempted;

        // The real intercept dir holds the crash-recovery journal — replay
        // input for elevated netsh calls — and the CA pfx. Both must be out
        // of reach for non-elevated same-user processes, so the directory is
        // created admin/SYSTEM-only (same shape as ProgramDataGuard; the
        // app is elevated and keeps full access). One-shot, best-effort:
        // failures never block callers, and the test seam (DirOverride)
        // bypasses this entirely — a non-elevated self-test must not ACL
        // itself out of its own temp root.
        private static void EnsureRealDirHardened()
        {
            if (_hardenAttempted) return;
            _hardenAttempted = true;
            try
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AutoCommand", "intercept");
                Directory.CreateDirectory(dir);

                var info = new DirectoryInfo(dir);
                var security = info.GetAccessControl();
                security.SetAccessRuleProtection(true, false);
                var sidAdmins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var sidSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    sidAdmins, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(
                    sidSystem, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                info.SetAccessControl(security);
            }
            catch { /* non-elevated or odd filesystem — the journal-field
                      validation in InterceptSystemHooks remains the second
                      lock on this door */ }
        }

        private static string CaPath => Path.Combine(Dir, "ca.pfx");

        private static readonly object Gate = new();
        private static X509Certificate2 _ca;
        private static readonly Dictionary<string, (X509Certificate2 Cert, DateTime MintedUtc)> _leafCache =
            new(StringComparer.OrdinalIgnoreCase);

        // ── DPAPI (crypt32) ───────────────────────────────────────────────
        // Raw P/Invoke rather than the ProtectedData package: this assembly
        // deliberately carries no NuGet dependencies, and the codebase
        // already uses wininet/setupapi P/Invokes the same way.

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
                if (!CryptProtectData(ref inBlob, "AutoCommand intercept CA", IntPtr.Zero,
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

        /// <summary>The CA, creating and persisting it on first use.</summary>
        internal static X509Certificate2 GetOrCreateCa()
        {
            lock (Gate)
            {
                if (_ca != null) return _ca;
                if (_ca == null)
                {
                    try
                    {
                        if (File.Exists(CaPath))
                        {
                            byte[] raw = File.ReadAllBytes(CaPath);
                            // DPAPI first; a legacy plaintext PFX (pre-DPAPI
                            // install) still loads and is upgraded in place.
                            byte[] pfx;
                            try { pfx = Unprotect(raw); }
                            catch (CryptographicException)
                            {
                                pfx = raw;
                                File.WriteAllBytes(CaPath, Protect(raw)); // upgrade at rest
                            }
                            _ca = X509CertificateLoader.LoadPkcs12(pfx, null);
                        }
                    }
                    catch { /* unreadable pfx — regenerate below */ }
                }

                if (_ca == null || !_ca.HasPrivateKey || DateTime.UtcNow > _ca.NotAfter.AddDays(-30))
                {
                    using var rsa = RSA.Create(2048);
                    var request = new CertificateRequest(CaSubject, rsa,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                        certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(
                        X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
                    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(
                        request.PublicKey, false));
                    _ca = request.CreateSelfSigned(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(2));

                    Directory.CreateDirectory(Dir);
                    File.WriteAllBytes(CaPath, Protect(_ca.Export(X509ContentType.Pfx)));
                }
                return _ca;
            }
        }

        /// <summary>The persisted CA's thumbprint WITHOUT creating one — the
        /// startup repair sweep asks "is our CA on disk?" before deciding
        /// whether machine trust is stranded; GetOrCreateCa would mint a new
        /// CA as a side effect, which is exactly what the sweep must not do.
        /// Null when nothing is persisted.</summary>
        internal static string TryGetPersistedThumbprint()
        {
            lock (Gate)
            {
                if (_ca != null) return _ca.Thumbprint;
                try
                {
                    if (!File.Exists(CaPath)) return null;
                    byte[] raw = File.ReadAllBytes(CaPath);
                    byte[] pfx;
                    try { pfx = Unprotect(raw); }
                    catch (CryptographicException) { pfx = raw; }
                    using var cert = X509CertificateLoader.LoadPkcs12(pfx, null);
                    return cert.Thumbprint;
                }
                catch { return null; }
            }
        }

        /// <summary>Our exact CA subject, for the repair sweep's stranded-trust
        /// scan (older installs' CA files may be gone while the Root entry
        /// survives).</summary>
        internal static string CaSubjectForRepair => CaSubject;

        // ── Root store lifecycle ──────────────────────────────────────────

        /// <summary>Trusts the CA machine-wide for the session's duration.
        /// Requires elevation (the app's manifest guarantees it).</summary>
        internal static void InstallToRoot()
        {
            var ca = GetOrCreateCa();
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            var existing = store.Certificates.Find(X509FindType.FindByThumbprint, ca.Thumbprint, validOnly: false);
            if (existing.Count == 0) store.Add(ca);
        }

        /// <summary>
        /// Removes exactly our CA (by thumbprint) — never a blanket store
        /// cleanup. Returns true when no cert with that thumbprint remains in
        /// the store (including "was never installed"); false means the
        /// removal must be retried — callers keep the undo journal so the
        /// next app start's RecoverAfterCrash tries again.
        /// </summary>
        internal static bool RemoveFromRoot(string thumbprint = null)
        {
            string tp = thumbprint ?? GetOrCreateCa().Thumbprint;
            try
            {
                using (var ro = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
                {
                    ro.Open(OpenFlags.ReadOnly);
                    if (ro.Certificates.Find(X509FindType.FindByThumbprint, tp, validOnly: false).Count == 0)
                        return true;
                }
                using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                var matches = store.Certificates.Find(X509FindType.FindByThumbprint, tp, validOnly: false);
                foreach (var cert in matches)
                    store.Remove(cert);
                return store.Certificates.Find(X509FindType.FindByThumbprint, tp, validOnly: false).Count == 0;
            }
            catch { return false; /* RecoverAfterCrash retries at next app start */ }
        }

        // ── leaf minting ──────────────────────────────────────────────────

        /// <summary>
        /// A server certificate for one hostname (or IP), signed by the CA.
        /// Cached per hostname per 10 minutes — reused connections and
        /// reconnects do not re-mint.
        /// </summary>
        internal static X509Certificate2 GetOrMintLeaf(string host)
        {
            lock (Gate)
            {
                if (_leafCache.TryGetValue(host, out var cached) &&
                    DateTime.UtcNow - cached.MintedUtc < TimeSpan.FromMinutes(10))
                    return cached.Cert;

                var ca = GetOrCreateCa();
                using var rsa = RSA.Create(2048);
                var request = new CertificateRequest($"CN={host}", rsa,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false)); // serverAuth
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));

                bool isIp = IPAddress.TryParse(host, out var ip);
                var sanBuilder = new SubjectAlternativeNameBuilder();
                if (isIp) sanBuilder.AddIpAddress(ip);
                else sanBuilder.AddDnsName(host);
                request.CertificateExtensions.Add(sanBuilder.Build());

                // Fresh random serial per leaf — RFC 5280 requires per-CA
                // uniqueness; reusing the CA's own serial (the old behavior)
                // breaks revocation semantics for every leaf. High bit is
                // cleared: the serial is a positive big-endian integer.
                var serial = RandomNumberGenerator.GetBytes(16);
                serial[0] &= 0x7F;
                var leaf = request.Create(ca, DateTime.UtcNow.AddMinutes(-5),
                    DateTime.UtcNow.AddDays(7), serial);
                // CopyWithPrivateKey returns the cert WITH its private key —
                // the chain to the CA is built by clients via the Root store.
                var leafWithKey = leaf.CopyWithPrivateKey(rsa);

                _leafCache[host] = (leafWithKey, DateTime.UtcNow);
                return leafWithKey;
            }
        }

        /// <summary>Drops every cached leaf (private keys included). Called
        /// at session stop: without this, the last session's minted keys sit
        /// in a static dictionary for the life of the process, long past the
        /// session that justified minting them.</summary>
        internal static void ClearLeafCache()
        {
            lock (Gate)
            {
                foreach (var entry in _leafCache.Values)
                    try { entry.Cert.Dispose(); } catch { }
                _leafCache.Clear();
            }
        }
    }
}
