using System;
using System.Security.Cryptography.X509Certificates;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Authenticode signer checks for binaries this elevated app is about to
    /// launch with admin rights when the path itself came from a
    /// user-writable source (HKCU values, %LOCALAPPDATA% scans, %TEMP%
    /// caches). Signature + trusted chain + subject pin: an unsigned plant or
    /// a foreign-signed binary fails, whatever its file name claims to be.
    /// </summary>
    public static class SignatureChecker
    {
        /// <summary>
        /// True when the file carries an Authenticode signature that chains to
        /// a trusted root and whose signer subject is Microsoft Corporation.
        /// Best-effort: any failure reading or validating reads as "not
        /// trusted", so callers fall back to safer paths, never forward.
        /// </summary>
        public static bool IsMicrosoftSigned(string path)
        {
            try
            {
                // CreateFromSignedFile returns the base X509Certificate; the
                // chain builder needs the X509Certificate2 wrapper.
                using var signed = X509Certificate.CreateFromSignedFile(path);
                using var cert = new X509Certificate2(signed);
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                if (!chain.Build(cert)) return false;
                return cert.Subject.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }
}
