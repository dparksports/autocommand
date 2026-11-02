using System;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Windows.Devices.Enumeration;

namespace DeviceMonitor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting Device Monitor (DeviceWatcher)...");
            Console.WriteLine("Press Ctrl+C to stop.");

            var watcher = DeviceInformation.CreateWatcher();
            watcher.Added += Watcher_Added;
            watcher.Removed += Watcher_Removed;
            watcher.Updated += (s, e) => { }; // Ignore updates to reduce noise

            watcher.Start();

            // Keep alive
            System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
        }

        private static string GetInitiator()
        {
            try
            {
                // Best effort: Get the user associated with the "explorer" process (interactive user)
                var query = new SelectQuery("SELECT UserName FROM Win32_ComputerSystem");
                using (var searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        return mo["UserName"]?.ToString();
                    }
                }
            }
            catch {}
            return WindowsIdentity.GetCurrent().Name;
        }

        private static void Watcher_Added(DeviceWatcher sender, DeviceInformation args)
        {
            PrintEvent("ADDED", ConsoleColor.Green, args.Name, args.Id, args.Kind.ToString());
        }

        private static void Watcher_Removed(DeviceWatcher sender, DeviceInformationUpdate args)
        {
            PrintEvent("REMOVED", ConsoleColor.Red, "Unknown Name (Removed)", args.Id, "Unknown");
        }

        private static void PrintEvent(string type, ConsoleColor color, string name, string id, string kind)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            string initiator = GetInitiator() ?? "Unknown";

            Console.WriteLine();
            Console.ForegroundColor = color;
            Console.WriteLine($"[{timestamp}] {type}");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  Name:      {name}");
            Console.WriteLine($"  Id:        {id}");
            Console.WriteLine($"  Type:      {kind}");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  Initiator: {initiator}");
            Console.ResetColor();
        }
    }
}
