using System.Management;
using System;
using System.Collections.Generic;

class UsbPhantomMonitor
{
    static Dictionary<string, string> knownDevices = new Dictionary<string, string>();

    static void Main()
    {
        Console.WriteLine("=== Real-time USB Phantom Device Monitor ===");
        Console.WriteLine("Monitoring VID_0000, VID_054C, VID_05E3 devices.");
        Console.WriteLine("Unplug/plug your keyboard or mouse to see which device causes phantom entries.");
        Console.WriteLine("Press Ctrl+C to exit.\n");

        // Initialize known devices
        UpdateKnownDevices();

        // Set up WMI event watcher for device changes
        ManagementEventWatcher watcher = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent")
        );

        watcher.EventArrived += new EventArrivedEventHandler(DeviceChanged);
        watcher.Start();

        // Keep app running
        while (true) System.Threading.Thread.Sleep(1000);
    }

    static void DeviceChanged(object sender, EventArrivedEventArgs e)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - USB device change detected");

        // Get current device list
        var currentDevices = new Dictionary<string, string>();
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
        foreach (ManagementObject obj in searcher.Get())
        {
            string deviceId = (obj["DeviceID"] ?? "").ToString();
            string name = (obj["Name"] ?? "").ToString();
            currentDevices[deviceId] = name;
        }

        // Compare to known devices
        foreach (var kvp in currentDevices)
        {
            if (!knownDevices.ContainsKey(kvp.Key))
            {
                string deviceId = kvp.Key;
                string name = kvp.Value;
                string color = "WHITE";

                if (deviceId.Contains("VID_0000"))
                    color = "RED";
                else if (deviceId.Contains("VID_054C"))
                    color = "CYAN";
                else if (deviceId.Contains("VID_05E3"))
                    color = "GREEN";

                Console.ForegroundColor = ConsoleColor.White;
                if (color == "RED") Console.ForegroundColor = ConsoleColor.Red;
                else if (color == "CYAN") Console.ForegroundColor = ConsoleColor.Cyan;
                else if (color == "GREEN") Console.ForegroundColor = ConsoleColor.Green;

                Console.WriteLine($"[NEW] {GetDeviceClass(name)} - {name} ({deviceId})");

                // Special message for phantom devices
                if (deviceId.Contains("VID_0000"))
                    Console.WriteLine(">>> Phantom device detected! Likely caused by the mouse.");

                Console.ResetColor();
            }
        }

        // Update known devices
        knownDevices = currentDevices;
    }

    static void UpdateKnownDevices()
    {
        knownDevices.Clear();
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
        foreach (ManagementObject obj in searcher.Get())
        {
            string deviceId = (obj["DeviceID"] ?? "").ToString();
            string name = (obj["Name"] ?? "").ToString();
            knownDevices[deviceId] = name;
        }
    }

    static string GetDeviceClass(string name)
    {
        name = name.ToLower();
        if (name.Contains("mouse") || name.Contains("hid"))
            return "Mouse";
        if (name.Contains("keyboard"))
            return "Keyboard";
        if (name.Contains("hub"))
            return "USB";
        return "System";
    }
}
