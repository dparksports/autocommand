using System;
using System.Management;
using System.Threading;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== Real-time USB Phantom Device Monitor ===");
        Console.WriteLine("Monitoring VID_0000, VID_054C, VID_05E3 devices.");
        Console.WriteLine("Unplug/plug your keyboard or mouse to see which device causes phantom entries.\n");

        // Watch for device changes
        ManagementEventWatcher watcher = new ManagementEventWatcher();
        WqlEventQuery query = new WqlEventQuery(
            "SELECT * FROM Win32_DeviceChangeEvent"
        );

        watcher.EventArrived += new EventArrivedEventHandler(DeviceChanged);
        watcher.Query = query;
        watcher.Start();

        Console.WriteLine("Press Ctrl+C to exit.\n");

        // Keep the program running
        while (true)
        {
            Thread.Sleep(1000);
        }
    }

    private static void DeviceChanged(object sender, EventArrivedEventArgs e)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - USB device change detected\n");
        PrintRelevantDevices();
    }

    private static void PrintRelevantDevices()
    {
        using (var searcher = new ManagementObjectSearcher(
            "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_0000%' OR DeviceID LIKE '%VID_054C%' OR DeviceID LIKE '%VID_05E3%'"
        ))
        {
            foreach (var device in searcher.Get())
            {
                string status = (device["Status"] ?? "").ToString();
                string name = (device["Name"] ?? "").ToString();
                string deviceId = (device["DeviceID"] ?? "").ToString();
                string pnpClass = (device["PNPClass"] ?? "").ToString();

                // Highlight VID_0000 devices in red
                if (deviceId.Contains("VID_0000"))
                    Console.ForegroundColor = ConsoleColor.Red;
                else
                    Console.ForegroundColor = ConsoleColor.White;

                Console.WriteLine($"[{status}] {pnpClass} - {name} ({deviceId})");
            }
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}
