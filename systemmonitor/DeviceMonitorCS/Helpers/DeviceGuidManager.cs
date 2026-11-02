using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DeviceMonitorCS.Helpers
{
    public class DeviceGuidManager
    {
        private readonly string _filePath;
        private HashSet<Guid> _knownGuids = new HashSet<Guid>();

        public DeviceGuidManager()
        {
            // Store Compliance: Use LocalAppData instead of BaseDirectory
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string folderInfo = Path.Combine(appData, "DeviceMonitorCS");
            
            if (!Directory.Exists(folderInfo))
            {
                Directory.CreateDirectory(folderInfo);
            }

            _filePath = Path.Combine(folderInfo, "monitored_guids.txt");
            LoadDefaults();
            LoadCustom();
        }

        private void LoadDefaults()
        {
            // Default Interface GUIDs
            _knownGuids.Add(NativeMethods.GUID_DEVINTERFACE_USB_DEVICE);
            _knownGuids.Add(NativeMethods.GUID_DEVINTERFACE_MONITOR);
            _knownGuids.Add(NativeMethods.GUID_DEVINTERFACE_HID);
            _knownGuids.Add(NativeMethods.GUID_DEVINTERFACE_NET);
            _knownGuids.Add(NativeMethods.GUID_DEVINTERFACE_BLUETOOTH);
            _knownGuids.Add(NativeMethods.GUID_KSCATEGORY_AUDIO);
            _knownGuids.Add(NativeMethods.GUID_DEVINTERFACE_IMAGE);
        }

        private void LoadCustom()
        {
            try
            {
                if (File.Exists(_filePath))
                {
                    var lines = File.ReadAllLines(_filePath);
                    foreach (var line in lines)
                    {
                        if (Guid.TryParse(line.Trim(), out Guid g))
                        {
                            _knownGuids.Add(g);
                        }
                    }
                }
            }
            catch { }
        }

        public IEnumerable<Guid> GetAllGuids()
        {
            return _knownGuids;
        }

        public bool AddAndSave(string guidString)
        {
            if (Guid.TryParse(guidString, out Guid g))
            {
                if (!_knownGuids.Contains(g))
                {
                    _knownGuids.Add(g);
                    Save();
                    return true;
                }
            }
            return false;
        }

        private void Save()
        {
            try
            {
                var customGuids = _knownGuids.Select(g => g.ToString()).ToList();
                File.WriteAllLines(_filePath, customGuids);
            }
            catch { }
        }
    }
}
