using Google.Apis.Auth.OAuth2;
using Google.Apis.Util.Store;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DeviceMonitorCS.Services
{
    public class UserProfile
    {
        public string UserId { get; set; }
        public string Name { get; set; }
        public bool IsGuest { get; set; }
    }

    public class AuthenticationService
    {
        public UserProfile CurrentUser { get; private set; }

        public AuthenticationService()
        {
            // Always initialize as Guest / Test Drive User
            var guestId = GetOrGenerateGuestId();
            CurrentUser = new UserProfile
            {
                UserId = guestId,
                Name = "Test Drive User",
                IsGuest = true
            };
        }

        private string GetOrGenerateGuestId()
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DeviceMonitorCS");
            var path = Path.Combine(folder, "guest_id.txt");

            if (File.Exists(path))
            {
                return File.ReadAllText(path);
            }

            var newId = Guid.NewGuid().ToString();
            Directory.CreateDirectory(folder);
            File.WriteAllText(path, newId);
            return newId;
        }
    }
}
