using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Data.SQLite;
using Newtonsoft.Json;
using System.Web;
using System.Security.Policy;

namespace ChromeDecrypter
{
    internal static class Decrypter
    {
        public static string outputFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "Cookies.txt");
        public static string jsonOutputFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "Cookies.json");

        public static string outputLoginDataFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "Login Data.txt");
        public static string jsonLoginDataOutputFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "Login Data.json");

        public static void DecryptBrowserKey(string browserDataPath, string outputFilePath)
        {
            string localStateFilePath = Path.Combine(browserDataPath, "Local State");
            if (!File.Exists(localStateFilePath))
            {
                Console.WriteLine("Can't find \"Local State\" file.");
                return;
            }

            string localStateContent = File.ReadAllText(localStateFilePath);
            Console.WriteLine("Reading \"Local State\" file...");
            var regex = new Regex("\"encrypted_key\"\\s*:\\s*\"([^\"]+)\"");
            var match = regex.Match(localStateContent);

            if (!match.Success)
            {
                Console.WriteLine("Can't find encrypted key on the \"Local State\" file.");
                Console.ReadKey();
                return;
            }

            string encryptedKeyBase64 = match.Groups[1].Value;
            // Convert the base64 string to byte array
            Console.WriteLine("Converting from Base64...");
            byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKeyBase64);

            // Strip the 'DPAPI' prefix
            byte[] dpapiBytes = new byte[encryptedKeyBytes.Length - 5];
            Array.Copy(encryptedKeyBytes, 5, dpapiBytes, 0, dpapiBytes.Length);

            // Decrypt the bytes using DPAPI
            Console.WriteLine("Decrypting DPAPI bytes...");
            byte[] decryptedBytes = ProtectedData.Unprotect(dpapiBytes, null, DataProtectionScope.CurrentUser);

            // Write the decrypted master key to the output file
            Console.WriteLine("Saving key file...");
            File.WriteAllBytes(outputFilePath, decryptedBytes);
            Console.WriteLine("Key file saved! Press any key to continue.");
        }

        public static void SaveCookies(string browserDataPath, bool isOperaSelected, string keyPath)
        {
            string cookiesFilePath = Path.Combine(browserDataPath, isOperaSelected ? "" : "Default", "Network", "Cookies");
            if (!File.Exists(cookiesFilePath))
            {
                Console.WriteLine("Can't find \"Cookies\" file.");
                return;
            }
            if (!File.Exists(keyPath))
            {
                Console.WriteLine("Can't find \"BrowserKey\" file. Please, decrypt the browser key before doing this.");
                return;
            }

            Console.WriteLine("Reading the browser key...");
            byte[] keyBytes = File.ReadAllBytes(keyPath);
            Console.WriteLine("Extracting cookies...");
            var groupedData = CookieExtractor.ExtractCookies(cookiesFilePath, keyBytes);

            if (!Program.executedWithArgs)
            {
                askForSaveFile:
                Console.Write("Do you want to save the extracted cookies on an output file? (Y/n): ");
                ConsoleKey pressedKey = Console.ReadKey().Key;
                if (pressedKey == ConsoleKey.Y)
                {
                    askForJSONFile:
                    Console.Write("\nJSON file? (Y/n): ");
                    pressedKey = Console.ReadKey().Key;
                    if (pressedKey == ConsoleKey.Y)
                    {
                        Console.WriteLine("\nSaving JSON file..");
                        WriteCookiesToFile(groupedData, jsonOutputFilePath, true);
                        Console.WriteLine("Saved JSON file!");
                    }
                    else if (pressedKey != ConsoleKey.N)
                    {
                        goto askForJSONFile;
                    }
                    if (pressedKey != ConsoleKey.Y)
                    {
                        Console.WriteLine("\nSaving output file..");
                        WriteCookiesToFile(groupedData, outputFilePath, false);
                        Console.WriteLine("Saved output file!");
                    }
                }
                else if (pressedKey != ConsoleKey.N) { Console.WriteLine(""); goto askForSaveFile; }
                Console.WriteLine("\n");
            }
            else
            {
                WriteCookiesToFile(groupedData, jsonOutputFilePath, true);
            }

            // Prompt the user to specify a domain and print cookies for that domain
            if (Program.executedWithArgs) return;

            Console.Write("Do yo wanna see the cookies from an specific domain? Put it or leave it blank: ");
#pragma warning disable CS8600, CS8604
            string domain = Console.ReadLine();
            if (!string.IsNullOrEmpty(domain)) { PrintCookiesForDomain(groupedData, domain); return; }
            Console.WriteLine("Press any key to continue.");
        }

        public static void DecryptLoginData(string browserDataPath, bool isOperaSelected, string keyPath)
        {
            string loginDataFilePath = Path.Combine(browserDataPath, isOperaSelected ? "" : "Default", "Login Data");
            if (!File.Exists(loginDataFilePath))
            {
                Console.WriteLine("Can't find \"Login Data\" file.");
                return;
            }
            if (!File.Exists(keyPath))
            {
                Console.WriteLine("Can't find \"BrowserKey\" file. Please, decrypt the browser key before doing this.");
                return;
            }

            Console.WriteLine("Reading BrowserKey file...");
            byte[] keyBytes = File.ReadAllBytes(keyPath);
            Console.WriteLine("Extracting Login Data...");

            List<Dictionary<string, string>> loginData = new();

            using (var conn = new SQLiteConnection($"Data Source={loginDataFilePath};Version=3;"))
            {
                conn.Open();
                string query = "SELECT action_url, origin_url, username_value, password_value FROM logins";
                using (var cmd = new SQLiteCommand(query, conn))
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        byte[] encryptedPassword = (byte[])reader["password_value"];
                        string actionUrl = reader["action_url"].ToString();
                        string originUrl = reader["origin_url"].ToString();

                        Dictionary<string, string> loginDataInfo = new()
                        {
                            { "url", string.IsNullOrEmpty(actionUrl) ? originUrl : actionUrl },
                            { "username", reader["username_value"].ToString() },
                            { "password", DecryptPassword(encryptedPassword, keyBytes) }
                        };
                        loginData.Add(loginDataInfo);
                    }
                }
            }

            if (!Program.executedWithArgs)
            {
                askForSaveFile:
                Console.Write("Do you want to save the extracted login data on an output file? (Y/n): ");
                ConsoleKey pressedKey = Console.ReadKey().Key;
                if (pressedKey == ConsoleKey.Y)
                {
                    askForJSONFile:
                    Console.Write("\nJSON file? (Y/n): ");
                    pressedKey = Console.ReadKey().Key;
                    if (pressedKey == ConsoleKey.Y)
                    {
                        Console.WriteLine("\nSaving JSON file..");
                        WriteLoginDataToFile(loginData, jsonLoginDataOutputFilePath, true);
                        Console.WriteLine("Saved JSON file!");
                    }
                    else if (pressedKey != ConsoleKey.N)
                    {
                        goto askForJSONFile;
                    }
                    if (pressedKey != ConsoleKey.Y)
                    {
                        Console.WriteLine("\nSaving output file..");
                        WriteLoginDataToFile(loginData, outputLoginDataFilePath, false);
                        Console.WriteLine("Saved output file!");
                    }
                }
                else if (pressedKey != ConsoleKey.N) { Console.WriteLine(""); goto askForSaveFile; }
            }
            else
            {
                WriteLoginDataToFile(loginData, jsonLoginDataOutputFilePath, true);
            }

            if (Program.executedWithArgs) return;

            Console.Write("Do you want to see the credentials from an specific website? Put it or leave empty: ");
#pragma warning disable CS8600, CS8604
            string website = Console.ReadLine();
            if (!string.IsNullOrEmpty(website)) { DisplayCredentials(loginData, website); return; }
            Console.WriteLine("Press any key to continue.");
        }

        // Decrypts the encrypted cookie value using AES-GCM
        private static string DecryptPassword(byte[] encryptedValue, byte[] masterKey)
        {
            try
            {
                // IV y payload
                byte[] iv = new byte[12];
                byte[] payload;
                Buffer.BlockCopy(encryptedValue, 3, iv, 0, iv.Length);
                payload = new byte[encryptedValue.Length - iv.Length - 3];
                Buffer.BlockCopy(encryptedValue, iv.Length + 3, payload, 0, payload.Length);

                // Separar el ciphertext y el tag
                byte[] tag = new byte[16];
                byte[] ciphertext = new byte[payload.Length - tag.Length];
                Buffer.BlockCopy(payload, 0, ciphertext, 0, ciphertext.Length);
                Buffer.BlockCopy(payload, ciphertext.Length, tag, 0, tag.Length);

                // Decryptar
                using (var aes = new AesGcm(masterKey))
                {
                    byte[] plaintext = new byte[ciphertext.Length];
                    aes.Decrypt(iv, ciphertext, tag, plaintext);
                    return Encoding.UTF8.GetString(plaintext);
                }
            }
            catch
            {
                return "Chrome < 80";
            }
        }

        // Writes the extracted cookies to the output file
        private static void WriteCookiesToFile(Dictionary<string, List<Dictionary<string, object>>> groupedData, string outputFilePath, bool jsonFormat)
        {
            using (var outputFile = new StreamWriter(outputFilePath, false, Encoding.UTF8))
            {
                if (jsonFormat) // If wanna save on a json
                {
                    Dictionary<string, List<Dictionary<string, object>>> jsonToSave = new();
                    foreach (var host in groupedData.Keys)
                    {
                        List<Dictionary<string, object>> cookies = new();
                        foreach (var domainCookies in groupedData[host])
                        {
                            cookies.Add(CookieExtractor.ConvertCookieToJson(domainCookies, host));
                        }
                        jsonToSave.Add(host, cookies);
                    }
                    outputFile.Write(JsonConvert.SerializeObject(jsonToSave, Formatting.Indented));
                }
                else
                {
                    foreach (var host in groupedData.Keys)
                    {
                        outputFile.WriteLine(new string('=', 70));
                        outputFile.WriteLine($"Host: {host}");
                        foreach (var cookie in groupedData[host])
                        {
                            outputFile.WriteLine();
                            foreach (var key in cookie.Keys)
                            {
                                outputFile.WriteLine($"{key.Replace('_', ' ')}: {cookie[key]}");
                            }
                        }
                        outputFile.WriteLine(new string('=', 70));
                        outputFile.WriteLine();
                    }
                }
            }
        }

        private static void WriteLoginDataToFile(List<Dictionary<string, string>> loginData, string outputFilePath, bool jsonFormat)
        {
            using (var outputFile = new StreamWriter(outputFilePath, false, Encoding.UTF8))
            {
                if (jsonFormat) // If wanna save on a json
                {
                    outputFile.Write(JsonConvert.SerializeObject(loginData, Formatting.Indented));
                }
                else
                {
                    foreach (var loginDataInfo in loginData)
                    {
                        outputFile.WriteLine(new string('=', 70));
                        outputFile.WriteLine($"Url: {loginDataInfo["url"]}");
                        outputFile.WriteLine($"Username: {loginDataInfo["username"]}");
                        outputFile.WriteLine($"Password: {loginDataInfo["password"]}");
                        outputFile.WriteLine(new string('=', 70));
                        outputFile.WriteLine();
                    }
                }
            }
        }

        // Prints cookies for the specified domain in JSON format
        private static void PrintCookiesForDomain(Dictionary<string, List<Dictionary<string, object>>> groupedData, string domain)
        {
            Console.Clear();
            if (groupedData.ContainsKey(domain))
            {
                var cookiesJson = new List<Dictionary<string, object>>();
                foreach (var cookie in groupedData[domain])
                {
                    cookiesJson.Add(CookieExtractor.ConvertCookieToJson(cookie, domain));
                }
                Console.WriteLine(JsonConvert.SerializeObject(cookiesJson, Formatting.Indented));
            }
            else
            {
                Console.WriteLine($"No cookies found for domain: {domain}.");
            }
        }

        private static void DisplayCredentials(List<Dictionary<string, string>> loginData, string website)
        {
            Console.Clear();
            foreach (var loginDataInfo in loginData)
            {
                if (loginDataInfo["url"] == website)
                {
                    string separator = new string('-', 60);
                    Console.WriteLine(separator);
                    Console.WriteLine($"URL: {loginDataInfo["url"]}");
                    Console.WriteLine($"User Name: {loginDataInfo["username"]}");
                    Console.WriteLine($"Password: {loginDataInfo["password"]}");
                    Console.WriteLine(separator);
                    Console.WriteLine();
                    break;
                }
            }
        }
    }
}
