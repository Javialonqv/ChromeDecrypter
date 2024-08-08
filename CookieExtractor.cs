using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ChromeDecrypter
{
    internal class CookieExtractor
    {
        // Extracts cookies from the database and decrypts them using the master key
        public static Dictionary<string, List<Dictionary<string, object>>> ExtractCookies(string cookiesFilePath, byte[] keyBytes)
        {
            var groupedData = new Dictionary<string, List<Dictionary<string, object>>>();

            // Open a connection to the SQLite database
            using (var conn = new SQLiteConnection($"Data Source={cookiesFilePath};Version=3;"))
            {
                conn.Open();

                // SQL query to select relevant cookie information
                using (var cmd = new SQLiteCommand(@"SELECT 
                                                host_key, 
                                                name, 
                                                encrypted_value, 
                                                path, 
                                                creation_utc, 
                                                last_access_utc, 
                                                expires_utc, 
                                                is_secure, 
                                                is_httponly, 
                                                has_expires, 
                                                is_persistent, 
                                                priority, 
                                                samesite 
                                             FROM cookies", conn))
                {
                    using (var reader = cmd.ExecuteReader())
                    {
                        // Loop through each row in the result set
                        while (reader.Read())
                        {
                            string hostKey = reader.GetString(0);

                            // Create a dictionary to hold cookie data
                            var cookieData = new Dictionary<string, object>
                            {
                                { "name", reader.GetString(1) },
                                { "decrypted_value", DecryptCookieValue((byte[])reader["encrypted_value"], keyBytes) }, // Decrypt the cookie value
                                { "path", reader.GetString(3) },
                                { "creation_utc", ChromeTimeToDateTime(reader.GetInt64(4)) }, // Convert Chrome time to DateTime
                                { "last_access_utc", ChromeTimeToDateTime(reader.GetInt64(5)) }, // Convert Chrome time to DateTime
                                { "expires_utc", ChromeTimeToDateTime(reader.GetInt64(6)) }, // Convert Chrome time to DateTime
                                { "secure", reader.GetBoolean(7) },
                                { "http_only", reader.GetBoolean(8) },
                                { "session", !reader.GetBoolean(9) }, // Determine if the cookie is a session cookie
                                { "host_only", !reader.GetBoolean(10) }, // Determine if the cookie is host-only
#pragma warning disable CS8604
                                { "same_site", ConvertSameSite(reader.GetInt32(12)) } // Convert SameSite value to string
                            };

                            // Add cookie data to the grouped data dictionary
                            if (!groupedData.ContainsKey(hostKey))
                            {
                                groupedData[hostKey] = new List<Dictionary<string, object>>();
                            }
                            groupedData[hostKey].Add(cookieData);
                        }
                    }
                }
            }

            return groupedData;
        }

        // Decrypts the encrypted cookie value using AES-GCM
        private static string DecryptCookieValue(byte[] encryptedValue, byte[] masterKey)
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

        // Converts Chrome time (microseconds since 1601) to DateTime
        public static DateTime ChromeTimeToDateTime(long chromedate)
        {
            try
            {
                return new DateTime(1601, 1, 1) + TimeSpan.FromTicks(chromedate * 10);
            }
            catch
            {
                return new DateTime(chromedate);
            }
        }

        // Converts the SameSite integer value to a string representation
        private static string? ConvertSameSite(int sameSite)
        {
            switch (sameSite)
            {
                case 0: return "no_restriction";
                case 1: return "lax";
                case 2: return "strict";
                default: return null;
            }
        }

        // Converts a cookie dictionary to a JSON-serializable dictionary
        public static Dictionary<string, object> ConvertCookieToJson(Dictionary<string, object> cookie, string host, string? storeId = null)
        {
#pragma warning disable CS8600
            object expirationDate = cookie["expires_utc"];
            if (expirationDate is DateTime timeObj)
            {
                try
                {
                    expirationDate = ConvertToUnixTimeSecondsWithDecimals(new DateTimeOffset(timeObj));
                }
                catch
                {
                    expirationDate = null;
                }
            }
            else if (!(expirationDate is int) && !(expirationDate is double))
            {
                expirationDate = null;
            }

            return new Dictionary<string, object>
            {
                { "domain", host },
                { "expirationDate", expirationDate },
                { "hostOnly", cookie["host_only"] },
                { "httpOnly", cookie["http_only"] },
                { "name", cookie["name"] },
                { "path", cookie["path"] },
                { "sameSite", cookie["same_site"] },
                { "secure", cookie["secure"] },
                { "session", cookie["session"] },
                { "storeId", storeId },
                { "value", cookie["decrypted_value"] }
            };
        }


        static double ConvertToUnixTimeSecondsWithDecimals(DateTimeOffset dateTimeOffset)
        {
            // Obtener los segundos completos desde la época Unix
            long seconds = dateTimeOffset.ToUnixTimeSeconds();

            // Obtener los microsegundos desde el último segundo completo
            long microseconds = (dateTimeOffset.UtcDateTime.Ticks % TimeSpan.TicksPerSecond) / 10; // Convertir ticks a microsegundos

            // Convertir microsegundos a decimales de segundo
            double decimalSeconds = microseconds / 1_000_000.0;

            // Combinar los segundos y los decimales
            return seconds + decimalSeconds;
        }

        public static void ConvertJSONIntoAnotherFormat(string cookieJSONFilePath, string convertedOutputPath)
        {
            if (!File.Exists(cookieJSONFilePath))
            {
                Console.WriteLine("Can't find \"Cookies.json\" file, please extract them before doing this.");
                return;
            }
            Console.WriteLine("Reading Cookies JSON file...");
            string cookiesContent = File.ReadAllText(cookieJSONFilePath);
            var content = JsonConvert.DeserializeObject<Dictionary<string, List<Dictionary<string, object>>>>(cookiesContent);
            List<Dictionary<string, object>> convertedJSON = new();

            Console.WriteLine("Converting...");
            foreach (var domainCookies in content.Values)
            {
                foreach (var cookie in domainCookies) { convertedJSON.Add(cookie); }
            }

            Console.WriteLine("Saving...");
            File.WriteAllText(convertedOutputPath, JsonConvert.SerializeObject(convertedJSON, Formatting.Indented));
            Console.WriteLine("Saved! Press any key to continue.");
        }
    }
}
