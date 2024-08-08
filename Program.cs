using ChromeDecrypter;
using CommandLine;
using System;
using System.Data.Entity.Core.Objects.DataClasses;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    static Dictionary<int, string> browserDataPaths = new()
    {
        { 0, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "/AppData/Local/Google/Chrome/User Data/" },
        { 1, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "/AppData/Local/Microsoft/Edge/User Data/" },
        { 2, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "/AppData/Roaming/Opera Software/Opera Stable/" },
        { 3, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "/AppData/Roaming/Opera Software/Opera GX Stable/" }
    };
    static bool isOperaSelected;
    public static bool executedWithArgs = false;
    static int action = 0;
    static int browser = 0;

    //static string keyOutputFilePath = Directory.GetCurrentDirectory() + "/BrowserKey";
    static string keyOutputFilePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath), "Output", "BrowserKey");

    public class Options
    {
        [Option('a', "-action", Required = true, HelpText = "Sets the action to execute (DecryptKey/DecryptCookies/DecryptLoginData/DecryptAll).")]
        public string action { get; set; } = "";
        [Option('b', "-browser", Required = true, HelpText = "Sets the target browser (Chrome/Edge/Opera/OperaGX).")]
        public string browser { get; set; } = "";
    }

    static void Main(string[] args)
    {
        if (!Directory.Exists(Path.GetDirectoryName(keyOutputFilePath))) { Directory.CreateDirectory(Path.GetDirectoryName(keyOutputFilePath)); }
        System.Environment.SetEnvironmentVariable("SQLite_NoConfigure", "1");

        if (args.Length == 0)
        {
            Console.Clear();
            ChooseAction();
            Console.Clear();
            if (action < 5) ChooseBrowser();

            if (action == 1)
            {
                Console.Clear();
                Decrypter.DecryptBrowserKey(browserDataPaths[browser], keyOutputFilePath);
            }
            else if (action == 2)
            {
                Console.Clear();
                Decrypter.SaveCookies(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
            }
            else if (action == 3)
            {
                Console.Clear();
                Decrypter.DecryptLoginData(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
            }
            else if (action == 4)
            {
                Console.Clear();
                Decrypter.DecryptBrowserKey(browserDataPaths[browser], keyOutputFilePath);
                Console.Clear();
                Decrypter.SaveCookies(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
                Console.Clear();
                Decrypter.DecryptLoginData(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
            }
            else if (action == 5)
            {
                Console.Clear();
                SSHExecution.Init();
            }
            else if (action == 6)
            {
                Environment.Exit(0);
            }
            Console.ReadKey();
            Main(args);
        }
        else if (args.Length == 4)
        {
            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
            {
                if (o.action == "DecryptKey") { action = 1; }
                else if (o.action == "DecryptCookies") { action = 2; }
                else if (o.action == "DecryptLoginData") { action = 3; }
                else if (o.action == "DecryptAll") { action = 4; }

                if (o.browser == "Chrome") { browser = 0; }
                if (o.browser == "Edge") { browser = 1; }
                if (o.browser == "Opera") { browser = 2; }
                if (o.browser == "OperaGX") { browser = 3; }
            }
            );

            executedWithArgs = true;
            if (action == 1)
            {
                //Console.Clear();
                Decrypter.DecryptBrowserKey(browserDataPaths[browser], keyOutputFilePath);
            }
            else if (action == 2)
            {
                //Console.Clear();
                Decrypter.SaveCookies(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
            }
            else if (action == 3)
            {
                //Console.Clear();
                Decrypter.DecryptLoginData(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
            }
            else if (action == 4)
            {
                //Console.Clear();
                Decrypter.DecryptBrowserKey(browserDataPaths[browser], keyOutputFilePath);
                Decrypter.SaveCookies(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
                Decrypter.DecryptLoginData(browserDataPaths[browser], isOperaSelected, keyOutputFilePath);
            }
        }
    }

    static void ChooseAction()
    {
        Console.WriteLine("What do you want to do?\n");
        Console.WriteLine("[1] Decrypt Browser Key");
        Console.WriteLine("[2] Decrypt Browser Cookies");
        Console.WriteLine("[3] Decrypt Browser Login Data");
        Console.WriteLine("[4] Decrypt All");
        Console.WriteLine("[6] Execute in SSH");
        Console.WriteLine("[7] Exit\n");
        Console.Write("> ");
        string? input = Console.ReadLine();
        if (int.TryParse(input, out int result))
        {
            if (result >= 1 && result <= 7)
            {
                action = result;
                return;
            }
        }

        Console.WriteLine("Please enter a valid option.");
        ChooseAction();
    }
    static void ChooseBrowser()
    {
        Console.WriteLine("Which browser is the target?\n");
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
                browser = result - 1;
                if (result == 3 || result == 4) { isOperaSelected = true; }
                return;
            }
        }

        Console.WriteLine("Please enter a valid option.");
        ChooseBrowser();
    }
}