using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace F2B_Installer
{
    internal class Installer
    {
        public static void Write(String txt, String foreground, String background)
        {
            if (background != null)
            {
                switch (background.ToLower())
                {
                    case "back":
                        Console.BackgroundColor = ConsoleColor.Black;
                        break;
                    case "white":
                        Console.BackgroundColor = ConsoleColor.White;
                        break;
                    case "red":
                        Console.BackgroundColor = ConsoleColor.Red;
                        break;
                    case "cyan":
                        Console.BackgroundColor = ConsoleColor.Cyan;
                        break;
                    case "green":
                        Console.BackgroundColor = ConsoleColor.Green;
                        break;
                    case "gray":
                        Console.BackgroundColor = ConsoleColor.Gray;
                        break;
                    case "blue":
                        Console.BackgroundColor = ConsoleColor.Blue;
                        break;
                    case "darkblue":
                        Console.BackgroundColor = ConsoleColor.DarkBlue;
                        break;
                    case "darkcyan":
                        Console.BackgroundColor = ConsoleColor.DarkCyan;
                        break;
                    case "darkgray":
                        Console.BackgroundColor = ConsoleColor.DarkGray;
                        break;
                    case "darkgreen":
                        Console.BackgroundColor = ConsoleColor.DarkGreen;
                        break;
                    case "darkmagenta":
                        Console.BackgroundColor = ConsoleColor.DarkMagenta;
                        break;
                    case "darkred":
                        Console.BackgroundColor = ConsoleColor.DarkRed;
                        break;
                    case "darkyellow":
                        Console.BackgroundColor = ConsoleColor.DarkYellow;
                        break;
                    case "magenta":
                        Console.BackgroundColor = ConsoleColor.Magenta;
                        break;
                    case "yellow":
                        Console.BackgroundColor = ConsoleColor.Yellow;
                        break;
                }
            }
            //#######
            if (foreground != null)
            {
                switch (foreground.ToLower())
                {
                    case "back":
                        Console.ForegroundColor = ConsoleColor.Black;
                        break;
                    case "white":
                        Console.ForegroundColor = ConsoleColor.White;
                        break;
                    case "red":
                        Console.ForegroundColor = ConsoleColor.Red;
                        break;
                    case "cyan":
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        break;
                    case "green":
                        Console.ForegroundColor = ConsoleColor.Green;
                        break;
                    case "gray":
                        Console.ForegroundColor = ConsoleColor.Gray;
                        break;
                    case "blue":
                        Console.ForegroundColor = ConsoleColor.Blue;
                        break;
                    case "darkblue":
                        Console.ForegroundColor = ConsoleColor.DarkBlue;
                        break;
                    case "darkcyan":
                        Console.ForegroundColor = ConsoleColor.DarkCyan;
                        break;
                    case "darkgray":
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        break;
                    case "darkgreen":
                        Console.ForegroundColor = ConsoleColor.DarkGreen;
                        break;
                    case "darkmagenta":
                        Console.ForegroundColor = ConsoleColor.DarkMagenta;
                        break;
                    case "darkred":
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        break;
                    case "darkyellow":
                        Console.ForegroundColor = ConsoleColor.DarkYellow;
                        break;
                    case "magenta":
                        Console.ForegroundColor = ConsoleColor.Magenta;
                        break;
                    case "yellow":
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        break;
                }
            }

            Console.Write(txt);
            Console.ResetColor();
        }

        public static void InternExtract(string path, string outfile, string embededfile)
        {
            string writepfilepath;

            if (path == null || path == "")
            {
                writepfilepath = outfile;
            }
            else
            {
                writepfilepath = path + outfile;
            }

            try
            {
                Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("F2B_Installer." + embededfile);
                FileStream fileStream = new(writepfilepath, FileMode.Create);
                for (int i = 0; i < stream.Length; i++)
                    fileStream.WriteByte((byte)stream.ReadByte());
                fileStream.Close();
            }
            catch (UnauthorizedAccessException)
            {
                var attributes = File.GetAttributes(writepfilepath);
                if ((attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                {
                    attributes &= ~FileAttributes.Hidden;
                    File.SetAttributes(writepfilepath, attributes);
                }
                InternExtract(path, outfile, embededfile);
            }
            catch (System.IO.DirectoryNotFoundException)
            {
                Directory.CreateDirectory(path);
                InternExtract(path, outfile, embededfile);
            }
        }

        //##################################################################################

        static void Main()
        {
            Console.WriteLine();

            String IN;

            //kheck for installation
            if (File.Exists("C:\\Program Files\\OpenSSH-Fail2Ban\\F2B-SRV.exe") && File.Exists("C:\\Program Files\\OpenSSH-Fail2Ban\\F2B-CLI.exe"))
            {
                Write("F2B Installation found, overwrite?", "darkyellow", null);
                Write(" [y/n]: ", "darkgray", null);

                IN = Console.ReadLine();

                if (IN.ToLower() != "y")
                {
                    Write("\nExiting..\n", "gray", null);

                    Write("[press enter to exit] ", "darkgray", null);

                    Console.ReadLine();

                    return;
                }

                if (new ServiceController("OpenSSH Fail2Ban").Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending or ServiceControllerStatus.ContinuePending)
                {
                    Write("\nStoppig Service..\n", "gray", null);

                    new ServiceController("OpenSSH Fail2Ban").Stop();
                }
                else
                {
                    Console.WriteLine();
                }

                Write("Closing mmc.exe\n", "gray", null);
                PowerShell.Create().AddScript("taskkill /im mmc.exe /f").Invoke();

                Write("Unregistering 'OpenSSH Fail2Ban'\n\n", "gray", null);
                PowerShell.Create().AddScript("sc.exe delete \"OpenSSH Fail2Ban\"\n\n").Invoke();
            }
            else
            {
                Write("Install Open-SSH-Fail2Ban service??", "darkcyan", null);
                Write(" [y/n]: ", "darkgray", null);

                IN = Console.ReadLine();

                if (IN.ToLower() != "y")
                {
                    Write("\nExiting..\n", "gray", null);

                    Write("[press enter to exit] ", "darkgray", null);

                    Console.ReadLine();

                    return;
                }
                else
                {
                    Console.WriteLine();
                }
            }

            //add to path variable
            Write("Installing..\n\n", "green", null);

            String PathV = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine);

            if (PathV.Contains("C:\\Program Files\\OpenSSH-Fail2Ban"))
            {
                Write("Skipping 'Path' integration\n", "darkgray", null);
            }
            else
            {
                Write("Integratig F2B to Machine Path Variable\n", "gray", null);

                Environment.SetEnvironmentVariable("Path", Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine) + ";C:\\Program Files\\OpenSSH-Fail2Ban;", EnvironmentVariableTarget.Machine);
            }

            //extract files
            Write("Extracting Files..\n", "gray", null);

            Write("config.txt\n", "gray", null);
            InternExtract("C:\\Program Files\\OpenSSH-Fail2Ban\\", "config.txt", "config.txt");

            Write("F2B-CLI.exe\n", "gray", null);
            InternExtract("C:\\Program Files\\OpenSSH-Fail2Ban\\", "F2B-CLI.exe", "F2B-CLI.exe");

            Write("F2B-SRV.exe\n", "gray", null);
            InternExtract("C:\\Program Files\\OpenSSH-Fail2Ban\\", "F2B-SRV.exe", "F2B-SRV.exe");

            //register service
            Write("Registering F2B-SRV.exe as a service with name 'OpenSSH Fail2Ban'\n", "gray", null);
            PowerShell.Create().AddScript("New-Service -Name \"OpenSSH Fail2Ban\" -BinaryPathName \"C:\\Program Files\\OpenSSH-Fail2Ban\\F2B-SRV.exe\" -Description \"Protects the OpenSSH server service from brute-force attacks.\"").Invoke();

            Write("\nDone\n\n", "green", null);

            //ask to start service
            Write("Start the 'OpenSSH Fail2Ban' service now?", "darkcyan", null);
            Write(" [y/n]: ", "darkgray", null);

            IN = Console.ReadLine();

            if (IN.ToLower() != "y")
            {
                Write("\nExiting..\n", "gray", null);

                Write("[press enter to exit] ", "darkgray", null);

                Console.ReadLine();

                return;
            }

            Write("\nStarting..\n", "gray", null);
            new ServiceController("OpenSSH Fail2Ban").Start();

            Thread.Sleep(3000);

            for (Int32 i = 0; new ServiceController("OpenSSH Fail2Ban").Status != ServiceControllerStatus.Running; i++)
            {
                Thread.Sleep(100);

                if (i == 200)
                {
                    Write("\nError\n", "red", null);

                    Write("[press enter to exit] ", "darkgray", null);

                    Console.ReadLine();

                    return;
                }
            }

            Write("\nInstallation successfully\n", "green", null);
            Write("[press enter to exit] ", "darkgray", null);

            Console.ReadLine();
        }
    }
}
