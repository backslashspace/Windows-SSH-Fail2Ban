using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace F2B_CLI
{
    internal class Program
    {
        //=========================================================================================================================

        const String Version = "1.0.0.0";

        public class Config
        {
            public static String[] LogScanTime { get; set; }
            public static String[] LogScanIntervall { get; set; }
            public static List<String> BanTimeUnit { get; set; }
            public static List<Int32> BanTimeNum { get; set; }
            public static Boolean CountBannerError { get; set; }
            public static Boolean CatchNegotiationErrors { get; set; }
            public static Boolean PermBan { get; set; }
            public static Int32 FailTrigger { get; set; }
        }

        //---------------------------------------

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

        public static String[,] GetLog()
        {
            //get lookup time
            string LogTime = Config.LogScanTime[1] switch
            {
                "m" => DateTime.Now.AddMinutes(Int32.Parse(Config.LogScanTime[0]) * -1).ToUniversalTime().ToString("o"),
                "h" => DateTime.Now.AddHours(Int32.Parse(Config.LogScanTime[0]) * -1).ToUniversalTime().ToString("o"),
                "d" => DateTime.Now.AddDays(Int32.Parse(Config.LogScanTime[0]) * -1).ToUniversalTime().ToString("o"),
                "M" => DateTime.Now.AddMonths(Int32.Parse(Config.LogScanTime[0]) * -1).ToUniversalTime().ToString("o"),
                _ => DateTime.Now.AddHours(-1).ToUniversalTime().ToString("o"),
            };

            //read eventlog
            EventLogQuery QueryResult = new("OpenSSH/Operational", PathType.LogName, $"*[System[TimeCreated[@SystemTime>='{LogTime}']]]")
            {
                ReverseDirection = true
            };

            EventLogReader ELR = new(QueryResult);

            List<EventRecord> ER = new();

            while (true)
            {
                EventRecord Rec = ELR.ReadEvent();

                if (Rec == null)
                {
                    break;
                }

                ER.Add(Rec);
            }

            //final Outlist
            List<String> Users = new();
            List<String> IPs = new();

            String[] temp;

            for (Int32 i = 0; i < ER.Count; i++)
            {
                String WorkString = ER[i].Properties[1].Value.ToString();

                void None()
                {
                    Regex RGX1 = new("Failed none for ");
                    Regex RGX2 = new("invalid user ");

                    String User = "";

                    String temp = RGX1.Replace(WorkString, "", 1);

                    if (temp.Contains("invalid user"))
                    {
                        temp = RGX2.Replace(temp, "$[None]Invalid-User$=", 1);
                    }

                    String[] sarr = temp.Split(' ');

                    for (Int32 e = 0; e < sarr.Length - 5; e++)
                    {
                        User += sarr[e];

                        if (e + 6 < sarr.Length)
                        {
                            User += " ";
                        }
                    }

                    if (IsIP(sarr[sarr.Length - 4], out String TIP, true))
                    {
                        IPs.Add(TIP);

                        Users.Add(User);
                    }
                }

                void FailedPassword()
                {
                    Regex RGX1 = new("Failed password for ");
                    Regex RGX2 = new("invalid user ");

                    String User = "";

                    String temp = RGX1.Replace(WorkString, "", 1);

                    if (temp.Contains("invalid user"))
                    {
                        temp = RGX2.Replace(temp, "$Invalid-User$=", 1);
                    }

                    String[] sarr = temp.Split(' ');

                    for (Int32 e = 0; e < sarr.Length - 5; e++)
                    {
                        User += sarr[e];

                        if (e + 6 < sarr.Length)
                        {
                            User += " ";
                        }
                    }

                    if (IsIP(sarr[sarr.Length - 4], out String TIP, true))
                    {
                        IPs.Add(TIP);

                        Users.Add(User);
                    }
                }

                void KeyFile()
                {
                    Regex RGX = new("Connection reset by authenticating user ");

                    String User = "";

                    String temp = RGX.Replace(WorkString, "$Invalid-KeyFile$=", 1);

                    String[] sarr = temp.Split(' ');

                    for (Int32 e = 0; e < sarr.Length - 4; e++)
                    {
                        User += sarr[e];

                        if (e + 5 < sarr.Length)
                        {
                            User += " ";
                        }
                    }

                    if (IsIP(sarr[sarr.Length - 4], out String TIP, true))
                    {
                        IPs.Add(TIP);

                        Users.Add(User);
                    }
                }

                void KeyFileUser()
                {
                    Regex RGX = new("Invalid user ");

                    String User = "";

                    String temp = RGX.Replace(WorkString, "$Invalid-KeyFile-User$=", 1);

                    String[] sarr = temp.Split(' ');

                    for (Int32 e = 0; e < sarr.Length - 4; e++)
                    {
                        User += sarr[e];

                        if (e + 5 < sarr.Length)
                        {
                            User += " ";
                        }
                    }

                    if (IsIP(sarr[sarr.Length - 3], out String TIP, true))
                    {
                        IPs.Add(TIP);

                        Users.Add(User);
                    }
                }

                void BannerExchange()
                {
                    Regex RGX = new(".*from ");
                    Regex RGX2 = new(" port.*");

                    String temp = RGX.Replace(WorkString, "", 1);

                    temp = RGX2.Replace(temp, "", 1);

                    if (IsIP(temp, out String TIP, true))
                    {
                        IPs.Add(TIP);

                        Users.Add("$BannerError$");
                    }
                }

                void NegotiationError()
                {
                    Regex RGX = new(" port.*");
                    Regex RGX2 = new(".*with ");

                    String temp = RGX.Replace(WorkString, "", 1);
                    temp = RGX2.Replace(temp, "", 1);

                    if (IsIP(temp, out String TIP, true))
                    {
                        IPs.Add(TIP);

                        Users.Add("$CipherMismatch$");
                    }
                }

                temp = WorkString.Split(' ');

                if (WorkString == "Authentication refused." || WorkString.Contains(" ::1 ") || WorkString.Contains(" 127.0.0.1 "))
                {
                    continue;
                }
                else if (temp[0] == "Failed" && temp[1] == "password")
                {
                    FailedPassword();
                    continue;
                }
                else if (temp[1] == "user")
                {
                    KeyFileUser();
                    continue;
                }
                else if (temp[3] == "authenticating" && temp[1] != "closed")
                {
                    KeyFile();
                    continue;
                }
                else if (Config.CountBannerError && temp[1] == "exchange:")
                {
                    BannerExchange();
                    continue;
                }
                else if (Config.CatchNegotiationErrors && temp[2] == "negotiate")
                {
                    NegotiationError();
                    continue;
                }
                else if (temp[1] == "none")
                {
                    None();
                    continue;
                }
            }

            //form a
            String[,] OutArray = new string[IPs.Count, 2];

            for (Int32 i = 0; i < IPs.Count; i++)
            {
                if (IPs[i].Contains('%'))
                {
                    OutArray[i, 0] = IPs[i].Split('%')[0];
                }
                else
                {
                    OutArray[i, 0] = IPs[i];
                }

                OutArray[i, 1] = Users[i];
            }

            return OutArray;
        }

        public static dynamic GetReg(String Path, String Value, RegistryValueKind ExpectedType, Boolean DeleteWrongType)
        {
            //return null when missing or DeleteWrongType true (after deleteion)
            //return -1 when wrong type and DeleteWrongType false
            var Out = Registry.GetValue(Path, Value, null);

            if (Out == null)
            {
                return null;
            }

            switch (ExpectedType)
            {
                case RegistryValueKind.String:
                    if (Out is String)
                    {
                        return Out;
                    }
                    return Fallback();
                case RegistryValueKind.DWord:
                    if (Out is Int32)
                    {
                        return Out;
                    }

                    return Fallback();
                case RegistryValueKind.QWord:
                    if (Out is Int64)
                    {
                        return Out;
                    }

                    return Fallback(); ;
                case RegistryValueKind.MultiString:
                    if (Out is String[])
                    {
                        return Out;
                    }

                    return Fallback();
                case RegistryValueKind.Binary:
                    if (Out is Byte[] || Out is Int16[] || Out is Int32[] || Out is Int64[])
                    {
                        return Out;
                    }

                    return Fallback();
                default:
                    return null;
            }

            dynamic Fallback()
            {
                if (DeleteWrongType)
                {
                    String DPath = Path.Split('\\')[0];
                    Path = Regex.Match(Path, "(?<=\\\\).*").ToString();

                    RegistryKey Key = DPath.ToUpper() switch
                    {
                        "HKEY_LOCAL_MACHINE" => Registry.LocalMachine.OpenSubKey(Path, true),
                        "HKEY_CURRENT_USER" => Registry.CurrentUser.OpenSubKey(Path, true),
                        "HKEY_CLASSES_ROOT" => Registry.ClassesRoot.OpenSubKey(Path, true),
                        "HKEY_USERS" => Registry.Users.OpenSubKey(Path, true),
                        "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig.OpenSubKey(Path, true),
                        _ => null
                    };

                    try
                    {
                        using (Key)
                        {
                            Key.DeleteValue(Value, false);
                        }
                    }
                    catch (System.ArgumentException) { }

                    return null;
                }

                return -1;
            }
        }

        public static String[] FetchUniqueIPs(String[,] Log)
        {
            List<String> temp = new() { };

            for (Int32 i = 0; i < Log.GetLength(0); i++)
            {
                temp.Add(Log[i, 0]);
            }

            String[] Output = temp.Distinct().ToArray();

            return Output;
        }

        public static String[] LogDetails(String IP, String[,] Log)
        {
            //returns ustring, attemps in []

            String UString = "";
            String temp;

            Int32 Attempts = 0;
            Boolean FirstRun = true;

            for (Int32 i = 0; i < Log.GetLength(0); i++)
            {
                temp = Log[i, 1];

                if (!UString.Contains(temp) && Log[i, 0] == IP)
                {
                    if (FirstRun)
                    {
                        UString += temp;

                        FirstRun = false;
                    }
                    else
                    {
                        UString += ", " + temp;
                    }
                }

                if (Log[i, 0].Contains(IP))
                {
                    Attempts++;
                }
            }

            return new String[] { UString, Attempts.ToString() };
        }

        public static Boolean IsIP(String InIP, out String OutIP, Boolean RMP)
        {
            //returns bool (is or not ip), if activ naked ip out

            if (IPAddress.TryParse(InIP.ToUpper(), out _))
            {
                if (RMP && InIP.Contains('%'))
                {
                    OutIP = InIP.Split('%')[0];
                }
                else
                {
                    OutIP = InIP;
                }

                return true;
            }
            else
            {
                OutIP = null;

                return false;
            }
        }

        public static void LoadConfig()
        {
            //static config read

            Boolean LogScanTime = true;
            Boolean CountBannerError = true;
            Boolean CatchNegotiationErrors = true;
            Boolean FailTrigger = true;
            Boolean PermBan = true;
            Boolean LogScanIntervall = true;

            Boolean BanTime = true;

            String Errors = "";

            //

            String[] Data;

            try
            {
                Data = File.ReadAllLines(System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\config.txt");
            }
            catch (Exception)
            {
                Write("Error reading config file\n└ Fallback to to default\n", "red", null);

                Config.PermBan = true;
                Config.CountBannerError = true;
                Config.CatchNegotiationErrors = false;
                Config.FailTrigger = 12;
                Config.LogScanTime = new String[] { "1", "h" };
                Config.LogScanIntervall = new String[] { "5", "s" };

                Config.BanTimeUnit = new List<String> { "h", "h", "d", "d", "d", "M", "M" };
                Config.BanTimeNum = new List<Int32> { 1, 3, 1, 7, 1, 1, 3 };

                EventOut("Error reading config file (C:\\Program Files\\OpenSSH-Fail2Ban\\config.txt)\n\nFallback to defaults", EventLogEntryType.Error, 7);

                return;
            }

            foreach (String Line in Data)
            {
                if (!Line.Contains("#"))
                {
                    String CLine = Line.Replace(" ", "");

                    if (CLine == "")
                    {
                        continue;
                    }
                    else if (CLine.Contains("LogScanTime="))
                    {
                        Write("LogScanTime = ", "gray", null);

                        String[] temp = CLine.Split('=')[1].Split('/');

                        if (temp.Length < 2)
                        {
                            Write("Error [Invalid Config]: " + temp[0] + "\n", "red", null);
                            Write("└ Fallback to 1h\n", "darkyellow", null);

                            Config.LogScanTime = new String[] { "1", "h" };

                            LogScanTime = false;

                            Errors += "LogScanTime: fallback to 1h\n";

                            continue;
                        }

                        if (temp[1].Contains("m") || temp[1].Contains("h") || temp[1].Contains("d") || temp[1].Contains("M"))
                        {
                            try
                            {
                                Int32 I = Int32.Parse(temp[0]);

                                if (I < 0)
                                {
                                    I *= -1;
                                }

                                Write(I + temp[1] + "\n", "gray", null);

                                Config.LogScanTime = new String[] { I.ToString(), temp[1] };
                            }
                            catch (Exception)
                            {
                                Write("Error [Invalid Config]: " + temp[0] + "\n", "red", null);
                                Write("└ Fallback to 1h\n", "darkyellow", null);

                                Errors += "LogScanTime: fallback to 1h\n";

                                Config.LogScanTime = new String[] { "1", "h" };
                            }
                        }
                        else
                        {
                            Write("Error [Invalid Config] (Time Unit): " + temp[1] + "\n", "red", null);
                            Write("└ Fallback to 1h\n", "darkyellow", null);

                            Errors += "LogScanTime: fallback to 1h\n";

                            Config.LogScanTime = new String[] { "1", "h" };
                        }

                        LogScanTime = false;
                    }

                    else if (CLine.Contains("FailTrigger="))
                    {
                        Write("FailTrigger = ", "gray", null);

                        String temp = CLine.Split('=')[1];

                        try
                        {
                            Int32 I = Int32.Parse(temp);

                            if (I < 0)
                            {
                                I *= -1;
                            }

                            Config.FailTrigger = I;

                            Write(I + "\n", "gray", null);
                        }
                        catch (Exception)
                        {
                            Write("Error [Invalid Config]: Invalid Format (requires Int32)\n", "red", null);
                            Write("└ Fallback to 12\n", "darkyellow", null);

                            Errors += "FailTrigger: fallback to 10\n";
                        }

                        FailTrigger = false;
                    }

                    else if (CLine.Contains("LogScanIntervall="))
                    {
                        Write("LogScanIntervall = ", "gray", null);

                        String[] temp = CLine.Split('=')[1].Split('/');

                        if (temp.Length < 2)
                        {
                            Write("Error [Invalid Config]: " + temp[0] + "\n", "red", null);
                            Write("└ Fallback to 5s\n", "darkyellow", null);

                            Config.LogScanIntervall = new String[] { "5", "s" };
                            LogScanIntervall = false;

                            Errors += "LogScanIntervall: fallback to 5s\n";

                            continue;
                        }

                        if (temp[1].Contains("s") || temp[1].Contains("m") || temp[1].Contains("h") || temp[1].Contains("d"))
                        {
                            try
                            {
                                Int32 I = Int32.Parse(temp[0]);

                                if (I < 0)
                                {
                                    I *= -1;
                                }

                                Write(I + temp[1] + "\n", "gray", null);

                                Config.LogScanIntervall = new String[] { I.ToString(), temp[1] };
                            }
                            catch (Exception)
                            {
                                Write("Error [Invalid Config]: " + temp[0] + "\n", "red", null);
                                Write("└ Fallback to 5s\n", "darkyellow", null);

                                Errors += "LogScanIntervall: fallback to 5s\n";

                                Config.LogScanIntervall = new String[] { "5", "s" };
                            }
                        }
                        else
                        {
                            Write("Error [Invalid Config] (Time Unit): " + temp[1] + "\n", "red", null);
                            Write("└ Fallback to 5s\n", "darkyellow", null);

                            Errors += "LogScanIntervall: fallback to 5s\n";

                            Config.LogScanIntervall = new String[] { "5", "s" };
                        }

                        LogScanIntervall = false;
                    }

                    else if (CLine.Contains("CountBannerError="))
                    {
                        Write("CountBannerError = ", "gray", null);

                        String temp = CLine.Split('=')[1];

                        if (temp == "true")
                        {
                            Write("true\n", "gray", null);

                            Config.CountBannerError = true;
                        }
                        else if (temp == "false")
                        {
                            Write("false\n", "gray", null);

                            Config.CountBannerError = false;
                        }
                        else
                        {
                            Write("Error [Invalid Config] (Boolean): " + temp + "\n", "red", null);
                            Write("└ Fallback to true\n", "darkyellow", null);

                            Errors += "CountBannerError: fallback to true\n";

                            Config.CountBannerError = true;
                        }

                        CountBannerError = false;
                    }

                    else if (CLine.Contains("CatchNegotiationErrors="))
                    {
                        Write("CatchNegotiationErrors = ", "gray", null);

                        String temp = CLine.Split('=')[1];

                        if (temp == "true")
                        {
                            Write("true\n", "gray", null);

                            Config.CatchNegotiationErrors = true;
                        }
                        else if (temp == "false")
                        {
                            Write("false\n", "gray", null);

                            Config.CatchNegotiationErrors = false;
                        }
                        else
                        {
                            Write("Error [Invalid Config] (Boolean): " + temp + "\n", "red", null);
                            Write("└ Fallback to false\n", "darkyellow", null);

                            Errors += "CatchNegotiationErrors: fallback to true\n";

                            Config.CatchNegotiationErrors = true;
                        }

                        CatchNegotiationErrors = false;
                    }

                    else if (CLine.Contains("PermBan="))
                    {
                        Write("PermBan = ", "gray", null);

                        String temp = CLine.Split('=')[1];

                        if (temp == "true")
                        {
                            Write("true\n", "gray", null);

                            Config.PermBan = true;
                        }
                        else if (temp == "false")
                        {
                            Write("false\n", "gray", null);

                            Config.PermBan = false;
                        }
                        else
                        {
                            Write("Error [Invalid Config] (Boolean): " + temp + "\n", "red", null);
                            Write("└ Fallback to false\n", "darkyellow", null);

                            Errors += "PermBan: fallback to false\n";

                            Config.PermBan = false;
                        }

                        PermBan = false;
                    }

                    //

                    else if (CLine.Contains("BanTime="))
                    {
                        String[] pre;

                        Config.BanTimeNum = new List<Int32>();
                        Config.BanTimeUnit = new List<String>();

                        //when single
                        if (!CLine.Contains(','))
                        {
                            if (CLine.Split('=')[1] == "off" && Config.PermBan)
                            {
                                Config.BanTimeUnit.Add("off");

                                BanTime = false;

                                continue;
                            }

                            pre = CLine.Split('=')[1].Split('/');

                            if (pre.Length == 2 && (pre[1].Contains("m") || pre[1].Contains("h") || pre[1].Contains("d") || pre[1].Contains("M")))
                            {
                                try
                                {
                                    Int32 I = Int32.Parse(pre[0]);

                                    if (I < 0)
                                    {
                                        I *= -1;
                                    }

                                    Config.BanTimeNum.Add(I);
                                    Config.BanTimeUnit.Add(pre[1]);

                                    Write("BanTime = " + I + pre[1] + "\n", "gray", null);

                                    BanTime = false;
                                }
                                catch (Exception)
                                {
                                    break;
                                }
                            }
                            else
                            {
                                break;
                            }
                        }
                        //when more
                        else
                        {
                            pre = CLine.Split('=')[1].Split(',');

                            BanTime = false;

                            for (Int32 i = 0; i < pre.Length; i++)
                            {
                                String[] temp = pre[i].Split('/');

                                if (temp[0] == "off")
                                {
                                    continue;
                                }
                                else if (temp.Length != 2)
                                {
                                    BanTime = true;

                                    break;
                                }

                                if (temp[1].Contains("m") || temp[1].Contains("h") || temp[1].Contains("d") || temp[1].Contains("M"))
                                {
                                    try
                                    {
                                        Int32 I = Int32.Parse(temp[0]);

                                        if (I < 0)
                                        {
                                            I *= -1;
                                        }

                                        Config.BanTimeNum.Add(I);
                                        Config.BanTimeUnit.Add(temp[1]);
                                    }
                                    catch (Exception)
                                    {
                                        BanTime = true;

                                        break;
                                    }
                                }
                                else
                                {
                                    BanTime = true;

                                    break;
                                }
                            }

                            if (!BanTime)
                            {
                                Write("BanTime = ", "gray", null);

                                for (Int32 i = 0; i < Config.BanTimeNum.Count; i++)
                                {
                                    if (i + 1 == Config.BanTimeNum.Count)
                                    {
                                        Write(Config.BanTimeNum[i] + Config.BanTimeUnit[i], "gray", null);
                                    }
                                    else
                                    {
                                        Write(Config.BanTimeNum[i] + Config.BanTimeUnit[i] + ", ", "gray", null);
                                    }
                                }

                                Console.WriteLine();
                            }
                        }
                    }
                }
            }

            //chek for missing config
            if (LogScanIntervall)
            {
                Write("Loaded default for LogScanTime\n", "darkyellow", null);
                Config.LogScanTime = new String[] { "1", "h" };
            }
            if (LogScanTime)
            {
                Write("Loaded default for LogScanIntervall\n", "darkyellow", null);
                Config.LogScanIntervall = new String[] { "5", "s" };
            }
            if (CountBannerError)
            {
                Write("Loaded default for CountBannerError\n", "darkyellow", null);
                Config.CountBannerError = true;
            }
            if (CatchNegotiationErrors)
            {
                Write("Loaded default for CatchNegotiationErrors\n", "darkyellow", null);
                Config.CatchNegotiationErrors = true;
            }
            if (FailTrigger)
            {
                Write("Loaded default for FailTrigger\n", "darkyellow", null);
                Config.FailTrigger = 12;
            }
            if (PermBan)
            {
                Write("Loaded default for PermBan\n", "darkyellow", null);
                Config.PermBan = true;
            }
            if (BanTime)
            {
                Config.BanTimeUnit = new List<String> { "h", "h", "d", "d", "d", "M", "M" };
                Config.BanTimeNum = new List<Int32> { 1, 3, 1, 7, 1, 1, 3 };

                Write("BanTime = ", "gray", null);
                Write("Error [Invalid Config] (Invalide Format)\n", "red", null);
                Write("└ Fallback to ", "darkyellow", null);

                Errors += "BanTime: fallback to 1/h,3/h,1/d,7/d,14/d,1/M,3/M\n";

                for (Int32 i = 0; i < Config.BanTimeNum.Count; i++)
                {
                    if (i + 1 == Config.BanTimeNum.Count)
                    {
                        Write(Config.BanTimeNum[i] + Config.BanTimeUnit[i], "gray", null);
                    }
                    else
                    {
                        Write(Config.BanTimeNum[i] + Config.BanTimeUnit[i] + ", ", "gray", null);
                    }
                }

                Console.WriteLine();
            }

            if (Errors != "")
            {
                EventOut("Error loading config:\n" + Errors, EventLogEntryType.Error, 6);
            }

            return;
        }

        public static class DB
        {
            public static Boolean BanStatus(String IP)
            { 
                if (!IsIP(IP, out IP, false))
                {
                    return false;
                }

                try
                {
                    String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", false).GetValueNames();

                    String temp;

                    foreach (var V in VNames)
                    {
                        try
                        {
                            temp = IPAddress.Parse(V.ToUpper().Split('#')[1]).ToString();

                            if (temp == IP)
                            {
                                return true;
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    return false;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            public static Boolean IsTrusted(String IP, Boolean RMWrongTyp)
            {
                return GetReg("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH-Fail2Ban\\Trusted", IP, RegistryValueKind.DWord, RMWrongTyp) switch
                {
                    null => false,
                    -1 => false,
                    _ => true,
                };
            }

            public static Int32 Create(String IP, String BanTime, String UnBanTime)
            {
                try
                {
                    String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", false).GetValueNames();

                    Int32 NewID = 0;

                    Boolean ValideID = true;

                    //get lowest free id
                    while (true)
                    {
                        foreach (String V in VNames)
                        {
                            if (V.Split('#')[0] == NewID.ToString() && V.Contains('#'))
                            {
                                ValideID = false;

                                break;
                            }
                        }

                        if (ValideID)
                        {
                            break;
                        }
                        else
                        {
                            ValideID = true;
                        }

                        NewID++;
                    }

                    Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH-Fail2Ban\Banned", NewID + "#" + IP, BanTime + "#" + UnBanTime, RegistryValueKind.String);

                    return NewID;
                }
                catch (Exception)
                {
                    Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH-Fail2Ban\Banned", 0 + "#" + IP, BanTime + "#" + UnBanTime, RegistryValueKind.String);

                    return 0;
                }
            }
        }

        public static void EventOut(String Message, EventLogEntryType Type, Int32 LogID)
        {
            if (!EventLog.SourceExists("OpenSSH-Fail2Ban"))
            {
                EventLog.CreateEventSource("OpenSSH-Fail2Ban", "OpenSSH-Fail2Ban");
            }

            using EventLog eventLog = new("OpenSSH-Fail2Ban");
            eventLog.Source = "OpenSSH-Fail2Ban";
            eventLog.WriteEntry(Message, Type, LogID, 0);
            eventLog.Dispose();
        }

        public static void Ban(String IP, String Users, Int32 Attempts)
        {
            //get history
            Int32 Hist = IPHistory(IP);

            //set hitory + 1 in reg
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH-Fail2Ban\History", IP, Hist + 1, RegistryValueKind.DWord);

            //get ban time
            DateTime BanTime = DateTime.Now;

            //get UnBanTime, Ban-ID, duration string & create DB entry
            dynamic UnBanTime = DateTime.Now;
            Int32 BanID = 0;
            String Duration = null;

            Boolean Ethy = false;

            void PermaBan()
            {
                UnBanTime = " --- --- ";
                BanID = DB.Create(IP, BanTime.ToString(), "---------- --------");
                Duration = "$Permanent$";

                Ethy = true;
            }

            if (Config.PermBan && Config.BanTimeUnit[0] == "off")
            {
                PermaBan();
            }
            else
            {
                if (Hist <= 0)
                {
                    switch (Config.BanTimeUnit[0])
                    {
                        case "m":
                            UnBanTime = BanTime.AddMinutes(Config.BanTimeNum[0]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[0] + " minute*s";
                            break;
                        case "h":
                            UnBanTime = BanTime.AddHours(Config.BanTimeNum[0]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[0] + " hour*s";
                            break;
                        case "d":
                            UnBanTime = BanTime.AddDays(Config.BanTimeNum[0]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[0] + " day*s";
                            break;
                        case "M":
                            UnBanTime = BanTime.AddMonths(Config.BanTimeNum[0]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[0] + " month*s";
                            break;
                    }
                }
                else if (Config.BanTimeUnit.Count > Hist)
                {
                    switch (Config.BanTimeUnit[Hist])
                    {
                        case "m":
                            UnBanTime = BanTime.AddMinutes(Config.BanTimeNum[Hist]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Hist] + " minute*s";
                            break;
                        case "h":
                            UnBanTime = BanTime.AddHours(Config.BanTimeNum[Hist]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Hist] + " hour*s";
                            break;
                        case "d":
                            UnBanTime = BanTime.AddDays(Config.BanTimeNum[Hist]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Hist] + " day*s";
                            break;
                        case "M":
                            UnBanTime = BanTime.AddMonths(Config.BanTimeNum[Hist]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Hist] + " month*s";
                            break;
                    }
                }
                else if (Config.PermBan)
                {
                    PermaBan();
                }
                else
                {
                    switch (Config.BanTimeUnit[Config.BanTimeUnit.Count - 1])
                    {
                        case "m":
                            UnBanTime = BanTime.AddMinutes(Config.BanTimeNum[Config.BanTimeNum.Count - 1]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Config.BanTimeNum.Count - 1] + " minute*s";
                            break;
                        case "h":
                            UnBanTime = BanTime.AddHours(Config.BanTimeNum[Config.BanTimeNum.Count - 1]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Config.BanTimeNum.Count - 1] + " hour*s";
                            break;
                        case "d":
                            UnBanTime = BanTime.AddDays(Config.BanTimeNum[Config.BanTimeNum.Count - 1]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Config.BanTimeNum.Count - 1] + " day*s";
                            break;
                        case "M":
                            UnBanTime = BanTime.AddMonths(Config.BanTimeNum[Config.BanTimeNum.Count - 1]);
                            BanID = DB.Create(IP, BanTime.ToString(), UnBanTime.ToString());
                            Duration = Config.BanTimeNum[Config.BanTimeNum.Count - 1] + " month*s";
                            break;
                    }
                }
            }

            //prep for task creation
            try
            {
                using TaskService ts = new();
                ts.GetFolder(@"\OpenSSH-Fail2Ban Scheduled Unbans").DeleteTask("F2B ID #" + BanID);
                ts.Dispose();

                //write event log
                EventOut(
                "Corrupt database?\nScheduled Task = Exists\n" +
                "IP-Ban Triggered = Yes\nIP Blocked in Firewall - probably not?\n" +
                "-> Deleted old Scheduled Task\n" +
                "-> Created new Scheduled Task, Firewall & Database entry.\n" +
                "────────────────────────────────────────────\n" +
                "\nBlocked " + IP + " for " + Duration + ".\n\n" +
                "┌─────────────────── Ban details ───────────────\n" +
                "│Ban ID:\t\t\t" + BanID + "\n" +
                "│Failed Attempts: \t" + Attempts + "\n" +
                "│Times banned before:\t" + Hist + "\n" +
                "│Ban date:\t\t[" + BanTime + "]\n" +
                "│Unban date:\t\t[" + UnBanTime + "]\n" +
                "│User*s:\t\t\t" + Users, EventLogEntryType.Warning, 2);
            }
            catch (Exception)
            {
                //write event log
                EventOut(
                "\nBlocked " + IP + " for " + Duration + ".\n\n" +
                "┌─────────────────── Ban details ───────────────\n" +
                "│Ban ID:\t\t\t" + BanID + "\n" +
                "│Failed Attempts: \t" + Attempts + "\n" +
                "│Times banned before:\t" + Hist + "\n" +
                "│Ban date:\t\t[" + BanTime + "]\n" +
                "│Unban date:\t\t[" + UnBanTime + "]\n" +
                "│User*s:\t\t\t" + Users, EventLogEntryType.Information, 1);
            }

            if (!Ethy)
            {
                //create scheduled unban task
                using TaskService ts = new();
                TaskDefinition td = ts.NewTask();
                td.RegistrationInfo.Description = "Restores access of " + IP + " in " + Duration + ".";
                td.RegistrationInfo.Author = "Fail2Ban-SRV";
                td.Principal.RunLevel = TaskRunLevel.Highest;
                td.Settings.WakeToRun = true;
                td.Settings.DisallowStartIfOnBatteries = false;
                td.Settings.StopIfGoingOnBatteries = false;
                td.Settings.ExecutionTimeLimit = TimeSpan.Zero;
                td.Principal.LogonType = TaskLogonType.S4U;

                using TimeTrigger dt = new();
                dt.StartBoundary = UnBanTime;
                dt.Repetition.Interval = TimeSpan.FromMinutes(2);

                td.Triggers.Add(dt);
                td.Actions.Add(new ExecAction("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Remove-NetFirewallRule -DisplayName 'F2B ID #" + BanID + "'; Remove-ItemProperty -Path HKLM:\\SOFTWARE\\OpenSSH-Fail2Ban\\Banned -Name '" + BanID + "#" + IP + "'; SCHTASKS /Delete /TN 'OpenSSH-Fail2Ban Scheduled Unbans\\F2B ID #" + BanID + "' /f", null));
                ts.RootFolder.CreateFolder("OpenSSH-Fail2Ban Scheduled Unbans", null, false);
                ts.GetFolder(@"\OpenSSH-Fail2Ban Scheduled Unbans").RegisterTaskDefinition("F2B ID #" + BanID, td);

                ts.Dispose();
                dt.Dispose();
            }

            //block ip in firewall
            AddFirewall(BanID, IP, BanTime);

            if (Ethy)
            {
                Write("[Perma-Banned] " + IP + "\n", "darkyellow", null);
            }
            else
            {
                Write("[Banned] " + IP + "\n", "darkyellow", null);
            }

            //----

            static Int32 IPHistory(String IP)
            {
                try
                {
                    var temp = GetReg("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH-Fail2Ban\\History", IP, RegistryValueKind.DWord, true);

                    if (temp is Int32)
                    {
                        return temp;
                    }
                    else
                    {
                        return 0;
                    }
                }
                catch
                {
                    return 0;
                }
            }
        }

        //-------------------------------------------------------------------------------------------------------------------------
        //changed

        public static void CMain()
        {
            String[,] Log;

            String[] UniqueIPs;

            Write("\n============= ", "darkgray", null);
            Write("SSH Fail2Ban", "gray", null);
            Write(" =============\n", "darkgray", null);

            Write("Start Time: " + DateTime.Now + "\n", "gray", null);
            Write("Loading Config\n", "darkgray", null);

            LoadConfig();

            Write("----------------------------------------\n", "darkgray", null);

            //work loop
            while (true)
            {
                //get log
                try
                {
                    Log = GetLog();
                }
                catch (Exception)
                {
                    Write("SSH Log missing, sleeping for 69 seconds\n", "magenta", null);

                    Thread.Sleep(69000);

                    continue;
                }

                switch (Log.GetLength(0))
                {
                    case 0:
                        //if no
                        Write("No violations in the last " + Config.LogScanTime[0] + Config.LogScanTime[1] + "\n", "gray", null);
                        goto Sleep; //goto is epik

                    case 1:
                        //if one
                        UniqueIPs = FetchUniqueIPs(Log);

                        if (Log.GetLength(0) >= Config.FailTrigger)
                        {
                            if (DB.IsTrusted(UniqueIPs[0], true))
                            {
                                Write("[CLog][Trusted] " + UniqueIPs[0] + "\n", "gray", null);

                                break;
                            }
                            else if (!DB.BanStatus(UniqueIPs[0]))
                            {
                                String[] temp = LogDetails(UniqueIPs[0], Log);

                                Ban(UniqueIPs[0], temp[0], Log.GetLength(0));
                            }
                            else
                            {
                                Write("[CLog][Banned] " + UniqueIPs[0] + "\n", "gray", null);
                            }
                        }
                        else
                        {
                            Write(Log.GetLength(0) + "x " + UniqueIPs[0] + "\n", "gray", null);
                        }

                        break;

                    default:
                        //if more

                        UniqueIPs = FetchUniqueIPs(Log);

                        foreach (String IP in UniqueIPs)
                        {
                            Int32 IPC = 0;

                            for (Int32 i = 0; i < Log.GetLength(0); i++)
                            {
                                if (Log[i, 0] == IP)
                                {
                                    IPC++;

                                    if (IPC >= Config.FailTrigger)
                                    {
                                        if (DB.IsTrusted(IP, true))
                                        {
                                            Write("[CLog][Trusted] " + IP + "\n", "gray", null);

                                            break;
                                        }
                                        else if (!DB.BanStatus(IP))
                                        {
                                            String[] temp = LogDetails(IP, Log);

                                            Ban(IP, temp[0], Int32.Parse(temp[1]));

                                            break;
                                        }
                                        else
                                        {
                                            Write("[CLog][Banned] " + IP + "\n", "gray", null);

                                            break;
                                        }
                                    }
                                }
                            }

                            if (IPC < Config.FailTrigger)
                            {
                                Write(IPC + "x " + IP + "\n", "gray", null);
                            }
                        }

                        break;
                }

                Sleep://i sleep

                TimeSpan Sleep = Config.LogScanIntervall[1] switch
                {
                    "s" => new TimeSpan(0, 0, 0, Int32.Parse(Config.LogScanIntervall[0])),
                    "m" => new TimeSpan(0, 0, Int32.Parse(Config.LogScanIntervall[0]), 0),
                    "h" => new TimeSpan(0, Int32.Parse(Config.LogScanIntervall[0]), 0, 0),
                    "d" => new TimeSpan(Int32.Parse(Config.LogScanIntervall[0]), 0, 0, 0),
                    _ => new TimeSpan(0, 0, 0, 5),
                };

                Thread.Sleep(Sleep);

                CheckSRVStatus(50, 300);

                Write("----------------------------------------\n", "darkgray", null);
            }
        }

        public static void AddFirewall(Int32 BanID, String IP, DateTime BanTime)
        {
            INetFwRule2 inboundRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
            inboundRule.Enabled = true;
            inboundRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            inboundRule.Name = "F2B ID #" + BanID;
            inboundRule.Description = "Blocks access of " + IP + ".\nGenerated by OpenSSH-Fail2Ban (CLI) on " + BanTime + ".";
            inboundRule.Grouping = "OpenSSH Fail2Ban";
            inboundRule.RemoteAddresses = IP;

            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            firewallPolicy.Rules.Add(inboundRule);
        }

        //=========================================================================================================================
        //=========================================================================================================================
        //new

        public static void CheckSRVStatus(Int32 Segments, Int32 TimePerSegment)
        {
            try
            {
                if (new ServiceController("OpenSSH Fail2Ban").Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
                {
                    Write("----------------------------------------\n", "darkgray", null);

                    Write("Warning: ", "darkyellow", null);
                    Write("\"OpenSSH Fail2Ban\" service status: ", "gray", null);
                    Write("Running\n", "green", null);
                    Write("Paused application while system service is running to prevent database corruption\n", "gray", null);
                    Write("Attempting to continue every 15 seconds:\n\n", "gray", null);

                    while (new ServiceController("OpenSSH Fail2Ban").Status is ServiceControllerStatus.Running or ServiceControllerStatus.ContinuePending or ServiceControllerStatus.StartPending)
                    {
                        Console.Write("█");

                        for (Int32 i = 0; i < Segments; i++)
                        {
                            Write("▓", "darkgray", null);
                        }

                        Write("█\r█", "white", null);

                        Thread.Sleep(TimePerSegment);

                        for (Int32 i = Segments; i > 0; i--)
                        {
                            Write("▓", "green", null);

                            Thread.Sleep(TimePerSegment);
                        }

                        Console.Write("\r");
                    }

                    Console.WriteLine();
                }
            }
            catch (Exception)
            { }
        }

        //

        public static void Help()
        {
            Write("\n======================= ", "darkgray", null);
            Write("SSH Fail2Ban", "white", null);
            Write(" ============================\n\n", "darkgray", null);

            //help
            Write("\t/Help\t\t", "yellow", null);
            Write("Shows this page\n\n", "gray", null);

            //about
            Write("\t/About\t\t", "yellow", null);
            Write("Shows program information\n\n", "gray", null);

            //start
            Write("\t/Start\t\t", "yellow", null);
            Write("Starts the CLI version\n\n", "gray", null);

            //show
            Write("\t/Show ", "yellow", null);

            Write("[", "darkgray", null);
            Write(" Banned ", "darkcyan", null);
            Write("|", "darkgray", null);
            Write(" Trusted ", "darkcyan", null);
            Write("| [ ", "darkgray", null);
            Write(" History ", "darkcyan", null);
            Write("|", "darkgray", null);
            Write(" History ", "darkcyan", null);
            Write(" \"IP\" ", "yellow", null);
            Write("] ]\n\n", "darkgray", null);

                //banned
            Write("\t   Banned", "darkcyan", null);
            Write("\tShows a list of currently banned IPs,\n\t\t\ttheir corresponding IDs and ban times\n\n", "gray", null);

                //Trusted
            Write("\t   Trusted", "darkcyan", null);
            Write("\tShows the list of known/trusted IPs,\n\t\t\twhich will be ignored by the program\n\n", "gray", null);

                //History
            Write("\t   History", "darkcyan", null);
            Write("\tShows for the selected or all IPs\n\t\t\tthe number of previous bans\n\n", "gray", null);

            //ADD
            Write("\t/Add ", "yellow", null);

            Write("[", "darkgray", null);
            Write(" Banned ", "darkcyan", null);
            Write("|", "darkgray", null);
            Write(" Trusted ", "darkcyan", null);
            Write("]", "darkgray", null);
            Write(" \"IP\"\n\n", "yellow", null);

            //banned
            Write("\t   Banned", "darkcyan", null);
            Write("\tPermanently bans IP + adds it to\n\t\t\tthe firewall and database\n\t\t\t(This will not increment the IPs History)\n\n", "gray", null);

            //Trusted
            Write("\t   Trusted", "darkcyan", null);
            Write("\tAdds an IP to the trusted list\n\t\t\twhich will be ignored by the program\n\n", "gray", null);

            //Remove
            Write("\t/Remove ", "yellow", null);

            Write("[ [ [", "darkgray", null);
            Write(" Trusted ", "darkcyan", null);
            Write("|", "darkgray", null);
            Write(" History ", "darkcyan", null);
            Write("]", "darkgray", null);
            Write(" \"IP\" ", "yellow", null);
            Write("|", "darkgray", null);
            Write(" All ", "yellow", null);
            Write("] | [", "darkgray", null);
            Write(" Banned ", "darkcyan", null);
            Write("[", "darkgray", null);
            Write(" \"IP\" ", "yellow", null);
            Write("|", "darkgray", null);
            Write(" \"ID\" ", "yellow", null);
            Write("|", "darkgray", null);
            Write(" All ", "yellow", null);
            Write("]", "darkgray", null);
            Write(" /S ", "yellow", null);
            Write("] ]\n\n", "darkgray", null);

            //banned
            Write("\t   Banned", "darkcyan", null);
            Write("\tUnbans specific or all IPs/IDs\n\t\t\t/S prevents a re-ban if the IP is currently in\n\t\t\tthe program's trigger range (will temporarily\n\t\t\tadd to the trusted IPs)\n\t\t\tThe time point to revoke the 'Trusted' status is\n\t\t\tcalculated from the recorded ban time + log scan time\n\n", "gray", null);

            //Trusted
            Write("\t   Trusted", "darkcyan", null);
            Write("\tRemoves all or specific IP from the trusted list\n\n", "gray", null);

            //History
            Write("\t   History", "darkcyan", null);
            Write("\tRemoves all or specific IP history\n\n", "gray", null);
        }

        public static void About()
        {
            Write("\nVersion: ", "gray", null);
            Write(Version + "\n", "yellow", null);

            Write("https://github.com/backslashspace/Windows-SSH-Fail2Ban\n\n", "cyan", null);


        }

        public static void Start()
        {
            try
            {
                if (new ServiceController("OpenSSH Fail2Ban").Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.Paused)
                {
                    CMain();

                    return;
                }
                else
                {
                    Write("\nWarning: ", "darkyellow", null);
                    Write("\"OpenSSH Fail2Ban\" service status: ", "gray", null);
                    Write("Running\n", "green", null);
                    Write("Use 'net stop \"OpenSSH Fail2Ban\"' or the GUI to stop the service\nand be able to use the console mode\n\n", "gray", null);
                }
            }
            catch (Exception)
            {
                CMain();
            }

            return;
        }

        public class Show
        {
            public static void Banned()
            {
                try
                {
                    String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", false).GetValueNames();

                    if (VNames.Length != 0 || VNames[0] != "")
                    {
                        Boolean SmallForm = false;

                        Boolean NoIP = true;

                        //test if can use compact form if array not too long
                        if (VNames.Length <= 1000)
                        {
                            SmallForm = true;

                            foreach (String V in VNames) 
                            { 
                                try
                                {
                                    if (IPAddress.Parse(V.Split('#')[1]).ToString().Length > 15)
                                    {
                                        SmallForm = false;
                                        break;
                                    }
                                }
                                catch (Exception)
                                {}
                            }
                        }

                        //print
                        if (SmallForm)
                        {
                            Write("\n=========================== ", "darkgray", null);
                            Write("SSH Fail2Ban Banned IPs", "white", null);
                            Write(" ============================\n\n", "darkgray", null);

                            Write("┏┅┅┅ ", "darkgray", null);
                            Write("ID", "darkcyan", null);
                            Write(" ┅┅┅┓ ┏┅┅┅┅┅┅ ", "darkgray", null);
                            Write("IP", "darkcyan", null);
                            Write(" ┅┅┅┅┅┅┅┓ ┏┅┅┅┅┅┅ ", "darkgray", null);
                            Write("Ban date", "darkcyan", null);
                            Write(" ┅┅┅┅┅┓ ┏┅┅┅┅┅ ", "darkgray", null);
                            Write("Unban date", "darkcyan", null);
                            Write(" ┅┅┅┅┓\n", "darkgray", null);
                        }
                        else
                        {
                            Write("\n======================================= ", "darkgray", null);
                            Write("SSH Fail2Ban Banned IPs", "white", null);
                            Write(" ========================================\n\n", "darkgray", null);

                            Write("┏┅┅┅ ", "darkgray", null);
                            Write("ID", "darkcyan", null);
                            Write(" ┅┅┅┓ ┏┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅ ", "darkgray", null);
                            Write("IP", "darkcyan", null);
                            Write(" ┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓ ┏┅┅┅┅┅┅ ", "darkgray", null);
                            Write("Ban date", "darkcyan", null);
                            Write(" ┅┅┅┅┅┓ ┏┅┅┅┅┅ ", "darkgray", null);
                            Write("Unban date", "darkcyan", null);
                            Write(" ┅┅┅┅┓\n", "darkgray", null);
                        }
                        
                        foreach (String Name in VNames)
                        {
                            if (Name.Length >= 5 && Name.Length <= 48 && Name.Contains('#'))
                            {
                                String[] IDIP = Name.Split('#');

                                //test if current object is valid
                                try
                                {
                                    if (!IsIP(IDIP[1], out IDIP[1], true))
                                    {
                                        continue;
                                    }

                                    if (!(Int32.Parse(IDIP[0]) < 100000000))
                                    {
                                        continue;
                                    }
                                }
                                catch (Exception)
                                {
                                    continue;
                                }

                                NoIP = false;
                                String[] Time;

                                String RDates = GetReg("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH-Fail2Ban\\Banned", Name, RegistryValueKind.String, false).ToString();

                                //print id
                                switch (IDIP[0].Length)
                                {
                                    case 1 or 2 or 3 or 4 or 5:
                                        Write("┋", "darkgray", null);
                                        Write(" " + IDIP[0] + "\t  ", "yellow", null);
                                        Write(" ┋", "darkgray", null);
                                        break;
                                    case 6:
                                        Write("┋", "darkgray", null);
                                        Write(" " + IDIP[0] + "  ", "yellow", null);
                                        Write(" ┋", "darkgray", null);
                                        break;
                                    case 7:
                                        Write("┋", "darkgray", null);
                                        Write(" " + IDIP[0] + " ", "yellow", null);
                                        Write(" ┋", "darkgray", null);
                                        break;
                                    case 8:
                                        Write("┋", "darkgray", null);
                                        Write(" " + IDIP[0], "yellow", null);
                                        Write(" ┋", "darkgray", null);
                                        break;
                                }

                                //print ip
                                if (SmallForm)
                                {
                                    switch (IDIP[1].Length)
                                    {
                                        case 3 or 4 or 5 or 6:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 7:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 8:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 9:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 10:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "     ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 11:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "    ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 12:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "   ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 13:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "  ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 14:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + " ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 15:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1], "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                    }
                                }
                                else
                                {
                                    switch (IDIP[1].Length)
                                    {
                                        case 3 or 4 or 5 or 6:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t\t\t\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 8 or 7:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t\t\t\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 16 or 15 or 14 or 13 or 12 or 11 or 10 or 9:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t\t\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 22 or 23 or 24 or 21 or 20 or 19 or 18 or 17:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 25 or 26 or 27 or 28 or 29 or 30 or 31 or 32:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "\t      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 33:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "      ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 34:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "     ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 35:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "    ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 36:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "   ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 37:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + "  ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 38:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1] + " ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 39:
                                            Write(" ┋", "darkgray", null);
                                            Write(" " + IDIP[1], "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                    }
                                }

                                //print dates
                                try
                                {
                                    Time = RDates.Split('#');

                                    if (RDates != null && RDates != "" && RDates != "-1" && Time[0].Length == 19 && Time[1].Length == 19)
                                    {
                                        Write(" ┋", "darkgray", null);
                                        Write(" " + Time[0], "yellow", null);
                                        Write(" ┋", "darkgray", null);

                                        Write(" ┋", "darkgray", null);
                                        Write(" " + Time[1], "yellow", null);
                                        Write(" ┋\n", "darkgray", null);
                                    }
                                    else
                                    {
                                        throw new FieldAccessException();
                                    }
                                }
                                catch (Exception) 
                                {
                                    Write(" ┋\t\t       ┋ ┋\t\t       ┋\n", "darkgray", null);
                                }
                            }
                        }

                        if (SmallForm)
                        {
                            if (NoIP)
                            {
                                Write("┋    No    ┋ ┋       IPs       ┋ ┋          in         ┋ ┋       database      ┋\n", "darkgray", null);
                            }
                            
                            Write("┗┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛\n\n", "darkgray", null);
                        }
                        else
                        {
                            Write("┗┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛\n\n", "darkgray", null);
                        }

                        return;
                    }
                }
                catch (Exception)
                {}

                Write("\nNo IPs in database\n\n", "darkgray", null);
            }

            public static void Trusted()
            {
                try
                {
                    String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Trusted", false).GetValueNames();

                    if (VNames.Length != 0 || VNames[0] != "")
                    {
                        Boolean SmallForm = false;

                        Boolean NoIP = true;

                        //test if can use compact form if array not too long
                        if (VNames.Length <= 1000)
                        {
                            SmallForm = true;

                            foreach (String V in VNames)
                            {
                                try
                                {
                                    if (IPAddress.Parse(V).ToString().Length > 15)
                                    {
                                        SmallForm = false;
                                        break;
                                    }
                                }
                                catch (Exception)
                                { }
                            }
                        }

                        //print
                        if (SmallForm)
                        {
                            Write("\n========== ", "darkgray", null);
                            Write("SSH Fail2Ban Trusted IPs", "white", null);
                            Write(" ==========\n\n", "darkgray", null);

                            Write("┏┅┅┅┅┅┅ ", "darkgray", null);
                            Write("IP", "darkcyan", null);
                            Write(" ┅┅┅┅┅┅┅┓\n", "darkgray", null);

                        }
                        else
                        {
                            Write("\n======== ", "darkgray", null);
                            Write("SSH Fail2Ban Trusted IPs", "white", null);
                            Write(" =========\n\n", "darkgray", null);
                            Write("┏┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅ ", "darkgray", null);
                            Write("IP", "darkcyan", null);
                            Write(" ┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓\n", "darkgray", null);
                        }

                        String PrintIP = "";

                        foreach (String Name in VNames)
                        {
                            if (Name.Length >= 3 && Name.Length <= 50)
                            {
                                if (!IsIP(Name, out PrintIP, true))
                                {
                                    continue;
                                }

                                NoIP = false;

                                //print ip
                                if (SmallForm)
                                {
                                    switch (PrintIP.Length)
                                    {
                                        case 3 or 4 or 5:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t\t ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 6 or 7 or 8:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 9:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "      ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 10:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "     ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 11:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "    ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 12:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "   ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 13:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "  ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 14:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + " ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 15:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP, "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                    }
                                }
                                else
                                {
                                    switch (PrintIP.Length)
                                    {
                                        case 3 or 4 or 5:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t\t\t\t\t ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 6 or 7 or 8 or 9 or 10 or 11 or 12 or 13:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t\t\t         ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 14 or 15 or 16 or 17:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t\t         ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 18 or 19 or 20 or 21:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t\t         ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 22 or 23 or 24 or 25 or 26 or 27:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t         ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 29 or 28:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t\t ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 30:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "\t ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 31:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "        ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 32:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "       ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 33:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "      ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 34:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "     ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 35:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "    ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 36:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "   ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 37:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + "  ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 38:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP + " ", "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                        case 39:
                                            Write("┋", "darkgray", null);
                                            Write(" " + PrintIP, "yellow", null);
                                            Write(" ┋\n", "darkgray", null);
                                            break;
                                    }
                                }
                            }
                        }

                        if (SmallForm)
                        {
                            if (NoIP)
                            {
                                Write("┋  No IPs in DB   ┋\n", "darkgray", null);
                            }

                            Write("┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛\n\n", "darkgray", null);
                        }
                        else
                        {
                            Write("┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛\n\n", "darkgray", null);
                        }

                        return;
                    }

                    return;
                }
                catch { }

                Write("\nNo IPs in database\n\n", "darkgray", null);
            }

            public static void History(String Optional = null)
            {
                if (Optional != null)
                {
                    //check given IP
                    if (!IsIP(Optional, out String IP, true))
                    {
                        Write("\nError: Invalid IP\n\n", "red", null);

                        return;
                    }

                    String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\History", false).GetValueNames();

                    foreach (String Name in VNames)
                    {
                        if (Name == IP)
                        {
                            Int32 PB = GetReg("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH-Fail2Ban\\History", IP, RegistryValueKind.DWord, false);

                            if (PB >= 0)
                            {
                                if (PB == 1)
                                {
                                    Write("\n" + IP, "darkcyan", null);
                                    Write(" was banned ", "gray", null);
                                    Write("once", "darkcyan", null);
                                    Write(" before\n\n", "gray", null);
                                }
                                else
                                {
                                    Write("\n" + IP, "darkcyan", null);
                                    Write(" was banned ", "gray", null);
                                    Write(PB.ToString(), "darkcyan", null);
                                    Write(" times before\n\n", "gray", null);
                                }

                                return;
                            }
                        }
                    }

                    Write("\nNo history for " + IP + " present\n\n", "gray", null);
                }
                else
                {
                    //check all IPs

                    try
                    {
                        String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\History", false).GetValueNames();

                        if (VNames.Length != 0 || VNames[0] != "")
                        {
                            Boolean SmallForm = false;

                            Boolean NoIP = true;

                            //test if can use compact form if array not too long
                            if (VNames.Length <= 1000)
                            {
                                SmallForm = true;

                                foreach (String V in VNames)
                                {
                                    try
                                    {
                                        if (IPAddress.Parse(V).ToString().Length > 15)
                                        {
                                            SmallForm = false;
                                            break;
                                        }
                                    }
                                    catch (Exception)
                                    { }
                                }
                            }

                            //print
                            if (SmallForm)
                            {
                                Write("\n========== ", "darkgray", null);
                                Write("SSH Fail2Ban Trusted IPs", "white", null);
                                Write(" ==========\n\n", "darkgray", null);

                                Write("┏┅┅┅ ", "darkgray", null);
                                Write("PB", "darkcyan", null);
                                Write(" ┅┅┅┓ ┏┅┅┅┅┅┅ ", "darkgray", null);
                                Write("IP", "darkcyan", null);
                                Write(" ┅┅┅┅┅┅┅┓\n", "darkgray", null);
                            }
                            else
                            {
                                Write("\n======================================= ", "darkgray", null);
                                Write("SSH Fail2Ban Banned IPs", "white", null);
                                Write(" ========================================\n\n", "darkgray", null);

                                Write("┏┅┅┅ ", "darkgray", null);
                                Write("PB", "darkcyan", null);
                                Write(" ┅┅┅┓ ┏┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅ ", "darkgray", null);
                                Write("IP", "darkcyan", null);
                                Write(" ┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓\n", "darkgray", null);
                            }

                            String PrintIP = "";

                            Int32 CPB;

                            foreach (String Name in VNames)
                            {
                                if (Name.Length >= 3 && Name.Length <= 50)
                                {
                                    //test if current object is valid
                                    if (!IsIP(Name, out PrintIP, true))
                                    {
                                        continue;
                                    }

                                    CPB = GetReg("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH-Fail2Ban\\History", PrintIP, RegistryValueKind.DWord, false);

                                    if (CPB > 100000000)
                                    {
                                        continue;
                                    }

                                    NoIP = false;

                                    //print id
                                    switch (CPB.ToString().Length)
                                    {
                                        case 1 or 2 or 3 or 4 or 5:
                                            Write("┋", "darkgray", null);
                                            Write(" " + CPB + "\t  ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 6:
                                            Write("┋", "darkgray", null);
                                            Write(" " + CPB + "  ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 7:
                                            Write("┋", "darkgray", null);
                                            Write(" " + CPB + " ", "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                        case 8:
                                            Write("┋", "darkgray", null);
                                            Write(" " + CPB, "yellow", null);
                                            Write(" ┋", "darkgray", null);
                                            break;
                                    }

                                    //print ip
                                    if (SmallForm)
                                    {
                                        switch (PrintIP.Length)
                                        {
                                            case 3 or 4 or 5 or 6:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 7:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 8:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 9:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 10:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "     ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 11:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "    ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 12:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "   ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 13:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "  ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 14:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + " ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 15:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP, "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        switch (PrintIP.Length)
                                        {
                                            case 3 or 4 or 5 or 6:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t\t\t\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 8 or 7:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t\t\t\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 16 or 15 or 14 or 13 or 12 or 11 or 10 or 9:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t\t\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 22 or 23 or 24 or 21 or 20 or 19 or 18 or 17:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 25 or 26 or 27 or 28 or 29 or 30 or 31 or 32:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "\t      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 33:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "      ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 34:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "     ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 35:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "    ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 36:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "   ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 37:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + "  ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 38:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP + " ", "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                            case 39:
                                                Write(" ┋", "darkgray", null);
                                                Write(" " + PrintIP, "yellow", null);
                                                Write(" ┋\n", "darkgray", null);
                                                break;
                                        }
                                    }
                                }
                            }

                            if (SmallForm)
                            {
                                if (NoIP)
                                {
                                    Write("┋ No  IPs  ┋ ┋ in   Database   ┋\n", "darkgray", null);
                                }

                                Write("┗┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛\n\n", "darkgray", null);
                            }
                            else
                            {
                                Write("┗┅┅┅┅┅┅┅┅┅┅┛ ┗┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛\n\n", "darkgray", null);
                            }

                            return;
                        }
                    }
                    catch (Exception)
                    { }

                    Write("\nNo IPs in database\n\n", "darkgray", null);
                }
            }
        }

        public static class Add
        {
            public static void Banned(String IN)
            {
                if (!IsIP(IN, out String IP, true))
                {
                    Write("\nError: Invalid IP\n\n", "red", null);

                    return;
                }

                //check if already banned
                if (!DB.BanStatus(IP))
                {
                    //check if truted ip
                    if (!DB.IsTrusted(IP, true))
                    {
                        //get ban time
                        DateTime BanTime = DateTime.Now;

                        //create DB entry
                        Int32 BanID = DB.Create(IP, BanTime.ToString(), "---------- --------");

                        //create Log entry
                        EventOut(
                        "\nBlocked " + IP + " for $Permanent$.\n\n" +
                        "┌─────────────────── Ban details ───────────────\n" +
                        "│Type:\t\t\tManual [F2B-CLI.exe]\n" +
                        "│Ban ID:\t\t\t" + BanID + "\n" +
                        "│Ban date:\t\t[" + BanTime + "]\n" +
                        "│Unban date:\t\t[ --- --- ]\n", EventLogEntryType.Information, 1);

                        //block ip in firewall
                        AddFirewall(BanID, IP, BanTime);

                        Write("\nSuccessfully banned ", "gray", null);
                        Write(IP + "\n\n", "darkcyan", null);
                    }
                    else
                    {
                        Write("\nError: IP is a trusted IP\n\n", "red", null);

                        return;
                    }
                }
                else
                {
                    Write("\nError: IP already banned\n\n", "red", null);

                    return;
                }
            }

            public static void Trusted(String IN)
            {
                if (!IsIP(IN, out String IP, true))
                {
                    Write("\nError: Invalid IP\n\n", "red", null);

                    return;
                }

                if (!DB.IsTrusted(IP, true))
                {
                    Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH-Fail2Ban\Trusted", IP, 0, RegistryValueKind.DWord);

                    Write("\nSuccessfully added ", "gray", null);
                    Write(IP, "darkcyan", null);
                    Write(" to the trusted list\n\n", "gray", null);
                }
                else
                {
                    Write("\nError: IP already trusted\n\n", "red", null);
                }
            }
        }

        public static class Remove
        {
            public static void Banned(String IN, Boolean PreventInTimeBan = false)
            {
                if (IN.ToLower() == "all")
                {
                    //unban all ips

                    List<String> IPs = new();
                    List<String> IDs = new();

                    String[] tarr;

                    try
                    {
                        String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", false).GetValueNames();

                        foreach (var V in VNames)
                        {
                            try
                            {
                                tarr = V.Split('#');

                                if (tarr.Length == 2 && UInt32.TryParse(tarr[0], out _) && IPAddress.TryParse(tarr[1], out _))
                                {
                                    if (tarr[1].Contains('%'))
                                    {
                                        tarr[1] = tarr[1].Split('%')[0];
                                    }

                                    IPs.Add(tarr[1]);
                                    IDs.Add(tarr[0]);
                                }
                            }
                            catch
                            {
                                continue;
                            }
                        }
                    }
                    catch
                    { }

                    if (IPs.Count < 1)
                    {
                        Write("\nError: No valid database entrys found\n\n", "red", null);

                        return;
                    }

                    Console.WriteLine();

                    String UBNT;

                    void AddUBNT(String AddS)
                    {
                        if (UBNT != "")
                        {
                            UBNT += "|" + AddS;
                        }
                        else
                        {
                            UBNT = AddS;
                        }
                    }

                    for (int i = 0; i < IPs.Count; i++)
                    {
                        UBNT = "";

                        //rm fw entry
                        INetFwPolicy2 FWS = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

                        foreach (INetFwRule rule in FWS.Rules)
                        {
                            if (rule.Name == "F2B ID #" + IDs[i])
                            {
                                FWS.Rules.Remove(rule.Name);

                                UBNT = "FW";
                            }
                        }

                        //remove shed task
                        try
                        {
                            TaskService ts = new();
                            ts.GetFolder(@"\OpenSSH-Fail2Ban Scheduled Unbans").DeleteTask("F2B ID #" + IDs[i]);
                            ts.Dispose();

                            AddUBNT("T");
                        }
                        catch
                        { }

                        //preent reban in 'a
                        if (PreventInTimeBan)
                        {
                            if (UhhFunctionNameThatDoesShedStuff(UInt32.Parse(IDs[i]), IPs[i]))
                            {
                                AddUBNT("S");
                            }
                            else
                            {
                                AddUBNT("Error: database entry corrupt, ip unbanned");
                            }
                        }

                        //remove db entry
                        try
                        {
                            using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", true);
                            key.DeleteValue(IDs[i] + "#" + IPs[i], false);
                            key.Dispose();

                            AddUBNT("DB");
                        }
                        catch
                        { }

                        Write("[", "darkgray", null);
                        if (UBNT.Contains('E'))
                        {
                            Write(UBNT, "red", null);
                        }
                        else
                        {
                            Write(UBNT, "gray", null);
                        }
                        Write("] ", "darkgray", null);
                        Write(IPs[i] + "\n", "darkcyan", null);
                    }

                    Write("\n\tDone\n\n", "green", null);

                    return;
                }
                else
                {
                    static String IDfromIP(String IP)
                    {
                        //returns ID in form of UInt32 or null when ot found
                        try
                        {
                            String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", false).GetValueNames();

                            foreach (var V in VNames)
                            {
                                try
                                {
                                    if (V.Split('#')[1].Equals(IP))
                                    {
                                        return UInt32.Parse(V.Split('#')[0]).ToString();
                                    }
                                }
                                catch
                                {
                                    continue;
                                }
                            }

                            return null;
                        }
                        catch (Exception)
                        {
                            return null;
                        }
                    }

                    static String IPfromID(UInt32 ID)
                    {
                        //returns valid IP in string form from id input, null when not found
                        try
                        {
                            String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", false).GetValueNames();

                            String[] tmp;

                            foreach (var V in VNames)
                            {
                                tmp = V.Split('#');

                                if (tmp[0] == ID.ToString() && IsIP(tmp[1], out String IP, true))
                                {
                                    return IP;
                                }
                            }
                        }
                        catch
                        { }

                        return null;
                    }

                    //get ip & ID from input & validate

                    String WorkIP;
                    UInt32 WorkID;

                    try
                    {
                        WorkID = UInt32.Parse(IN);

                        //when id input

                        try
                        {
                            WorkIP = IPfromID(WorkID);

                            if (WorkIP == null)
                            {
                                throw new Exception();
                            }
                        }
                        catch
                        {
                            Write("\nError: ", "red", null);
                            Write(WorkID.ToString(), "darkcyan", null);
                            Write(" not assigned\n\n", "red", null);

                            return;
                        }
                    }
                    catch
                    {
                        if (!IsIP(IN, out WorkIP, true))
                        {
                            Write("\nError: Invalid input\n\n", "red", null);

                            return;
                        }

                        //when ip input

                        try
                        {
                            WorkID = UInt32.Parse(IDfromIP(WorkIP));
                        }
                        catch
                        {
                            Write("\nError: ", "red", null);
                            Write(WorkIP, "darkcyan", null);
                            Write(" not banned\n\n", "red", null);

                            return;
                        }
                    }

                    //remove from firewall

                    Int32 i = 0;

                    INetFwPolicy2 FWS = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

                    foreach (INetFwRule rule in FWS.Rules)
                    {
                        if (rule.Name == "F2B ID #" + WorkID)
                        {
                            FWS.Rules.Remove(rule.Name);
                            i++;
                        }
                    }

                    Write("\nDeleted ", "darkgray", null);
                    Write(i.ToString(), "gray", null);
                    Write(" firewall entry with ID ", "darkgray", null);
                    Write(WorkID.ToString() + "\n", "darkcyan", null);

                    //remove shed task
                    try
                    {
                        TaskService ts = new();
                        ts.GetFolder(@"\OpenSSH-Fail2Ban Scheduled Unbans").DeleteTask("F2B ID #" + WorkID);
                        ts.Dispose();

                        Write("Removed Scheduled Task with id ", "darkgray", null);
                        Write(WorkID.ToString() + "\n", "darkcyan", null);
                    }
                    catch
                    { }

                    //preent reban in 'a
                    if (PreventInTimeBan)
                    {
                        if (UhhFunctionNameThatDoesShedStuff(WorkID, WorkIP))
                        {
                            Write("Made ", "darkgray", null);

                            Write(WorkIP, "darkcyan", null);

                            Write(" temporarily trusted\n", "darkgray", null);
                        }
                    }

                    //remove db entry
                    try
                    {
                        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Banned", true);
                        key.DeleteValue(WorkID + "#" + WorkIP, false);
                        key.Dispose();
                    }
                    catch
                    { }

                    Write("Successfully unbanned ", "gray", null);
                    Write(WorkIP + "\n\n", "darkcyan", null);
                }

                Boolean UhhFunctionNameThatDoesShedStuff(UInt32 WorkID, String WorkIP)
                {
                    String[] CSAtring = LowConfig();

                    //get bandate
                    String Bandate = GetReg("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH-Fail2Ban\\Banned", WorkID + "#" + WorkIP, RegistryValueKind.String, true);

                    if (Bandate != null)
                    {
                        try
                        {
                            DateTime UnbanTime = DateTime.Parse(Bandate.Split('#')[0]);

                            UnbanTime = CSAtring[1] switch
                            {
                                "m" => UnbanTime.AddMinutes(Int32.Parse(CSAtring[0])),
                                "h" => UnbanTime.AddHours(Int32.Parse(CSAtring[0])),
                                "d" => UnbanTime.AddDays(Int32.Parse(CSAtring[0])),
                                "M" => UnbanTime.AddMonths(Int32.Parse(CSAtring[0])),
                                _ => throw new Exception(),
                            };

                            try
                            {
                                using TaskService ds = new();
                                ds.GetFolder(@"\OpenSSH-Fail2Ban Scheduled Unbans").DeleteTask("F2B Auto-Trust ID #" + WorkID);
                                ds.Dispose();
                            }
                            catch
                            { }

                            //create scheduled unban task
                            using TaskService ts = new();
                            TaskDefinition td = ts.NewTask();
                            td.RegistrationInfo.Description = "Removes 'Trusted' status of " + WorkIP + ".";
                            td.RegistrationInfo.Author = "Fail2Ban-CLI";
                            td.Principal.RunLevel = TaskRunLevel.Highest;
                            td.Settings.WakeToRun = true;
                            td.Settings.DisallowStartIfOnBatteries = false;
                            td.Settings.StopIfGoingOnBatteries = false;
                            td.Settings.ExecutionTimeLimit = TimeSpan.Zero;
                            td.Principal.LogonType = TaskLogonType.S4U;

                            using TimeTrigger dt = new();
                            dt.StartBoundary = UnbanTime;
                            dt.Repetition.Interval = TimeSpan.FromMinutes(2);

                            td.Triggers.Add(dt);
                            td.Actions.Add(new ExecAction("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Remove-ItemProperty -Path HKLM:\\SOFTWARE\\OpenSSH-Fail2Ban\\Trusted -Name '" + WorkIP + "'; SCHTASKS /Delete /TN 'OpenSSH-Fail2Ban Scheduled Unbans\\F2B Auto-Trust ID #" + WorkIP + "' /f", null));
                            ts.RootFolder.CreateFolder("OpenSSH-Fail2Ban Scheduled Unbans", null, false);
                            ts.GetFolder(@"\OpenSSH-Fail2Ban Scheduled Unbans").RegisterTaskDefinition("F2B Auto-Trust ID #" + WorkIP, td);

                            ts.Dispose();
                            dt.Dispose();

                            //make IP trusted
                            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH-Fail2Ban\Trusted", WorkIP, 0, RegistryValueKind.DWord);

                            return true;
                        }
                        catch
                        {

                        }
                    }

                    return false;
                }

                String[] LowConfig()
                {
                    try
                    {
                        String[] Data;

                        try
                        {
                            Data = File.ReadAllLines(System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + "\\config.txt");
                        }
                        catch
                        {
                            return new String[] { "1", "h" };
                        }

                        foreach (String CLine in Data)
                        {
                            if (CLine.Contains("LogScanTime="))
                            {
                                String[] temp = CLine.Split('=')[1].Split('/');

                                if (temp.Length < 2)
                                {
                                    return new String[] { "1", "h" };
                                }

                                if (temp[1].Contains("m") || temp[1].Contains("h") || temp[1].Contains("d") || temp[1].Contains("M"))
                                {
                                    try
                                    {
                                        Int32 I = Int32.Parse(temp[0]);

                                        if (I < 0)
                                        {
                                            I *= -1;
                                        }

                                        return new String[] { I.ToString(), temp[1] };
                                    }
                                    catch (Exception)
                                    {
                                        return new String[] { "1", "h" };
                                    }
                                }
                                else
                                {
                                    return new String[] { "1", "h" };
                                }
                            }
                        }
                    }
                    catch
                    { }

                    return new String[] { "1", "h" };
                }
            }

            public static void Trusted(String IN)
            {
                if (IN.ToLower() == "all")
                {
                    try
                    {
                        String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Trusted", false).GetValueNames();

                        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Trusted", true);

                        Boolean T = true;

                        Console.WriteLine();

                        foreach (String V in VNames)
                        {
                            if (!IsIP(V, out String IP, false) || !DB.IsTrusted(IP, true))
                            {
                                continue;
                            }

                            key.DeleteValue(IP, false);

                            Write("[", "darkgray", null);
                            Write("-", "gray", null);
                            Write("] ", "darkgray", null);
                            Write(V + "\n", "darkcyan", null);

                            T = false;
                        }

                        key.Dispose();

                        if (T)
                        {
                            throw new Exception();
                        }

                        Write("\nDone\n\n", "green", null);
                    }
                    catch
                    {
                        Write("Info: No trusted IPs found\n\n", "darkyellow", null);

                        return;
                    }
                }
                else
                {
                    if (!IsIP(IN, out IN, false))
                    {
                        Write("\nError: Invalid IP\n\n", "red", null);

                        return;
                    }

                    if (!DB.IsTrusted(IN, true))
                    {
                        Write("\nInfo: IP not trusted\n\n", "darkyellow", null);

                        return;
                    }

                    //mak untrusd
                    try
                    {
                        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\Trusted", true);
                        key.DeleteValue(IN, false);
                        key.Dispose();
                    }
                    catch
                    { }

                    Write("\nSuccessfully removed ", "gray", null);
                    Write(IN, "darkcyan", null);
                    Write(" trusted status\n\n", "gray", null);
                }
            }

            public static void History(String IN)
            {
                if (IN.ToLower() == "all")
                {
                    try
                    {
                        String[] VNames = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\History", false).GetValueNames();

                        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\History", true);

                        Boolean T = true;

                        Console.WriteLine();

                        foreach (String V in VNames)
                        {
                            if (!IsIP(V, out String IP, false))
                            {
                                continue;
                            }

                            key.DeleteValue(IP, false);

                            Write("[", "darkgray", null);
                            Write("-", "gray", null);
                            Write("] ", "darkgray", null);
                            Write(V + "\n", "darkcyan", null);

                            T = false;
                        }

                        key.Dispose();

                        if (T)
                        {
                            throw new Exception();
                        }

                        Write("\nDone\n\n", "green", null);
                    }
                    catch
                    {
                        Write("Info: No IP history found\n\n", "darkyellow", null);

                        return;
                    }
                }
                else
                {
                    if (!IsIP(IN, out IN, false))
                    {
                        Write("\nError: Invalid IP\n\n", "red", null);

                        return;
                    }

                    //mak untrusd
                    try
                    {
                        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenSSH-Fail2Ban\History", true);
                        key.DeleteValue(IN, false);
                        key.Dispose();
                    }
                    catch
                    { }

                    Write("\nSuccessfully removed ", "gray", null);
                    Write(IN, "darkcyan", null);
                    Write(" history\n\n", "gray", null);
                }
            }
        }

        //-------------------------------------------------------------------------------------------------------------------------

        static void Main(String[] args)
        { 
            Console.OutputEncoding = Encoding.UTF8;

            switch (args.Length)
            {
                case 1:
                    Length1();
                    return;
                case 2:
                    Length2();
                    return;
                case 3:
                    Length3();
                    return;
                case 4:
                    Length4();
                    return;
                default:
                    Invalid();
                    return;
            }

            //- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

            static void Invalid()
            {
                Write("\nInvalid input: use /help to list possible commands\n\n", "red", null);
            }

            void Length1()
            {
                switch (args[0].ToLower()) 
                {
                    case "/help":
                        Help();
                        return;
                    case "/about":
                        About();
                        return;
                    case "/start":
                        Start();
                        return;
                    default:
                        Invalid();
                        return;
                }
            }

            void Length2()
            {
                if (args[0].ToLower() == "/show")
                {
                    switch (args[1].ToLower())
                    {
                        case "banned":
                            Show.Banned();
                            return;
                        case "history":
                            Show.History();
                            return;
                        case "trusted":
                            Show.Trusted();
                            return;
                        default:
                            Invalid();
                            return;
                    }
                }
                else
                {
                    Invalid();
                }
            }

            void Length3()
            {
                switch (args[0].ToLower())
                {
                    case "/show":
                        LocalShow();
                        return;
                    case "/add":
                        LocalAdd();
                        return;
                    case "/remove":
                        LocalRemove();
                        return;
                    default:
                        Invalid();
                        return;
                }

                void LocalShow()
                {
                    if (args[1].ToLower() == "history")
                    {
                        Show.History(args[2]);
                    }
                    else
                    {
                        Invalid();
                    }
                }

                void LocalAdd()
                {
                    switch (args[1].ToLower())
                    {
                        case "banned":
                            Add.Banned(args[2]);
                            return;
                        case "trusted":
                            Add.Trusted(args[2]);
                            return;
                        default:
                            Invalid();
                            return;
                    }
                }

                void LocalRemove()
                {
                    switch (args[1].ToLower())
                    {
                        case "banned":
                            Remove.Banned(args[2]);
                            return;
                        case "trusted":
                            Remove.Trusted(args[2]);
                            return;
                        case "history":
                            Remove.History(args[2]);
                            return;
                        default:
                            Invalid();
                            return;
                    }
                }
            }

            void Length4()
            {
                if (args[0].ToLower() == "/remove" && args[1].ToLower() == "banned" && args[3].ToLower() == "/s")
                {
                    Remove.Banned(args[2], true);
                }
                else
                {
                    Invalid();
                }
            }
        }
    }
}