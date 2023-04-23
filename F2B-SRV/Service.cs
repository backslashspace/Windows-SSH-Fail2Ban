using Microsoft.Win32.TaskScheduler;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using NetFwTypeLib;
using System.Reflection;
using System.Net;

namespace F2B_SRV
{
    public partial class Service : ServiceBase
    {
        public Service()
        {
            InitializeComponent();
        }

        public static Thread TH;

        protected override void OnStart(String[] args)
        {
            TH = new Thread(BMain)
            {
                IsBackground = true
            };
            TH.Start();
        }

        protected override void OnStop()
        {
            //safe exit
            while (true)
            {
                if (TH.ThreadState.ToString().Contains("WaitSleepJoin"))
                {
                    TH.Abort();

                    break;
                }

                Thread.Sleep(100);
            }
        }

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
                        String[] temp = CLine.Split('=')[1].Split('/');

                        if (temp.Length < 2)
                        {
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

                                Config.LogScanTime = new String[] { I.ToString(), temp[1] };
                            }
                            catch (Exception)
                            {
                                Errors += "LogScanTime: fallback to 1h\n";

                                Config.LogScanTime = new String[] { "1", "h" };
                            }
                        }
                        else
                        {
                            Errors += "LogScanTime: fallback to 1h\n";

                            Config.LogScanTime = new String[] { "1", "h" };
                        }

                        LogScanTime = false;
                    }

                    else if (CLine.Contains("FailTrigger="))
                    {
                        String temp = CLine.Split('=')[1];

                        try
                        {
                            Int32 I = Int32.Parse(temp);

                            if (I < 0)
                            {
                                I *= -1;
                            }

                            Config.FailTrigger = I;
                        }
                        catch (Exception)
                        {
                            Errors += "FailTrigger: fallback to 10\n";
                        }

                        FailTrigger = false;
                    }

                    else if (CLine.Contains("LogScanIntervall="))
                    {
                        String[] temp = CLine.Split('=')[1].Split('/');

                        if (temp.Length < 2)
                        {
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

                                Config.LogScanIntervall = new String[] { I.ToString(), temp[1] };
                            }
                            catch (Exception)
                            {
                                Errors += "LogScanIntervall: fallback to 5s\n";

                                Config.LogScanIntervall = new String[] { "5", "s" };
                            }
                        }
                        else
                        {
                            Errors += "LogScanIntervall: fallback to 5s\n";

                            Config.LogScanIntervall = new String[] { "5", "s" };
                        }

                        LogScanIntervall = false;
                    }

                    else if (CLine.Contains("CountBannerError="))
                    {
                        String temp = CLine.Split('=')[1];

                        if (temp == "true")
                        {
                            Config.CountBannerError = true;
                        }
                        else if (temp == "false")
                        {
                            Config.CountBannerError = false;
                        }
                        else
                        {
                            Errors += "CountBannerError: fallback to true\n";

                            Config.CountBannerError = true;
                        }

                        CountBannerError = false;
                    }

                    else if (CLine.Contains("CatchNegotiationErrors="))
                    {
                        String temp = CLine.Split('=')[1];

                        if (temp == "true")
                        {
                            Config.CatchNegotiationErrors = true;
                        }
                        else if (temp == "false")
                        {
                            Config.CatchNegotiationErrors = false;
                        }
                        else
                        {
                            Errors += "CatchNegotiationErrors: fallback to true\n";

                            Config.CatchNegotiationErrors = true;
                        }

                        CatchNegotiationErrors = false;
                    }

                    else if (CLine.Contains("PermBan="))
                    {
                        String temp = CLine.Split('=')[1];

                        if (temp == "true")
                        {
                            Config.PermBan = true;
                        }
                        else if (temp == "false")
                        {
                            Config.PermBan = false;
                        }
                        else
                        {
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
                        }
                    }
                }
            }

            //chek for missing config
            if (LogScanIntervall)
            {
                Config.LogScanTime = new String[] { "1", "h" };
            }
            if (LogScanTime)
            {
                Config.LogScanIntervall = new String[] { "5", "s" };
            }
            if (CountBannerError)
            {
                Config.CountBannerError = true;
            }
            if (CatchNegotiationErrors)
            {
                Config.CatchNegotiationErrors = true;
            }
            if (FailTrigger)
            {
                Config.FailTrigger = 12;
            }
            if (PermBan)
            {
                Config.PermBan = true;
            }
            if (BanTime)
            {
                Errors += "BanTime: fallback to 1/h,3/h,1/d,7/d,14/d,1/M,3/M\n";

                Config.BanTimeUnit = new List<String> { "h", "h", "d", "d", "d", "M", "M" };
                Config.BanTimeNum = new List<Int32> { 1, 3, 1, 7, 1, 1, 3 };
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

            static void AddFirewall(Int32 BanID, String IP, DateTime BanTime)
            {
                INetFwRule2 inboundRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
                inboundRule.Enabled = true;
                inboundRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                inboundRule.Name = "F2B ID #" + BanID;
                inboundRule.Description = "Blocks access of " + IP + ".\nGenerated by OpenSSH-Fail2Ban (SRV) on " + BanTime + ".";
                inboundRule.Grouping = "OpenSSH Fail2Ban";
                inboundRule.RemoteAddresses = IP;

                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallPolicy.Rules.Add(inboundRule);
            }
        }

        //-------------------------------------------------------------------------------------------------------------------------

        public static void BMain()
        {
            String[,] Log;

            String[] UniqueIPs;

            LoadConfig();

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
                    Thread.Sleep(69000);

                    continue;
                }

                switch (Log.GetLength(0))
                {
                    case 0:
                        //if no
                        goto Sleep; //goto is epik

                    case 1:
                        //if one
                        UniqueIPs = FetchUniqueIPs(Log);

                        if (Log.GetLength(0) >= Config.FailTrigger)
                        {
                            if (DB.IsTrusted(UniqueIPs[0], true))
                            {
                                break;
                            }
                            else if (!DB.BanStatus(UniqueIPs[0]))
                            {
                                String[] temp = LogDetails(UniqueIPs[0], Log);

                                Ban(UniqueIPs[0], temp[0], Log.GetLength(0));
                            }
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
                                            break;
                                        }
                                    }
                                }
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
            }
        }
    }
}