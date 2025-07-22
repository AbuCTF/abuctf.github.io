---
title: "PrivilegeEscalation"
description: "Migrated from Astro"
icon: "article"
date: "2024-06-10"
lastmod: "2024-06-10"
draft: false
toc: true
weight: 999
---

Here’s an intro into privilege escalation for pretty much anybody on the security field. For now, it's pretty much only Linux at the moment. My spelling for `Privilege` is all over the place, so beware !

## Linux Privledge Escalation

`Resources:`

[TryHackMe](https://tryhackme.com/dashboard)

[Linux Privilege Escalation for Beginners](https://youtu.be/ZTnwg3qCdVM?si=ueqJosPdxKTOX2WF)

[CVE-2016-5195](https://www.cve.org/CVERecord?id=CVE-2016-5195)

[CVE](https://cve.mitre.org/index.html)

[CTF Handbook](https://ctf101.org/)

[CVE-2019-18276：权力的游戏](https://blog.wohin.me/posts/cve-2019-18276/)

**`Commands:`**

### **System Enumeration**

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh TCM@10.10.72.23                               
Unable to negotiate with 10.10.72.23 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -o HostKeyAlgorithms=ssh-rsa TCM@10.10.72.23  
The authenticity of host '10.10.72.23 (10.10.72.23)' can't be established.
RSA key fingerprint is SHA256:JwwPVfqC+8LPQda0B9wFLZzXCXcoAho6s8wYGjktAnk.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.72.23' (RSA) to the list of known hosts.
TCM@10.10.72.23's password: 
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed May  8 07:41:55 2024 from ip-10-100-1-130.eu-west-1.compute.internal
sudo ssh -i id_rsa -o HostKeyAlgorithms=+ssh-rsa root@10.10.254.148
```

There we are connected to our first machine ;)

`System Architecture`

```bash
TCM@debian:~$ uname -a
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
TCM@debian:~$ cat /etc/issue
Debian GNU/Linux 6.0 \n \l
TCM@debian:~$ cat /proc/version
Linux version 2.6.32-5-amd64 (Debian 2.6.32-48squeeze6) (jmm@debian.org) (gcc version 4.3.5 (Debian 4.3.5-4) ) #1 SMP Tue May 13 16:34:35 UTC 2014

```

Learning which `kernal` version the system OS uses and looking up known vulnerabilities is a way to get started with the enumeration.

`CPU Architecture`

```bash
TCM@debian:~$ lscpu
Architecture:          x86_64
CPU op-mode(s):        64-bit
CPU(s):                1
Thread(s) per core:    1
Core(s) per socket:    1
CPU socket(s):         1
NUMA node(s):          1
Vendor ID:             GenuineIntel
CPU family:            6
Model:                 63
Stepping:              2
CPU MHz:               2399.998
Hypervisor vendor:     Xen
Virtualization type:   full
L1d cache:             32K
L1i cache:             32K
L2 cache:              256K
L3 cache:              30720K

```

Something to note here is that, looking up at the cores a CPU is handling is important cause sometimes the exploit might require multiple cores. So, do your enumeration kids.

Task/Services

```bash
TCM@debian:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   8396   812 ?        Ss   07:38   0:00 init [2]  
root         2  0.0  0.0      0     0 ?        S    07:38   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    07:38   0:00 [migration/0]
root         4  0.0  0.0      0     0 ?        S    07:38   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S    07:38   0:00 [watchdog/0]
root         6  0.0  0.0      0     0 ?        S    07:38   0:00 [events/0]
root         7  0.0  0.0      0     0 ?        S    07:38   0:00 [cpuset]
root         8  0.0  0.0      0     0 ?        S    07:38   0:00 [khelper]
root         9  0.0  0.0      0     0 ?        S    07:38   0:00 [netns]
root        10  0.0  0.0      0     0 ?        S    07:38   0:00 [async/mgr]
root      2436  0.0  0.1  76728  3352 ?        Ss   07:53   0:00 sshd: TCM [priv] 
TCM       2446  0.0  0.0  76728  1712 ?        S    07:54   0:00 sshd: TCM@pts/0  
TCM       2447  0.0  0.1  19276  2072 pts/0    Ss   07:54   0:00 -bash
TCM       2518  0.0  0.0  16380  1180 pts/0    R+   08:02   0:00 ps aux
```

Most of the times, in capture-the flag style competitions, it is important to know the host name of the system as it can hint on the exploit related to it, for example is the host name is blue or jerry it can be derived that the system is either vulnerable to either Eternal Blue or Tomcat exploit. Know your exploits.

### User Enumeration

```bash
TCM@debian:~$ whoami
TCM
TCM@debian:~$ id
uid=1000(TCM) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
TCM@debian:~$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
TCM@debian:~$ cat /etc/passwd

TCM@debian:~$ cat /etc/shadow

TCM@debian:/etc$ cat group

TCM@debian:/$ history

```

### Network Enumeration

```bash
TCM@debian:/$ ifconfig

TCM@debian:/$ ip a

TCM@debian:/$ ip route

TCM@debian:/$ ip neigh
10.10.0.1 dev eth0 lladdr 02:c8:85:b5:5a:aa REACHABLE

TCM@debian:/$ netstat
```

By the way, here’s a quick detour on how to `ssh`  into another machine locally or remotely.

In this case, I’m connecting my Kali Linux to my Windows OS.

```bash
PS C:\> Add-WindowsCapability -Online -Name OpenSSH.Server

Path          :
Online        : True
RestartNeeded : False

PS C:\> Start-Service sshd
```

Now, on to Kali

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ ssh abura@<REDACTED>
abura@<REDACTED>'s password: 
Microsoft Windows [Version 10.0.19045.4291]
(c) Microsoft Corporation. All rights reserved.
                                               
abura@ABDUR-PC C:\Users\abura>cd ..
```

And yes, I still use a Windows 10 system. I like this better.

1. Once PowerShell is open, stop the SSH server service by running the following command:
    
    ```powershell
    Stop-Service sshd
    ```
    
    This command will stop the SSH server service, effectively ending the server.
    
2. Optionally, you can verify that the service has stopped by running:
    
    ```powershell
    Get-Service sshd 
    ```
    
    This command will display information about the SSH server service. If it's stopped, you won't see "Running" in the Status column.
    
### Password Enumeration
    
    ```bash
    grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
    locate password | more
    find / -name <authorized_keys>OR<id_rsa> 2> /dev/null
    ```
    
Note: 
    
**`2> /dev/null`**: This part redirects the standard error (stderr) output to **`/dev/null`**. In Unix-like operating systems, **`/dev/null`** is a special device file that discards all data written to it. So, **`2> /dev/null`** essentially means "send any error messages to nowhere", effectively suppressing error messages that might occur during the search.
    
### Automated Tools
    
`LinPEAS` - Linux Privilege Escalation Awesome Script
    
`LinEnum`
    
`LES`/ `LPC` - Linux Exploit Suggestor / Linux Privilege Checker
    
```bash
    TCM@debian:~/tools/linux-exploit-suggester$ ./linux-exploit-suggester.sh | grep cow
    [+] [CVE-2016-5195] dirtycow
       Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
    [+] [CVE-2016-5195] dirtycow 2
       Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
```
    
It is indeed vulnerable to **`dirtycow`**.
    
`Dirty COW`, short for "`Dirty Copy On Write`," is a computer security vulnerability that affects the Linux kernel. It was discovered in 2016 by Phil Oester and is caused by a race condition found in the way the kernel's memory subsystem handles copy-on-write (COW) breakage of read-only private mappings.
    
Here's how it works:
    
1. **Copy-On-Write (COW)**: COW is a memory management technique used by operating systems to efficiently manage memory. When a process wants to modify a shared piece of memory, instead of immediately making a copy of that memory, the operating system marks the memory page as read-only. The copy is only made when the process tries to write to that memory page.
2. **Race Condition**: A race condition occurs when two or more processes or threads attempt to change shared data at the same time. In the case of Dirty COW, the race condition happens between the time a page is marked as read-only and the time the copy-on-write mechanism is enforced.
3. **Privilege Escalation**: Exploiting the Dirty COW vulnerability allows an attacker to gain write access to read-only memory mappings. This can lead to privilege escalation, allowing an attacker to gain root access to a system.
4. **Exploitation**: An attacker can exploit Dirty COW by repeatedly writing to a specific read-only memory page while simultaneously reading from it. If the timing is right, the attacker's write operation can occur just after the page is marked as read-only but before the copy-on-write mechanism is applied. This allows the attacker to modify the memory page directly, bypassing the read-only protection.
5. **Impact**: Dirty COW can be used to escalate privileges on a system, potentially allowing an attacker to gain full control over the system. It affects all Linux-based operating systems, including Android devices.
6. **Mitigation**: Patching the Linux kernel with the necessary fixes is the most effective way to mitigate the Dirty COW vulnerability. Linux distributions regularly release security updates to address vulnerabilities like Dirty COW. Additionally, system administrators can implement security best practices, such as regular system updates and limiting access to sensitive resources, to reduce the risk of exploitation.
    
<aside>
💡 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW.”   
</aside>
    
Back to Privledge Escalation after a brief end-semester examinations. Man, that Math paper went horrendously bad. Dang !
    
Anyways here something on finding a file in Linux using the CLI.
    
[How to Find a File by Name Using Command Line in Ubuntu](https://www.tutorialrepublic.com/faq/how-to-find-a-file-by-name-using-command-line-in-ubuntu.php)
    
To search this file within the whole file system you can simply use:
    
```bash
    find / -type f -name sample.txt
```
    
Also let’s `Terminator` on the Ubuntu VM. Cause I cause John Hammond do it, and it’s  hella cool to work in it.
    
```bash
    sudo apt install terminator
```
    
[Terminator - A Linux terminal emulator - GeeksforGeeks](https://www.geeksforgeeks.org/terminator-a-linux-terminal-emulator/)
    
Here’s how a clean `NMap` scan looks like,
    
```bash
    mkdir nmap 
    nmap -sC -sV -oN nmap/initial <IP_ADDR>
```
    
so -`sC` is for default scripts, -`sV` is to enumerate versions and -`oN` to output in nmap format.
    
### Kernel Exploitation
    
Coming onto to the interesting part of the segment, let’s do some simple system checkup before diving into it.
    
    ```bash
    TCM@debian:~$ uname -a
    Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
    ```
    
This command gives you the type of OS and the version it’s running on. Fire it on a browser and look for exploits.
    
[Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)](https://www.exploit-db.com/exploits/40839)
    
Since, we already got the `dirtycow` exploit on the machine, 
    
```bash
    TCM@debian:~/tools/dirtycow$ gcc -pthread c0w.c -o cow
    TCM@debian:~/tools/dirtycow$ ./cowid
    
```
Further on, we explore the `/etc/paswd` and the `etc/shadow` file, more importantly the shadow file, which contains the hash for the root user.

{{< figure src="continue.jpg" alt="Continue" >}}
