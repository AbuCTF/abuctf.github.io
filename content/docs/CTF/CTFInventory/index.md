---
title: "CTFInventory"
description: "Migrated from Astro"
icon: "article"
date: "2024-11-17"
lastmod: "2024-11-17"
draft: false
toc: true
weight: 999
---

Hello CTFers. Here is an inventory for people actively competing in CTFs. This should cover almost all main domains of CTFs and some extras. It’s been a wild journey of competing in CTFs for the past 8 months, and it’s been one of the most exciting endeavors of my life. Being able to lead `H7Tex`, meeting super amazing people, travelling the country, sleepless nights, post-CTF drama, constantly getting humbled and all of that. I truly believe getting involved with CTFs is the the best way to learn and excel in Cyber-Security.  I hope this will become a strong-hold for people looking to get themselves equipped with the CTF world. Peace.

### Reverse Engineering

{{< figure src="3.png" alt="3" >}}

[gdsdecomp](https://github.com/bruvzg/gdsdecomp)

[Download Detect It Easy  - MajorGeeks](https://www.majorgeeks.com/files/details/detect_it_easy.html)

[Compiler Explorer](https://godbolt.org/)

[Decompiler Explorer](https://dogbolt.org/)

To check binary security settings:

`checksec —file <filename>`

```bash
┌──(kali㉿kali)-[~/Downloads/rev_packedaway]
└─$ upx -d packed

                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     22867 <-      8848   38.69%   linux/amd64   packed

Unpacked 1 file.
```

`IDA pro / Ghidra`

**Functions to convert UTF-8(Unicode) to it’s code point and vise-versa**

The `ord()` function in Python returns the Unicode code point of a single character.

For example:

- `ord('A')` returns 65, which is the Unicode code point for the character 'A'.
- `ord('汉')` returns 27721, which is the Unicode code point for the Chinese character '汉'.

In the context of the provided code, `ord()` is used to obtain the Unicode code point of each character in the encoded string. This code point is then used in the transformation process to derive the original flag.

To reverse the `ord()` function and obtain the character corresponding to a Unicode code point, you can use the `chr()` function. Here's how you can do it:

```python
# Unicode code point
code_point = 27721

# Reverse the Unicode code point to obtain the character
character = chr(code_point)

# Print the character
print(character)  # This will print '汉'

```

The `chr()` function takes a Unicode code point as input and returns the corresponding character. In this example, `chr(27721)` returns the character '汉'.

`PicoCTF` Reverse Engineering PDF:

[Book-6-Pico-Reversing.pdf](https://picoctf.org/learning_guides/Book-6-Reversing.pdf)

`Radare2`

`OllyDbg`

```
exiftool
readelf -s <executable>
strings
objdump -d
stegseek
binwalk -e
nc
ltrace / strace
readelf -a <file_name>
ida
gdb
apt-cache search <file_name>
nc 
rot13
install bsdgames
zsteg
steghide
hexdump -C
mysqlbinlog
xxd 
grep
ssh -X POST <hash> | grep -i <flagFormat>
man exiv2 | cat | xclip -selection clipboard
```

### **Cryptography**

{{< figure src="4.png" alt="4" >}}

[CryptoHack – Home](https://cryptohack.org/)

[Symbols Cipher List](https://www.dcode.fr/symbols-ciphers)

Here’s a brief reminder on how to create a python virtual environment, I started using this because the amount of dependencies that I installed started to break each other.

1. create the virtual environment:
    
    ```
    Copy code
    python3 -m venv neural
    
    ```
    
2. Activate the virtual environment:
    
    ```bash
    
    source neural/bin/activate
    ```
    

[CADO-NFS](https://cado-nfs.gitlabpages.inria.fr/)

[X-RSA](https://github.com/X-Vector/X-RSA)

[CyberChef](https://icyberchef.com/)

`Here’s a article on BSD sockets:`

The BSD socket interface, or Berkeley Software Distribution (BSD) sockets, is

**a collection of standard function calls that allow programmers to add internet communication to their products**. BSD sockets are a client/server architecture that uses TCP to allow a host to listen for incoming connection requests. The sockets interface handles internetworking protocols, so users only need to understand the protocols that tell them how to interpret the data.

BSD sockets are often used for network communication because they provide a well-defined API for exchanging data over the network. They typically rely on TCP and UDP socket communication.

**Here are some types of sockets:**

- Datagram sockets: Allow processes to use the User Datagram Protocol (UDP)
- Stream sockets: Allow processes to use the Transfer Control Protocol (TCP) for communication
- Raw sockets: Provide user access to the Internet Control Message Protocol (ICMP)

The socket interface in C provides a mechanism for setting up a communication channel to another host system. For both clients and servers, the initial function call is the same. Processes call socket() to request a new socket instance from the OS.

FreeBSD offers several functions for working with sockets. The socket function is used by both clients and servers. It is declared as: int socket(int domain, int type, int protocol); The return value is an integer.

The getsockopt() function retrieves the current value of a particular socket option for the specified socket. The setsockopt() function sets a particular socket option for the specified socket. Berkeley sockets can operate in one of two modes: blocking or non-blocking.

```jsx
import socket
HOST = 'betta.utctf.live'
PORT = 7356

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(s.recv(1024).decode())
    s.sendall(b'1\n')
    response = s.recv(1024).decode()
    encrypted_flag_hex = response.split(": ")[1].strip()
    encrypted_flag_bytes = hex_to_bytes(encrypted_flag_hex
```

[CrypTool Portal](https://www.cryptool.org/en/cto/)

[CacheSleuth - Multi Decoder](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.cachesleuth.com/multidecoder/&ved=2ahUKEwiWm-_BmdGEAxXoTWwGHbdMCQwQFnoECBQQAQ&usg=AOvVaw1P746PPpXzE_oFz-FR29WJ)

[RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)

[factordb.com](https://factordb.com/)

[Online Malbolge Compiler](https://www.tutorialspoint.com/execute_malbolge_online.php)

[CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.](https://crackstation.net/)

[CyberChef](https://gchq.github.io/CyberChef/)

**`mcrypt`**

`Malbolge - Old  Programming Language`

`Cool articles on Cryptography:`

[Cryptanalysis](https://en.wikipedia.org/wiki/Cryptanalysis)

[https://en.wikipedia.org/wiki/RSA_(cryptosystem)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

[Book-2-Pico-Cryptography.pdf](https://picoctf.org/learning_guides/Book-2-Cryptography.pdf)

[Cryptography&NetworkSecurity-WilliamStallings](https://drive.google.com/file/d/1wDmWWbhUx4qGBNIK-aWzgrTLOhcg9MSB/view?usp=sharing)

[Visual_cryptography](https://en.wikipedia.org/wiki/Visual_cryptography)

### Binary Exploitation

{{< figure src="5.png" alt="5" >}}

`PicoCTF` Binary-Exploitation PDF:

[Book-5-Pico-Binary-Exploitation.pdf](https://picoctf.org/learning_guides/Book-5-Binary-Exploitation.pdf)

`GNU Debugger`

<aside>
💡 pwntools
</aside>

```nasm
$ apt-get update
$ apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
$ python3 -m pip install --upgrade pip
$ python3 -m pip install --upgrade pwntools
```

Checkout more about Pwning at:

[Pwnology](https://abuctf.github.io/posts/Pwnology/)

### **Steganography**

{{< figure src="6.png" alt="6" >}}

[John the Ripper password cracker](https://www.openwall.com/john/)

[SecLists](https://github.com/danielmiessler/SecLists)

[hashcat](https://github.com/hashcat/hashcat)

[Aperi'Solve](https://www.aperisolve.com/)

{{< figure src="6.5.png" alt="6.5" >}}

```bash
└─$ deepsound2john beep.wav > sound.txt

└─$ john -w=/usr/share/wordlists/rockyou.txt sound.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic_1529 [sha1($p null_padded_to_len_32) (DeepSound) 128/128 AVX 4x1])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (beep.wav)     
1g 0:00:00:00 DONE (2024-04-20 15:18) 100.0g/s 168000p/s 168000c/s 168000C/s 123456..kenny
Use the "--show --format=dynamic_1529" options to display all of the cracked passwords reliably
Session completed.
```

```bash
└─$ stegolsb wavsteg -r -i challenge.wav -o output.txt -n 2 -b 10000
Files read                     in 0.05s
Recovered 10000 bytes          in 0.00s
Written output file            in 0.01s
                                                                                                                                               
└─$ cat output.txt 
NexusCTF{Th3_Le4st_S1Gn1f!c4n7_B1t55_1n_A_W4v_f1L3_6fe20da1bc9}                                                                                                                                                                                                    ���<�
```

[GitHub - ragibson/Steganography: Least Significant Bit Steganography for bitmap images (.bmp and .png), WAV sound files, and byte sequences. Simple LSB Steganalysis (LSB extraction) for bitmap images.](https://github.com/ragibson/Steganography?tab=readme-ov-file#recovering-data)

[Whitespace Interpreter](https://naokikp.github.io/wsi/whitespace.html)

`pngcheck -7cpqstvx osint1.png`

`sonic visualizer / Audacity`

`steghide extract -sf <filename>.jpg`

`stegseek <filename>.jpg <wordlist>.txt`

`curl / less`

[HexEd.it - Browser-based Online and Offline Hex Editing](https://hexed.it/)

[Steganography - A list of useful tools and resources](https://0xrick.github.io/lists/stego/)

[UTF-8 encoder/decoder](https://mothereff.in/utf-8)

[DeepSound-2.0](https://github.com/oneplus-x/DeepSound-2.0)

`StegoSuite`

[BertNase's Own - npiet fun!](https://www.bertnase.de/npiet/npiet-execute.php)

[Endianness](https://en.wikipedia.org/wiki/Endianness#See_also)

[exiv2](https://www.notion.so/exiv2-f4777f0e81164189a1d97ac96405bbec?pvs=21)

```bash
exiv2 -M"set Exif.Image.DateTime Ascii 1965:01:25 15:45:00"

exiv2 -M “set exif.Image.DateTime Ascii 1970:01:01 00:00:00.001”
```

[Processing JPEG photos online - IMG online](https://www.imgonline.com.ua/eng/)

`qsstv` - Qt based slow scan television and fax

### **Open Source Intelligence**

[OSINT Framework](https://osintframework.com/)

`Wayback Machine`

[Wayback Machine](https://web.archive.org/)

https://github.com/sherlock-project/sherlock

```jsx
└─$ pipx install sherlock-project
  installed package sherlock-project 0.15.0, installed using Python 3.11.9
  These apps are now globally available
    - sherlock
done! ✨ 🌟 ✨
```

[Web Check - X-Ray Vision for any Website](https://web-check.xyz/)

[Instant Username Search](https://instantusername.com/)

[geoestimation](https://labs.tib.eu/geoestimation/)

[PicartaAI](https://picarta.ai/)

```bash
sudo apt install maltego
```

[maltego | Kali Linux Tools](https://www.kali.org/tools/maltego/)

[WhatsMyName Web](https://whatsmyname.app/)

[URL and website scanner - urlscan.io](https://urlscan.io/)

[DNSdumpster.com - dns recon and research, find and lookup dns records](https://dnsdumpster.com/)

[28 Online Vulnerability Scanners & Network Tools | HackerTarget.com](https://hackertarget.com/)

[Epieos, the ultimate OSINT tool](https://epieos.com/)

[Intelligence X](https://intelx.io/)

[dehashed](https://dehashed.com/)

[Shodan](https://www.shodan.io/)

`Reverse Image Lookup:`

[TinEye Reverse Image Search](https://tineye.com/)

### **Web Exploitation**

Bruteforcing Tools:

`GoBuster`

`FFUF`

`dirb`

Enumeration:

`nikto`

`nmap`

`burp-suite`

Baby web challenges:

`/robots.txt`

`check source/inspect`

`JWT`

[jwt_tool](https://github.com/ticarpi/jwt_tool)

`LFI`

`SQLi`

[sqlmap](https://github.com/sqlmapproject/sqlmap)

`curl with headers including TRACE`

### **Miscellaneous**

[FileInfo.com - The File Format Database](https://fileinfo.com/)

[WOFF2](https://www.notion.so/WOFF2-81d00f5060af46b28e0ff8b01e16583e?pvs=21)

[File Formats](https://www.notion.so/File-Formats-2d31d0afb24f4471aad8666455b689f6?pvs=21)

[Day 18: Essential CTF Tools](https://int0x33.medium.com/day-18-essential-ctf-tools-1f9af1552214)

[Online Tools to crack CTF Contest!](https://dhanumaalaian.medium.com/online-tools-to-crack-ctf-contest-1ad7efa958da)

This is also the category where the some of the flags might be hidden Discord or with some Bot. It’s a nightmare for people getting started in CTFs, cause it was the same for me LOL. Here is a cheat-sheet on how you’ll tackle Discord flags. Trust me, some flags were just absurd.

{{< figure src="6.6.png" alt="p4" >}}

`https://bi0sctf{h1dd3n_1n_pl41n_s1ght}:hehe@ctf.bi0s.in/`

Check #announcements channel, it usually is put there or in other channels. It could be hidden in the channels description, pinned messages, random message at the start, at one of the admins user cards.

Here is a Discord bot challenge from Metared-CTF Argentina.

{{< figure src="7.png" alt="7" >}}

when the bot says it’s somewhere over here, it meant literally. Copy the message with Discord’s copy text option, now paste it in a text editor.

{{< figure src="8.png" alt="8" >}}

```
I'm not sure, but I think it's here 
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|||||||||||||||||||||||||||||||||||||||||||||||||||||| _ _ _ _ _ _  
Use the ctf fl-ag format: d1sc0rDTr1cKs
```

### **Digital Forensics**

[aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)

[sstv](https://github.com/colaclanth/sstv)

```bash
abura@Abdur-PC MINGW64 /c/Documents3/CyberSec/CTF/cybercollosiumCTF/forensics/space
$ sstv -d task.wav -o result.png
[sstv] Searching for calibration header... Found!
[sstv] Detected SSTV mode Robot 36
[sstv] Decoding image...   [#########################################] 100%
[sstv] Drawing image data...
[sstv] ...Done!
```

`tshark`

```bash
└─$ tshark -Y "icmp.ident == 0 && icmp.type == 8" -T fields -e data.data -r Echos\ Parody.pcap | awk '{ printf "%s", $1 }'
546d563464584e4456455a37517a427362444e6a6446395561444e74587a52736243456866513d3d

└─$ echo "546d563464584e4456455a37517a427362444e6a6446395561444e74587a52736243456866513d3d" | xxd -r -p                   
TmV4dXNDVEZ7QzBsbDNjdF9UaDNtXzRsbCEhfQ==

└─$ echo "TmV4dXNDVEZ7QzBsbDNjdF9UaDNtXzRsbCEhfQ==" | base64 -d
NexusCTF{C0ll3ct_Th3m_4ll!!}
```

```bash
tshark -r ./okay10.pcapng -Y 'usb.src=="1.2.1"' -T fields -e usbhid.data | sed 's/../:&/g2' > clicks
```

[dtmf-decoder](https://github.com/ribt/dtmf-decoder)

```jsx
Audio Anomaly

This anomaly turned out to be Morse code, though barely audible. To make the Morse code clearer, we utilized Audacity’s “Analyze > Plot Spectrum” function, revealing a concentration of beeps around 500 Hz.

Spectrum Analysis

To make the Morse code more discernible, we adjusted the audio frequencies using Audacity’s “Effect > EQ and Filters > Filter Curve EQ” feature, boosting frequencies around 500 Hz while suppressing others.

EQ Adjustment

With the Morse code now clearer, we visually represented it using red dots and dashes in free graphics software.
```

[Audioalter](https://audioalter.com/)

`Autopsy` Forensics tool

`pdfimages`

```bash
7z2john protected_2.7z > hash.txt
```

`mysqlbinlog`

`DLL:`

A dynamic-link library is a shared library in the Microsoft Windows or OS/2 operating system. A DLL can contain executable code, data, and resources, in any combination.

A dynamic link library (DLL) is **a collection of small programs that larger programs can load when needed to complete specific tasks**. The small program, called a DLL file, contains instructions that help the larger program handle what may not be a core function of the original program.

[Animated gif tools](https://ezgif.com/)

[Volatility 3 CheatSheet](https://blog.onfvp.com/post/volatility-cheatsheet/)

[File Formats in Memory Forensics](https://www.notion.so/File-Formats-in-Memory-Forensics-99b8b33c74124e4797187f171f5e7f78?pvs=21)

```
┌──(kali㉿kali)-[~/…/pecanCTF/FINALS/Forensics]
└─$ unrar x 1267.rar
```

`vol.py -f memory.raw -profile=Win10x64_19041 windows.pslist`

```bash
python3 /opt/volatility/vol.py -f ~/Documents/CTF/pecanCTF/memory.raw windows.info
Volatility 3 Framework 2.5.2
Progress:  100.00		PDB scanning finished                        
Variable	Value

Kernel Base	0xf8073a017000
DTB	0x1ad000
Symbols	file:///opt/volatility/volatility3/symbols/windows/ntkrnlmp.pdb/68A17FAF3012B7846079AEECDBE0A583-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf8073ac26398
Major/Minor	15.19041
MachineType	34404
KeNumberProcessors	2
SystemTime	2023-04-06 17:25:30
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Wed Jun 28 04:14:26 1995
```

```bash
python3 /opt/volatility/vol.py -f ~/Documents/CTF/pecanCTF/memory.raw windows.pslist | grep 3340
 python3 /opt/volatility/vol.py -f ~/Documents/CTF/pecanCTF/memory.raw windows.pstree
 python3 /opt/volatility/vol.py -f ~/Documents/CTF/pecanCTF/memory.raw windows.cmdline.CmdLine
sudo python3 /opt/volatility/vol.py -f ~/Documents/CTF/pecanCTF/memory.raw windows.netscan

connscan/sockscan
cmdscan
registry.userassist
registry.printkey
registry.hivelist
```

`Evtx` - Event Viewer

{{< figure src="9.png" alt="9" >}}

**Process ID:**

`DumpIt` is a fast memory acquisition tool for Windows (x86, x64, ARM64). **Generate full memory crash dumps of Windows machines**.

**`TabTip.exe**` is an executable exe file which belongs to the Touch Keyboard and Handwriting Panel process which comes along with the **Tablet PC Input Panel Accessory** Software developed by Microsoft Windows Operating System software developer.

The Service Host (`svchost.exe`) is **a shared-service process that Windows uses to load DLL files**. As its name suggests, the Service Host helps host the different files and processes that Windows needs to run efficiently. Services are organized into groups, and each group runs within a separate Service Host process.

`Ctfmon.exe`, also known as CTF (Collaborative Translation Framework) Loader, is a Microsoft process that always runs in the background. It is used by Microsoft Office **to control the Alternative User Input Text Input Processor and the Microsoft Office Language Bar**.

 **`SgrmBroker.exe`**System Guard Runtime Monitor Broker is responsible for monitoring and attests to the integrity of the Windows platform

`winlogon.exe` also known as the **Windows Logon Application process**, is a key component of the Windows operating system. It manages the user logon and logoff procedures, enforces security policies, and ensures the smooth functioning of your computer.
**`userinit.exe`**  is the file responsible for **executing the logon scripts, re-establishing the network connection, and then starting Explorer.exe**.
`Explorer.exe` is a vital process in the Windows operating system that **provides the graphical user interface and file management functions**. It is responsible for displaying the desktop, managing files and folders, launching applications, and handling system notifications

`dwm.exe` Desktop Window Manager (dwm.exe) composites windows in Windows, allowing for effects like transparency and live taskbar thumbnails.

`sihost.exe` [***Shell Infrastructure Host]***, in Windows 8 and above, when located in "C:\Windows\System32", is Microsoft's Shell Infrastructure Host. It works together with ShellExperienceHost.exe to control the Windows Graphical User Interface (GUI). It appears to depend on the Microsoft Visual C++ Redistributable Packages used by Windows. It handles only certain aspects such as taskbar opacity or transparency, the Start menu, displaying applications in the Windows interface, and changing wallpaper.

`WmiPrvSE.exe` legitimate and essential component for **keeping your computer's various applications and systems running effectively**.

`Smss.exe` is **the file name for the Session Manager Subsystem, a component of Microsoft Windows NT operating systems**. It is part of the Windows NT family of operating systems, starting in Windows NT 3.1 in 1993.

`MsMpEng.exe` - Its role is **to scan files for spyware, and quarantine or remove them if they are suspicious**. It also scans your laptop or desktop for known worms, harmful software, viruses, and other such programs.

The Windows Console Host, or `conhost.exe` , is both **the server application for all of the Windows Console APIs as well as the classic Windows user interface for working with command-line applications**.

The file extension `.ps1` is **used for PowerShell scripts**. A PowerShell script is a text file that contains one or more PowerShell commands. Each command appears on a separate line in the file

```bash
└─$ python3 vol.py -f ~/Desktop/sharedfolder/jerseyctf/living-on-the-edge/living-on-the-edge.vmem -o ~/Desktop/bin windows.memmap --dump --pid 5344

└─$ strings -e l pid.5344.dmp | grep jctf{ 
https://www.jerseyctf.com/?flag=jctf{3dg3_0f_y0ur_s3at}
https://www.jerseyctf.com/?flag=jctf{3dg3_0f_y0ur_s3at}#Resources
https://www.jerseyctf.com/?flag=jctf{3dg3_0f_y0ur_s3at}
...
```

```bash
remnux@remnux:/opt/volatility/dump$ file registry.UsrClassdat.0xab0a6570d000.hive 
registry.UsrClassdat.0xab0a6570d000.hive: MS Windows registry file, NT/2000 or above
```

[Image Magick](https://www.notion.so/Image-Magick-5111ec3d4d7f454aa79d7ca0879c03e3?pvs=21)

[Zbar Image](https://www.notion.so/Zbar-Image-085182e747f84210b073b0aded143c57?pvs=21)

[**Object Linking and Embedding (OLE)**](https://www.notion.so/Object-Linking-and-Embedding-OLE-8d5bc8e7117045acbdf7c35df31f06b5?pvs=21)

```bash
.pcapng - wireshack packet
 capture foresics
```

`Image Magick`

`Zbar Image`

To analyse and produce outputs for QR codes. 

```bash
zbarimg <image.png>
```

`OLE Tools`

```
olevba <file>.docx
```

`Gimp`

[How to Analyze Malicious Microsoft Office Files](https://intezer.com/blog/malware-analysis/analyze-malicious-microsoft-office-files/)

https://github.com/decalage2/oletools

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ oleid invitation.docm 
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: invitation.docm
WARNING  For now, VBA stomping cannot be detected for files in memory
--------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------+--------------------+----------+--------------------------
File format         |MS Word 2007+ Macro-|info      |                          
                    |Enabled Document    |          |                          
                    |(.docm)             |          |                          
--------------+--------------------+----------+--------------------------
Container format    |OpenXML             |info      |Container type            
--------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted 
--------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
--------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |This file does not contain
                    |                    |          |Excel 4/XLM macros.       
--------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships    
Relationships       |                    |          |such as remote templates, 
                    |                    |          |remote OLE objects, etc   
--------------+--------------------+----------+--------------------------
```

`apktool`

{{< figure src="2.png" alt="2" >}}

`decompile` .dex using the `dexdump` tool which is provided in android-sdk

`zipcrypto`

**`DeepBlueCLI` - Command-Line Tool to analyze windows event logs (evtx files)** 

**`LogParser` - Universal Query Tool**

### Blockchain

<aside>
💡 **Solidity contracts** are programs written in the Solidity programming language, which is specifically designed for writing smart contracts on blockchain platforms such as Ethereum. Smart contracts are self-executing contracts with the terms of the agreement directly written into code.

</aside>

[Fundamentals](https://www.notion.so/Fundamentals-95d714d0b28343b8bc9f2de51fb0f411?pvs=21)

[Other Concepts](https://www.notion.so/Other-Concepts-a0e5b1daf3c04a918ce54a9c6c9aed02?pvs=21)

[ABI](https://www.notion.so/ABI-8c619e9cee6b47baa461c0a03f98f198?pvs=21)

[Quickstart — web3.py 6.15.1 documentation](https://web3py.readthedocs.io/en/stable/quickstart.html)

```bash
>>> from web3 import Web3, EthereumTesterProvider
>>> w3 = Web3(EthereumTesterProvider())
>>> w3.is_connected()
True
```

**solc (Solidity Compiler) - ABI Generation**

[GitHub - 0xIchigo/Ethernaut: Solutions to Ethernaut, OpenZeppelin's Web3/Solidity based wargame](https://github.com/0xIchigo/Ethernaut/tree/master)

[Remix - Ethereum IDE](https://remix.ethereum.org/)

```python

In [1]: from web3 import Web3, AsyncWeb3

In [2]: url = 'http://94.237.57.161:31314/'

In [3]: web3 = Web3(Web3.HTTPProvider(url))

In [4]: web3
Out[4]: <web3.main.Web3 at 0x7f771f2dd990>

In [5]: web3.is_connected()
Out[5]: True

In[6]: abi = [
    {
        "inputs": [],
        "stateMutability": "payable",
        "type": "constructor"
    },
    {
        "inputs": [],
        "name": "TARGET",
        "outputs": [
            {
                "internalType": "contract RussianRoulette",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "stateMutability": "payable",
        "type": "constructor"
    },
    {
        "inputs": [],
        "name": "pullTrigger",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]
In [7]: sc = '0x0a9E45194F001F9b0b8c92F14B63d48dC37571c0'

In [8]: setup_contract = web3.eth.contract(address=sc, abi=abi)

In [9]: for f in setup_contract.functions:
   ...:     print(f)
   ...: 
TARGET
isSolved
pullTrigger
In [10]: web3.eth.block_number
Out[10]: 1

In [11]: balance = web3.eth.get_balance("0xD906F6268A3661414A8601c21c101b8d1323adD5")

In [12]: print(balance)
5000000000000000000000

In [13]: web3.from_wei(balance, 'ether')
Out[13]: Decimal('5000')

In [14]: setup_contract.functions.TARGET().call()
Out[14]: '0xD16950410fA12Bee8FE5f5cc20D113B29892F34a'

In [16]: target_contract = web3.eth.contract(address='0xD16950410fA12Bee8FE5f5cc20D113B29892F34a', abi=abi)

In [17]: for f in target_contract.functions:
    ...:     print(f)
    ...: 
TARGET
isSolved
pullTrigger

In [19]: target_contract.functions.pullTrigger().call()
Out[19]: 'im SAFU ... for now'

In [21]: setup_contract.functions.isSolved().call()
Out[21]: False

In [23]: balance = web3.eth.get_balance("0xD16950410fA12Bee8FE5f5cc20D113B29892F34a")

In [24]: print(balance)
10000000000000000000

In [25]: web3.from_wei(balance, 'ether')
Out[25]: Decimal('10')

In [26]: ca = '0xD16950410fA12Bee8FE5f5cc20D113B29892F34a'

In [27]: caller = '0xD906F6268A3661414A8601c21c101b8d1323adD5'

In [28]: pk = '0x9a7186e26154fea3976374a87e2b6b6af2c4421399bed492e3983d3a4459bacd'

In [29]: nonce = web3.eth.get_transaction_count(ca)

In [30]: print(nonce)
1

In [37]: web3.eth.chain_id
Out[37]: 31337

In [39]: web3.eth.gas_price
Out[39]: 1000000000

In [48]: tx = {
    ...:     'nonce': 1,
    ...:     'to': caller,
    ...:     'value': web3.to_wei(10, 'ether'),
    ...:     'gas': 200000,
    ...:     'gasPrice': web3.eth.gas_price,
    ...:     'chainId': 31337
    ...: }

In [49]: signed_tx = web3.eth.account.sign_transaction(tx, pk)

In [50]: tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

In [52]: print(tx_hash)
b'^D\xad\x0cxo\xf2\x84\x16\xa2\xe1\xa9\xe2y\x7fhuL\x97\x97\xa7%\x03\xe1;\t#\x93\x1eK\xee&'

```

[Solidity, Blockchain, and Smart Contract Course – Beginner to Expert Python Tutorial](https://youtu.be/M576WGiDBdQ?si=AAIIiG5XBfUSq4ia)

[Solidity — Solidity 0.8.28 documentation](https://docs.soliditylang.org/en/stable/)

[solidity](https://github.com/ethereum/solidity)

[Foundry Book](https://book.getfoundry.sh/)

[Learn Crypto – The Best Crypto Course on the Internet](https://teachyourselfcrypto.com/)

[ethereumbook](https://github.com/ethereumbook/ethereumbook)

[Blockchain](https://github.com/bellaj/Blockchain)

[ctf-blockchain](https://github.com/minaminao/ctf-blockchain)

More about `Blockchain` incoming!

### Game Hacking

`Cheat Engine`

[Cheat Engine](https://www.cheatengine.org/)

[Game Hacking](https://youtube.com/playlist?list=PLmqenIp2RQcg0x2mDAyL2MC23DAGcCR9b&si=0h0xH1thhezbTeqH)

`RPGMakerDecrypter`, which is a tool for extracting RPG Maker XP, VX and VX Ace encrypted archives.

[RPGMakerDecrypter](https://github.com/uuksu/RPGMakerDecrypter)

[game-hacking](https://github.com/dsasmblr/game-hacking)

Here is my write-up on IronCTF involving Game Hacking.

[IronCTF](https://abuctf.github.io/posts/IronCTF/#game-hacking)

### Android

[Blutter](https://github.com/worawit/blutter)

💡 `Blutter` is a Flutter Mobile Application Reverse Engineering Tool.

- [Apktool](https://ibotpeaches.github.io/Apktool/) – This tool is used for reverse engineering third party, closed, binary Android applications.
- [Dex2jar](https://github.com/pxb1988/dex2jar) – This widely available tool works with Android .dex and Java .class files, enabling the conversion of one binary format to another.
- [JD-GUI](https://github.com/java-decompiler/jd-gui) – This is a graphic utility tool that stands alone and displays Java sources from .class files.

Here are a few places to get started:

- [Android-Exploits](https://github.com/sundaysec/Android-Exploits) - This is an open-source guide on Android exploits and hacks from GitHub user [sundaysec](https://github.com/sundaysec), with links to additional resources and tools.
- [Hacking Android: 80 Pages of Experts' Tutorials](https://hakin9.org/download/hacking-android-80-pages-of-experts-tutorials/) –You will find code and tutorials on Android security, hacking, and exploits from monthly hacking and cybersecurity magazine Hakin9.

[IronCTF](https://abuctf.github.io/posts/IronCTF/#android)

### Resources

[Introduction - CTF Wiki](https://ctf-wiki.org/en/)

[Welcome | OOO archive | DEF CON CTF](https://archive.ooo/)

[pwn.college](https://pwn.college/)

[picoCTF - CMU Cybersecurity Competition](https://picoctf.org/)

[CryptoHack – Home](https://cryptohack.org/)

[TryHackMe | Cyber Security Training](https://tryhackme.com/)

[Hack The Box: The #1 Cybersecurity Performance Center](https://www.hackthebox.com/)

### Tools

[Vigenere Solver | guballa.de](https://www.guballa.de/vigenere-solver)

[Read DotCode Barcode Online](https://products.aspose.app/barcode/recognize/dotcode)

[XXTEA Encrypt & Decrypt - A.Tools](https://www.a.tools/Tool.php?Id=98)

[HiddenWave](https://github.com/techchipnet/HiddenWave)

[Rune Translator](https://valhyr.com/pages/rune-translator)

[azdle/b2](https://github.com/azdle/b2)

[hanynet.com • isteg](https://www.hanynet.com/isteg/)

[rengine](https://github.com/yogeshojha/rengine)

[Advance Recon Egnine](https://freelancermijan.github.io/reconengine/)

[pyzipper](https://pypi.org/project/pyzipper/)

[chessencryption](https://github.com/WintrCat/chessencryption)

[Attack-Defense Online Lab](https://www.attackdefense.com/)

[glitch](https://github.com/Blackslashtech/glitch)

```
flow-analyzing tool - tulip, vulnbox, Arkime, and exploit farms DestructiveFarm, 
FAST or Ataka.
```

{{< figure src="continue.jpg" alt="Continue" >}}
