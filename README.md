# ALinks

Collection of Active Directory links for purple teamers.

# ToC

- [Active Directory Red Team Tools](#active-directory-red-team-tools)
- [Active Directory Attacks & Defenses Tables](#active-directory-attacks-and-defenses-tables)
- [Sysmon for Blue Teams](#sysmon-for-blue-teams)
- [PowerShell ScriptBlock for Blue Teams](#powershell-scriptblock-for-blue-teams)
- [SIGMA Rules for Blue Teams](#sigma-rules-for-blue-teams)
- [Compliance](#compliance)
- [Security Baselines](#security-baselines)
- [Microsoft Security Blog](#microsoft-security-blog)
- [Hardening](#hardening)
- [Monitoring](#monitoring)
- [Honeys](#honeys)
- [Red Team](#red-team)
- [Evasion](#evasion)
- [Authentication Protocols Security](#authentication-protocols-security)
    - [Logon Types](#logon-types)
    - [LANMAN](#lanman)
        - [LM](#lm)
        - [NTLM](#ntlm)
        - [NTLMv1](#ntlmv1)
        - [NTLMv2](#ntlmv2)
    - [Kerberos](#kerberos)
        - [Kerberos 5](#kerberos-5)
    - [MsCache2](#mscache2)
    - [GSS-API/SSPI](#gss-apisspi)
        - [SSP](#ssp)
        - [Kerberos SSP](#kerberos-ssp)
        - [NTLM SSP](#ntlm-ssp)
        - [Negotiate SSP](#negotiate-ssp)
        - [Digest SSP](#digest-ssp)
        - [Secure Channel SSP](#secure-channel-ssp)
        - [Cred SSP](#cred-ssp)
        - [Custom SSP](#custom-ssp)
- [Network Protocols Security](#network-protocols-security)
    - [NTLM](#ntlm)
        - [Pass The Hash](#pass-the-hash)
    - [Kerberos](#kerberos)
        - [Kerberoasting](#kerberoasting)
        - [Timeroasting](#timeroasting)
        - [AS-REP Roasting](#as-rep-roasting)
        - [AS-REQ Roasting](#as-req-roasting)
        - [Kerberos Diamond Tickets](#kerberos-diamond-tickets)
        - [Kerberos Golden Tickets](#kerberos-golden-tickets)
        - [Kerberos Silver Tickets](#kerberos-silver-tickets)
        - [Kerberos Bronze Tickets](#kerberos-bronze-tickets)
        - [Kerberos Sapphire Tickets](#kerberos-sapphire-tickets)
        - [Kerberos Pass-The-Ticket](#kerberos-pass-the-ticket-ptt)
        - [Kerberos Unconstrained Delegation](#kerberos-unconstrained-delegation)
        - [Kerberos Constrained Delegation](#kerberos-constrained-delegation)
        - [Kerberos Resource-Based Constrained Delegation](#kerberos-resource-based-constrained-delegation-rbcd)
        - [Kerberos Pass The Certificate](#kerberos-pass-the-certificate)
        - [Kerberos UnPAC The Hash](#kerberos-unpac-the-hash)
        - [Kerberos OverPass The Hash](#kerberos-overpass-the-hash--pass-the-key)
        - [Kerberos Pre-Authentication Bruteforce](#kerberos-pre-authentication-bruteforce)
    - [ARP](#arp)
    - [DHCP](#dhcp)
    - [DHCPv6](#dhcpv6)
    - [SMB](#smb)
    - [LDAP](#ldap)
    - [DNS](#dns)
    - [LLMNR](#llmnr)
    - [NetBIOS](#netbios)
    - [WPAD](#wpad)
    - [RPC](#rpc)
    - [SAMRPC](#samrpc)
    - [WinRM](#winrm)
    - [RDP](#rdp)
    - [IIS](#iis)
    - [WSUS](#wsus)
    - [Active Directory Federation Services](#active-directory-federation-services)
    - [SSH](#ssh)
    - [DFS](#dfs)
    - [MSSQL](#mssql)
    - [Active Directory Integrated DNS ADIDNS](#active-directory-integrated-dns-adidns)
    - [Microsoft's Encrypting File System Remote MS-EFSR](#microsofts-encrypting-file-system-remote-ms-efsr)
    - [Microsoft’s Print Spooler MS-RPRN](#microsofts-print-spooler-ms-rprn)
    - [Microsoft's File Server Remote VSS MS-FSRVP](#microsofts-file-server-remote-vss-ms-fsrvp)
    - [Microsoft's Distributed File System Namespace Management MS-DFSNM](#microsofts-distributed-file-system-namespace-management-ms-dfsnm)
- [Read Only Domain Controller](#read-only-domain-controller)
- [Active Directory Certificate Services](#active-directory-certificate-services)
    - [ESC1](#esc1)
    - [ESC2](#esc2)
    - [ESC3](#esc3)
    - [ESC4](#esc4)
    - [ESC5](#esc5)
    - [ESC6](#esc6)
    - [ESC7](#esc7)
    - [ESC8](#esc8)
    - [ESC9](#esc9)
    - [ESC10](#esc10)
    - [ESC11](#esc11)
    - [ESC12](#esc12)
    - [ESC13](#esc13)
    - [ESC14](#esc14)
    - [ESC15](#esc15)
    - [ESC16](#esc16)
- [Trust Relationships](#trust-relationships)
    - [Trust Direction](#trust-direction)
    - [Trust Transitivity](#trust-transitivity)
    - [SID Filtering](#sid-filtering)
    - [Selective Authentication](#selective-authentication)
    - [Trust Types](#trust-types)
    - [Trust Key](#trust-key)
    - [Forest to Forest](#forest-to-forest)
        - [Extra SID / SID History](#extra-sid--sid-history)
        - [MSSQL Trusted Links](#mssql-trusted-links)
    - [Child Domain to Forest](#child-domain-to-forest)
        - [Known Parent/Child](#known-parentchild)
- [Access Tokens](#access-tokens)
- [Discretionary Access Control Lists DACLs and Access Control Entries ACEs](#discretionary-access-control-lists-dacls-and-access-control-entries-aces)
    - [Users](#users)
    - [Groups](#groups)
    - [Services](#services)
    - [Computers](#computers)
    - [Directories](#directories)
    - [Files](#files)
    - [Group Policy](#group-policy)
- [Group Policy Object GPO](#group-policy-object-gpo)
    - [GPO Scopes](#gpo-scopes)
    - [Group Policy Template](#group-policy-template)
    - [Group Policy Container](#group-policy-container)
    - [GPO Inheritance](#gpo-inheritance)
- [Users](#users)
    - [Local Users](#local-users)
    - [Domain Users](#domain-users)
    - [Azure AD Users](#azure-ad-users)
    - [Built-in Privileged Users](#built-in-privileged-users)
- [Groups](#groups)
- [DCOM](#dcom)
- [Comments](#comments)
- [Pre-Created Computer Account](#pre-created-computer-account)
- [Shadow Credentials](#shadow-credentials)
- [Group Managed Service Accounts gMSA](#group-managed-service-accounts-gmsa)
- [System Services](#system-services)
- [Task Scheduler](#task-scheduler)
- [Local Administrator Password Solution LAPS](#local-administrator-password-solution-laps)
- [Application Control](#application-control)
    - [AppLocker](#applocker)
    - [WDAC](#wdac)
- [Backups](#backups)
    - [Windows Shadow Copies](#windows-shadow-copies)
    - [Active Directory Recycle Bin](#active-directory-recycle-bin)
- [Windows Subsystem for Linux](#windows-subsystem-for-linux)
- [Drivers](#drivers)
- [Unquoted Paths](#unquoted-paths)
- [JIT & JEA](#jit--jea)
- [Microsoft Defender for Identity MDI](#microsoft-defender-for-identity-mdi)
- [Credentials](#credentials)
    - [Directory Service Restore Mode DSRM](#directory-service-restore-mode-dsrm)
    - [DPAPI](#dpapi)
    - [LSASS](#lsass)
    - [SAM](#sam)
    - [NTDS](#ntds)
    - [Windows Credential Manager](#windows-credential-manager)
    - [Azure AD Connect](#azure-ad-connect)
    - [LSA](#lsa)
    - [RunAs Saved Credentials](#runas-saved-credentials)
    - [Registry Hive Credentials](#registry-hive-credentials)
    - [PowerShell History Credentials](#powershell-history-credentials)
    - [Clipboard Credentials](#clipboard-credentials)
- [Persistence](#persistence)
    - [DCShadow](#dcshadow)
    - [DCSync](#dcsync)
    - [AdminDSHolder](#admindsholder)
    - [DLL Hijacking Persistence](#dll-hijacking-persistence)
- [Account Takeover](#account-takeover)
    - [AD Attribute](#ad-attribute)
    - [Shadow Credentials](#shadow-credentials)
- [MiTM](#mitm)
- [Classic Vulnerabilities](#classic-vulnerabilities)

# Active Directory Red Team Tools

Here's a list of common red team tools.

## 1. Reconnaissance & Enumeration
- **BloodHound**: AD enumeration and attack path mapping.
- **SharpHound**: BloodHound data collector (C#).
- **PowerView**: PowerShell toolkit for AD enumeration.
- **ADRecon**: Automated AD recon and documentation.
- **PingCastle**: Security assessment for AD.
- **LDAPSearch / AdFind**: LDAP enumeration tools.
- **NetSPI PowerUpSQL**: Attacks and audits SQL Server in AD.
- **ADExplorer**: AD database viewer and snapshot tool.
- **Find-Delegation**: PowerShell script for enumerating AD delegations.
- **LAPSToolkit**: Enumerates LAPS settings and credentials.

## 2. Credential Access & Extraction
- **Mimikatz**: Extracts credentials and Kerberos tickets.
- **Rubeus**: Kerberos ticket interaction.
- **LaZagne**: Extracts local credentials.
- **SharpDPAPI**: Attacks Windows DPAPI for secrets.
- **CredentialDumping (secretsdump.py, procdump.exe, etc.)**: Extracts credentials and hashes.
- **Gsecdump**: Dumps hashes from LSASS.
- **Windows Credential Editor (WCE)**: Extracts hashes and Kerberos tickets.
- **Invoke-Mimikatz**: PowerShell wrapper for Mimikatz.
- **Tokenvator**: Manipulates tokens for privilege escalation.

## 3. Lateral Movement
- **Impacket Toolkit**: SMB, RDP, Kerberos, and more (e.g., `psexec.py`, `wmiexec.py`, `dcomexec.py`).
- **PsExec (Sysinternals)**: Remote process execution.
- **CrackMapExec (CME)**: Network penetration testing tool.
- **SMBexec**: Executes commands over SMB.
- **WMImplant**: WMI lateral movement and command execution.
- **Invoke-TheHash**: Executes commands using NTLM hashes.
- **DAMP (Domain Admin Move Paths)**: Explores lateral movement options.
- **Evil-WinRM**: Powershell Remoting via WinRM.

## 4. Privilege Escalation
- **PowerUp**: PowerShell for Windows privilege escalation.
- **Seatbelt**: Host recon for escalation vectors.
- **Sherlock**: Checks for privilege escalation vulnerabilities.
- **Watson**: Finds privilege escalation vulnerabilities on Windows.
- **PrivescCheck**: Scans for common misconfigurations.
- **JAWS**: Windows local privilege escalation enumeration.

## 5. Persistence
- **Mimikatz / Rubeus**: Golden/Silver ticket generation.
- **DSInternals**: Interacts with AD DB for persistence.
- **Skeleton Key**: Patch LSASS to accept a master password.
- **Invoke-BackdoorLNK**: Creates malicious LNK files for persistence.
- **Koadic (COM Command & Control)**: Remote code execution and persistence.

## 6. Post-Exploitation & Command and Control (C2)
- **Cobalt Strike**: Full-featured C2 platform.
- **Empire**: PowerShell/C# C2.
- **Sliver**: Modern open-source C2.
- **Metasploit**: Exploitation and C2 framework.
- **Koadic**: COM C2 post-exploitation framework.
- **Pupy**: Multi-platform C2 and RAT.
- **Mythic**: Modern, web-based C2.

## 7. Miscellaneous / Support Tools
- **Responder**: LLMNR, NBT-NS, MDNS poisoning.
- **Inveigh**: PowerShell spoofing tool.
- **Certify**: AD CS enumeration and abuse.
- **PetitPotam**: EFSRPC NTLM relay attacks.
- **Coercer**: Forces remote authentication from Windows hosts.
- **NTLMRelayX**: Relays NTLM authentication.
- **Sprayhound**: Password spraying tool for AD.
- **Kerbrute**: Kerberos pre-auth user enumeration and password spraying.
- **CrackMapExec (Spraying features)**: Password spray and hash spraying.
- **Rpcdump**: Enumerates RPC endpoints.

## 8. Active Directory Certificate Services (AD CS) Abuse
- **Certify**: Enumeration and abuse of AD CS.
- **ForgeCert**: Forge certificates from vulnerable AD CS configurations.
- **Certipy**: Python tool for enumeration and abuse of AD CS.

## 9. Defensive Evasion
- **Invoke-Obfuscation**: PowerShell script obfuscator for bypassing detection.
- **PSReflect**: In-memory PowerShell module loading to avoid AV/EDR.
- **Nimcrypt**: Nim-based loader/encrypter for payloads.
- **Donut**: Generates shellcode from PE, .NET assemblies, and more.
- **Sharpshooter**: Payload generator for obfuscated JavaScript and HTA files.
- **Covenant**: .NET C2 framework with built-in evasion techniques.
- **SharpHide**: Hides payloads in alternate data streams.
- **PEzor**: Shellcode crypter and loader for Windows payloads.
- **Invoke-CradleCrafter**: Generates various download cradles to avoid network detection.
- **GhostPack**: Collection of C# tools designed to evade modern defenses (Rubeus, Seatbelt, SharpDump, etc.).
- **SCShell**: Lateral movement using Windows Service Control Manager without touching disk.
- **PoshC2**: C2 framework with evasion and obfuscation modules.
- **Luckystrike**: Malicious Office document generator with payload obfuscation.
- **Shellter**: Dynamic shellcode injection tool for AV evasion.
- **Metasploit's msfvenom**: Payload generation and encoding for AV bypass.
- **Veil Framework**: Payload obfuscation and AV evasion framework.
- **EvilClippy**: Manipulates and obfuscates MS Office documents (macros, VBA stomping).
- **Obfuscation.io**: Cross-language code obfuscator.
- **PowerShell AMSI & ETW Bypass Techniques**: Various scripts and methods for bypassing Anti-Malware Scan Interface and Event Tracing for Windows.
- **Invoke-PSInject**: Injects PowerShell into memory to avoid writing to disk.
- **StarFighter**: Bypasses application whitelisting (AppLocker, DeviceGuard).
- **ScareCrow**: Payload loader targeting EDR bypasses, especially for Cobalt Strike beacons.
- **SilkETW/SilkService**: For stealthy collection and evasion testing against ETW.

**Tip:**  
Most evasion tools are in active development—Blue Teams should continually update detection rules and test visibility against new evasion methods.

# Active Directory Attacks AND Defenses Tables

General AD Tier Zero Asset Abuse Attacks & Defenses:

| **Technique**              | **Description**                                                              | **Mitigation**                                              | **Detection Event/Rule**                        | **SIEM Detection Query (Splunk/KQL)**                                                                                |
|----------------------------|------------------------------------------------------------------------------|-------------------------------------------------------------|-------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **Domain Controller Compromise** | Attacker gains access to any DC, controlling AD forest/domain                | Physically/virtually isolate DCs; restrict admin logon       | 4624/4625 (DC logons), 4672 (special privileges) | Splunk: `index=wineventlog (EventCode=4624 OR EventCode=4672) ComputerName="DC*"`                                    |
| **KRBTGT Account Abuse**   | Theft/use of KRBTGT account for golden ticket attacks                        | Regularly reset KRBTGT; monitor ticket lifetimes             | 4768/4769 (abnormal TGT/TGS), 4624              | KQL: `SecurityEvent | where EventID==4768 or EventID==4769 and TicketOptions has "long_lifetime"`                |
| **AD CS (PKI) Compromise** | Compromise of CA, template, or PKI permissions for Tier Zero escalation      | Secure PKI hosts; restrict CA admins; audit templates        | 4886/4887 (CA logs), 4624 (CA server logons)     | Splunk: `index=wineventlog (EventCode=4886 OR EventCode=4887) Template_Name="*"`                                     |
| **AdminSDHolder/Protected Group Compromise** | Direct or indirect abuse of Tier Zero (protected) groups               | Limit group membership; monitor AdminSDHolder/ACL changes    | 4662/5136 (ACL change), 4732/4728 (group add)   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136 OR EventCode=4732) Group_Name="Domain Admins"`           |
| **GPO Abuse for Tier Zero** | Abuse GPOs linked to Tier Zero assets (e.g., DCs, PKI servers)              | Strict GPO delegation; monitor GPO links to Tier Zero OUs    | 5136 (GPO mod), 4739 (GPO linked)                | Splunk: `index=wineventlog (EventCode=5136 OR EventCode=4739) GroupPolicyLinked="*DC*" OR "*Tier0*"`                 |

General AD Abuse of Default ACLs Attacks & Defenses:

| **Technique**               | **Description**                                                             | **Mitigation**                                    | **Detection Event/Rule**                  | **SIEM Detection Query (Splunk/KQL)**                                                               |
|-----------------------------|-----------------------------------------------------------------------------|---------------------------------------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Default User/Group ACLs** | Exploit overly permissive default permissions on objects (users/groups)     | Harden default ACLs; use ACL templates            | 4662/5136 (ACL change), 4738 (user mod)   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) | search Rights="FullControl" or "GenericAll"`                    |
| **Computer Object ACLs**    | Abuse computer object permissions for privilege escalation (e.g., RBCD)     | Restrict who can join computers; review ACLs      | 4662/5136 (computer object mod)            | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Object_Type="computer"`                |
| **OU Delegation Defaults**  | Unintended access via default OU ACL inheritance                            | Regular OU ACL review; block inheritance where needed| 5136 (OU mod), 4739 (OU permissions)     | Splunk: `index=wineventlog (EventCode=5136 OR EventCode=4739) Object_Type="organizationalUnit"`      |
| **Inherited Permissions**   | Abuse inherited permissions for escalation/persistence                      | Block unwanted inheritance; audit effective rights | 4662/5136 (inheritance changes)            | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) | search Inheritance="Enabled"`                                  |


General AD ACLs Attacks & Defenses:

| **Attack/Abuse Vector**              | **Description**                                                                      | **Mitigation**                                              | **Detection Event/Rule**                  | **SIEM Detection Query (Splunk/KQL)**                                                               |
|--------------------------------------|--------------------------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **GenericAll Permission**            | Grants full control over an object, including user/group, computer, or OU            | Limit assignment; regular permission audits                  | 4662/5136 (object ACL change)              | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Rights="GenericAll"`                  |
| **GenericWrite Permission**          | Grants right to modify most object properties (passwords, group membership, etc.)    | Limit GenericWrite assignments; use least privilege          | 4662/5136                                   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Rights="GenericWrite"`                |
| **WriteDACL/WriteOwner Permission**  | Allows changing an object’s ACL or owner (take control of object, escalate/lockout)  | Avoid WriteDACL/WriteOwner except for admins                 | 4662/5136                                   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Rights="WriteDACL" OR Rights="WriteOwner"` |
| **All Extended Rights**              | Grants all “extended rights” (e.g., reset password, add child objects)               | Audit extended rights; restrict to trusted admins            | 4662/5136                                   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Rights="AllExtendedRights"`           |
| **ResetPassword Extended Right**     | Ability to reset password for user/computer objects (privilege escalation vector)    | Limit reset rights to helpdesk/admins only                   | 4662/5136                                   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Rights="ResetPassword"`               |
| **AddMember Extended Right**         | Right to add users to groups (especially dangerous on admin groups)                  | Restrict AddMember rights; monitor group changes             | 4732/4728 (group add), 4662                 | Splunk: `index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4662) Rights="AddMember"` |
| **Self Permission**                  | Object owner/user can modify own properties (dangerous if combined with other rights)| Limit use of SELF where not required                         | 4662/5136                                   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Principal="SELF"`                     |
| **Abuse via Inherited Permissions**  | Attacker abuses inherited ACLs (from OUs/groups) to gain rights on objects           | Review inheritance; block where not needed                    | 4662/5136 (inheritance change)               | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Inheritance="Enabled"`                |
| **ACL Backdoor/Persistence**         | Attacker adds a hidden user/group or SID to ACL for persistent access                | Regular permission audits; monitor unexpected ACEs           | 4662/5136 (unknown SID, unexpected ACE)      | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) | search SID="S-1-5-21*" AND NOT Principal IN (expected list)`   |
| **Abuse of AdminSDHolder**           | Modifying AdminSDHolder ACL applies changes to all protected groups                  | Monitor AdminSDHolder; limit who can modify it               | 4662/5136 (AdminSDHolder mod)                | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Object_Name="AdminSDHolder"`          |
| **msDS-AllowedToActOnBehalfOfOtherIdentity** | Abuse this RBCD attribute for resource-based delegation (persistence/impersonation) | Limit who can write msDS-AllowedToActOnBehalfOfOtherIdentity | 4662/5136                                   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Attribute_Name="msDS-AllowedToActOnBehalfOfOtherIdentity"` |

General AD Delegated OUs or Custom Delegations Attacks & Defenses:

| **Technique**                     | **Description**                                                      | **Mitigation**                                    | **Detection Event/Rule**                   | **SIEM Detection Query (Splunk/KQL)**                                                               |
|-----------------------------------|----------------------------------------------------------------------|---------------------------------------------------|---------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **OU Write Delegation Abuse**     | Delegated OU control lets attackers create users/groups with escalated rights | Restrict OU delegation; least privilege          | 5136 (OU mod), 4720 (user creation)         | Splunk: `index=wineventlog (EventCode=5136 OR EventCode=4720) Object_Type="organizationalUnit"`      |
| **Delegated GPO Linking**         | Attacker links malicious GPOs to OUs they control                     | Restrict GPO delegation; monitor link changes     | 5136 (GPO mod), 4739 (GPO linked to OU)     | Splunk: `index=wineventlog (EventCode=5136 OR EventCode=4739) | search GroupPolicyLinked="*OU*"`                               |
| **Object Control via Delegation** | Custom permissions grant broad control to objects in delegated OU     | Regular ACL reviews; audit custom permissions     | 4662/5136 (object mod), 4728 (group mod)    | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136 OR EventCode=4728) Object_Type="user"`  |
| **Delegated Admin Group Control** | Delegated rights over custom admin groups in non-protected OUs        | Limit admin group delegation; monitor group mods  | 4728/4729 (group mod), 5136 (OU mod)        | Splunk: `index=wineventlog (EventCode=4728 OR EventCode=4729 OR EventCode=5136) Group_Name="*Admin*"`|

General AD Shadow Admins Attacks & Defenses:

| **Technique**                  | **Description**                                                             | **Mitigation**                                          | **Detection Event/Rule**                  | **SIEM Detection Query (Splunk/KQL)**                                                                   |
|-------------------------------|-----------------------------------------------------------------------------|---------------------------------------------------------|--------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **Privileged ACL Delegation**  | Users/groups with rights to reset admin passwords/modify groups             | Regular ACL reviews; BloodHound/PowerView analysis      | 4662/5136 (ACL changes), 4728 (group add)  | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) | search Rights="ResetPassword"`                                    |
| **WriteDACL/WriteOwner Abuse** | Users with WriteDACL/WriteOwner on admin groups/OUs grant selves full access| Limit WriteDACL/WriteOwner rights; monitor assignments  | 4662/5136 (ACL mod), 4732                  | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) | search Object_Type="group" Rights="WriteDACL"`                   |
| **Service Principal Abuse**    | Shadow admins with control of service accounts that are members of admin groups| Harden SPN permissions; audit service accounts          | 4728/4732 (group add), 4670                | Splunk: `index=wineventlog EventCode=4728 Group_Name="Domain Admins" AND Account_Type="Service"`         |
| **Group Nesting Abuse**        | Nested groups grant indirect admin rights                                   | Flatten group memberships; audit nested groups           | 4728 (group membership change)              | Splunk: `index=wineventlog EventCode=4728 | stats count by Member_Name, Group_Name`                            |
| **GPO Delegation Abuse**       | Users delegated to manage GPOs linked to privileged OUs                     | Restrict GPO management; review GPO delegation           | 5136 (GPO change)                           | Splunk: `index=wineventlog EventCode=5136 | search GroupPolicyLinked="*Admin*" OR "*DC*"`                     |

General AD Password Policy & Authentication Attacks & Defenses:

| **Attack/Vector**                | **Description**                                           | **Mitigation**                                    | **Detection Event/Rule**         | **SIEM Detection Query (Splunk/KQL)**                                                  |
|----------------------------------|-----------------------------------------------------------|---------------------------------------------------|-----------------------------------|----------------------------------------------------------------------------------------|
| Password Spraying                | Trying common passwords across many users                 | MFA; strong password policy; account lockout      | 4625 (failed logon)               | Splunk: `index=wineventlog EventCode=4625 | stats count by src_ip, Account_Name | where count > threshold`          |
| Cracking Weak Password Hashes    | Cracking offline hashes from SAM/NTDS                     | Strong passwords; disable LM/NTLM                 | 4662/4663 (NTDS/SAM access)       | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=4663) Object_Name="*NTDS*"`    |
| Password Never Expires Abuse     | Targeting accounts with passwords set never to expire     | Periodic password audits; alert on flag           | 4738 (user mod), 4722 (user enable)| Splunk: `index=wineventlog EventCode=4738 UserAccountControl="Password Never Expires"`  |
| Kerberos Pre-Auth Not Required   | AS-REP roasting of users without pre-auth                 | Require pre-auth for all users                    | 4768                              | Splunk: `index=wineventlog EventCode=4768 PreAuthType="NONE"`                         |
| Fine-Grained Policy Abuse        | Abusing weak FGPP (PSO) assignments                       | Audit all FGPPs; align PSOs with org policy       | 4739 (FGPP applied)                | Splunk: `index=wineventlog EventCode=4739 | search "PasswordSettings"`                        |

General AD Account & Group Management Attacks & Defenses:

| **Attack/Vector**                | **Description**                                      | **Mitigation**                                        | **Detection Event/Rule**         | **SIEM Detection Query (Splunk/KQL)**                                            |
|----------------------------------|------------------------------------------------------|-------------------------------------------------------|-----------------------------------|----------------------------------------------------------------------------------|
| Orphaned SIDs/Stale Objects      | Unused or orphaned accounts/groups leveraged         | Periodic AD cleanup; disable/remove stale objects     | 4725/4726 (group/user delete)     | Splunk: `index=wineventlog (EventCode=4725 OR EventCode=4726)`                   |
| Exploiting Disabled/Expired Accts| Re-enabling or re-using old accounts for access      | Disable then delete; monitor for re-enables           | 4722 (user enabled), 4725 (delete)| Splunk: `index=wineventlog EventCode=4722`                                       |
| Shadow Groups                    | Group nesting for stealth escalation                 | Regular group membership audits                       | 4728 (add to group)               | Splunk: `index=wineventlog EventCode=4728 | stats count by Member_Name, Group_Name`           |
| Account Operators Abuse          | Account Operators group can modify many accounts     | Restrict membership; monitor group                    | 4728/4732 (group changes)         | Splunk: `index=wineventlog (EventCode=4728 OR EventCode=4732) Group_Name="Account Operators"` |

General AD Object/Schema Attacks & Defenses:

| **Attack/Vector**                   | **Description**                                 | **Mitigation**                                    | **Detection Event/Rule**         | **SIEM Detection Query (Splunk/KQL)**                                   |
|-------------------------------------|-------------------------------------------------|---------------------------------------------------|-----------------------------------|--------------------------------------------------------------------------|
| Schema Extension Abuse              | Adding malicious attributes or objects          | Restrict schema admin role; alert on changes      | 1109 (schema change)              | Splunk: `index=wineventlog EventCode=1109`                              |
| msDS-AllowedToDelegateTo Abuse      | Control over delegation enables escalation      | Monitor & restrict attribute modifications        | 4662/5136 (object mod)            | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Attribute_Name="msDS-AllowedToDelegateTo"` |
| msDS-AllowedToActOnBehalf Abuse     | Resource-based constrained delegation           | Audit & restrict who can write this attribute     | 4662/5136 (object mod)            | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Attribute_Name="msDS-AllowedToActOnBehalfOfOtherIdentity"` |
| adminCount Flag Manipulation        | Clearing or setting adminCount to affect protections | Monitor adminCount changes                      | 4738 (user mod)                   | Splunk: `index=wineventlog EventCode=4738 | search adminCount`                  |


General AD SYSVOL/GPO Attacks & Defenses:

| **Attack/Vector**                  | **Description**                                        | **Mitigation**                                         | **Detection Event/Rule**         | **SIEM Detection Query (Splunk/KQL)**                              |
|------------------------------------|--------------------------------------------------------|--------------------------------------------------------|-----------------------------------|--------------------------------------------------------------------|
| Backdoored SYSVOL Scripts          | Place backdoor in logon/startup scripts                | Restrict write to SYSVOL; script integrity monitoring   | 4663 (file access), 5145          | Splunk: `index=wineventlog EventCode=4663 Object_Name="*SYSVOL*"`  |
| GPP cPassword Abuse                | Steal credentials from Group Policy Preferences         | Remove cPasswords; monitor for cPassword in SYSVOL      | 4663 (file read), 5136 (GPO mod)  | Splunk: `index=wineventlog (EventCode=4663 OR EventCode=5136) | search "cPassword"`   |
| GPO-Based Persistence              | Set GPO to run code or maintain access (startup, logon) | Restrict GPO edits; audit script/command lines in GPOs  | 5136 (GPO mod), 4688 (proc exec)  | Splunk: `index=wineventlog EventCode=5136 Object_Type="groupPolicyContainer"` |

General AD Backup & Recovery Attacks & Defenses:

| **Attack/Vector**             | **Description**                                               | **Mitigation**                                          | **Detection Event/Rule**        | **SIEM Detection Query (Splunk/KQL)**                          |
|-------------------------------|---------------------------------------------------------------|---------------------------------------------------------|----------------------------------|----------------------------------------------------------------|
| Backup Operators Abuse        | Backup Operators can read files as SYSTEM                     | Limit group membership; monitor group changes           | 4728/4732 (group changes)        | Splunk: `index=wineventlog (EventCode=4728 OR EventCode=4732) Group_Name="Backup Operators"` |
| Restore Tool Abuse            | Restore or copy ntds.dit or registry for offline attacks      | Restrict tool access; audit backup/restore operations   | 4663 (file access), 7045         | Splunk: `index=wineventlog EventCode=4663 Object_Name="*NTDS*" OR Object_Name="*SAM*"`    |

General AD Living Off The Land (LOL) Persistence & Movement Attacks & Defenses:

| **Attack/Vector**            | **Description**                                 | **Mitigation**                                 | **Detection Event/Rule**           | **SIEM Detection Query (Splunk/KQL)**                            |
|------------------------------|-------------------------------------------------|-----------------------------------------------|------------------------------------|------------------------------------------------------------------|
| WMI Event Subscription       | Run code on trigger using WMI                   | Monitor WMI event subscriptions; restrict WMI | Sysmon 19 (WMI event)              | Splunk: `index=sysmon EventCode=19`                              |
| Scheduled Task Persistence   | Malicious scheduled task runs code persistently | Restrict who can create tasks; monitor 4698   | 4698 (task created), 4688 (schtasks.exe) | Splunk: `index=wineventlog EventCode=4698`                    |
| Service Creation/Abuse       | Use services to persist or escalate             | Monitor 7045, restrict service creation       | 7045 (service install), 4688       | Splunk: `index=wineventlog EventCode=7045`                       |
| Windows Subsystem for Linux  | Use WSL for persistence or movement             | Disable if not needed; monitor process usage  | 4688 (bash.exe/wsl.exe), 4104      | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*wsl.exe*"`     |

General AD DNS Attacks & Defenses:

| **Attack/Abuse Vector**      | **Description**                                                                 | **Mitigation**                                                   | **Detection Event/Rule**                | **SIEM Detection Query (Splunk/KQL)**                                                                                  |
|------------------------------|---------------------------------------------------------------------------------|------------------------------------------------------------------|------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| **DNS Reconnaissance**       | Attackers enumerate AD DNS zones, records, and service locations for targeting   | Restrict DNS zone transfer; enable auditing                       | 5156 (DNS queries), 4662 (object access) | Splunk: `index=wineventlog EventCode=5156 DestPort=53 | stats count by src_ip`                                                           |
| **Zone Transfer Attack**     | Unauthorized transfer of entire DNS zone (all records)                           | Disable zone transfers or restrict to authorized IPs              | 6001 (zone transfer), DNS server logs    | Splunk: `index=dnsevent EventCode=6001 | stats count by src_ip, zone`                                                      |
| **DNS Record Manipulation**  | Attacker modifies or adds DNS records (e.g., for man-in-the-middle, persistence) | Harden DNS ACLs; monitor record changes; restrict dynamic updates | 5136 (DNS record change), 257 (MS DNS)   | Splunk: `index=wineventlog (EventCode=5136) Object_Type="dnsNode"`                                                    |
| **DNSAdmin Privilege Escalation** | Abuse DNSAdmins group to load DLLs as SYSTEM (plugin execution)            | Remove unnecessary users from DNSAdmins; monitor group changes    | 4728/4732 (group changes), 4697 (DLL load)| Splunk: `index=wineventlog (EventCode=4728 OR EventCode=4732) Group_Name="DNSAdmins"`                                  |
| **DNS Cache Poisoning**      | Attacker injects malicious DNS entries into server cache for MITM/redirection    | Use DNSSEC; restrict who can update DNS; monitor cache entries    | 257 (MS DNS event), 5156                  | Splunk: `index=dnsevent EventCode=257 | search "cache" or "update"`                                                       |
| **Dynamic Update Abuse**     | Attacker abuses dynamic DNS update to register malicious or rogue records        | Restrict dynamic updates to trusted hosts                         | 257, 5136 (record add)                    | Splunk: `index=dnsevent EventCode=257 | search "dynamic update"`                                                          |
| **DNS Tunneling/Exfiltration** | Exfiltrate data using DNS queries (e.g., via text records, long/random domains)| Detect long/rare queries; restrict outbound DNS                   | 5156 (outbound DNS), 257                  | Splunk: `index=dnsevent EventCode=257 | regex query=".{50,}" | stats count by src_ip`                                                             |
| **Delegated Zone Exploitation** | Abuse of delegated or stub zones for persistence/lateral movement            | Regular review of delegated/stub zones; restrict delegation       | 5136 (zone changes), 257                   | Splunk: `index=wineventlog (EventCode=5136) Object_Type="dnsZone"`                                                    |
| **DNS Logging Gaps**         | Attackers clear/disable DNS logs to hide activity                               | Monitor for log service stops/clears                              | 517 (system logs cleared), 1102            | Splunk: `index=wineventlog (EventCode=517 OR EventCode=1102) SourceName="DNS Server"`                                  |

General AD DNS TTPs:

| **Attack/Technique**            | **Description**                                                                                   | **Mitigation**                                             | **Detection Event/Rule**                    | **SIEM Detection Query (Splunk/KQL)**                                                                                 |
|---------------------------------|---------------------------------------------------------------------------------------------------|------------------------------------------------------------|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| **DNS Record Persistence**      | Add/alter DNS records (A, CNAME, TXT, etc.) for C2, backdoor, or to maintain foothold             | Audit/alert on DNS changes; restrict who can modify        | 5136 (DNS record mod), 257 (MS DNS)          | Splunk: `index=wineventlog (EventCode=5136) Object_Type="dnsNode"`                                                   |
| **Malicious TXT Records for C2**| TXT records store encoded C2 instructions, exfil data, or PowerShell/command payloads              | Limit TXT records; alert on new/changed TXT; restrict who can create | 5136, 257                              | Splunk: `index=dnsevent EventCode=257 RecordType="TXT" | stats count by src_ip, Name, Text`                                              |
| **C2 via DNS (DNS Tunneling)**  | Use DNS queries to tunnel data or receive commands (Cobalt Strike, DNSCat2, etc.)                 | Alert on abnormal/long queries, rare domains, beaconing    | 5156, 257, DNS logs                          | Splunk: `index=dnsevent EventCode=257 | regex query=".{40,}" | stats count by src_ip | where count > threshold`                    |
| **Domain Generation Algorithm (DGA) C2** | Malware generates many pseudo-random DNS queries for C2                                | Alert on high rate of failed/unique lookups                | 257, DNS logs                                | Splunk: `index=dnsevent EventCode=257 | stats dc(query) by src_ip | where dc_query > threshold`                 |
| **Phantom Subdomain Registration**| Registering non-existent or typo-squatted subdomains to lure traffic or for persistence           | Alert on new subdomains, monitor registration process      | 5136, 257                                    | Splunk: `index=wineventlog (EventCode=5136) | search Name="*.corp.local" or Name="typo*.local"`                               |
| **DNS Record Hijacking**        | Change records (A, CNAME) to point to attacker infra (MITM, C2, phishing)                         | Audit/alert on sensitive record changes; limit access      | 5136, 257                                    | Splunk: `index=wineventlog (EventCode=5136) | search Object_Type="dnsNode" AND NewValue NOT IN (expected list)`               |
| **DNS Wildcard/Generic Record Abuse** | Add wildcard (*) DNS records for broad traffic capture/redirect                             | Block wildcard records; review DNS zone configs            | 5136, 257                                    | Splunk: `index=dnsevent EventCode=257 | search RecordType="A" AND Name="*"`                                             |
| **Reverse Lookup Poisoning**    | Add/modify PTR records for trusted hostnames                                                     | Restrict who can change PTR; audit changes                 | 5136, 257                                    | Splunk: `index=dnsevent EventCode=257 RecordType="PTR"`                                                              |
| **DNS Zone/Stub Delegation Persistence**| Create rogue delegated zones to maintain control after removal elsewhere                | Audit delegated/stub zones; restrict delegation            | 5136 (zone changes), 257                      | Splunk: `index=wineventlog (EventCode=5136) Object_Type="dnsZone"`                                                   |
| **Exfil via DNS (Data Theft)**  | Exfiltrate sensitive data via large, base64-encoded DNS queries                                | Alert on long queries, many failed lookups, odd TXT lookups| 257, DNS logs                                | Splunk: `index=dnsevent EventCode=257 | regex query=".{50,}" | stats count by src_ip`                                                           |
| **Poisoning DNS Cache**         | Insert malicious records into cache to redirect or intercept traffic                             | Enable DNSSEC; monitor for unexpected cache entries        | 257, cache events                             | Splunk: `index=dnsevent EventCode=257 | search "cache" AND (NewValue NOT IN expected)`                                  |
| **DNS Logging/Monitoring Gaps** | Disable/clear DNS logs to hide attack traces                                                     | Alert on log clear/stop, enforce log retention             | 1102, 517 (log clear)                         | Splunk: `index=wineventlog (EventCode=1102 OR EventCode=517) SourceName="DNS Server"`                                |
| **DNSAdmins DLL Injection**     | Members of DNSAdmins group can load DLLs on DNS server as SYSTEM (executes arbitrary code)       | Limit DNSAdmins group; monitor group membership, DLL loads | 4728/4732 (group mod), 4697 (DLL load)        | Splunk: `index=wineventlog (EventCode=4728 OR EventCode=4732) Group_Name="DNSAdmins"`                                |
| **Threat Actor: APT29 (Cozy Bear)** | APT29 known to use DNS for C2, persistence, and reconnaissance                              | Monitor for known TTPs, hunting on DNS tunnels and C2      | 257, 5136, threat intel feeds                 | Splunk: `index=dnsevent | search known APT29 C2 domains or techniques`                                    |

General AD Kerberos Attacks & Defenses:

| **Attack**                                    | **Description**                                                                              | **Mitigation**                                                                              | **Detection Rule (Event IDs)**                                            | **SIEM Detection Query (Splunk/KQL)**                                                                                                                                                                                                                                                                                                               |
|-----------------------------------------------|----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Kerberoasting                                | Requesting TGS for SPNs to extract/crack service account hashes                              | Strong/unique passwords for service accounts; monitor TGS requests                          | 4769                                                                   | **Splunk:** `index=wineventlog EventCode=4769 Service_Name="*" user!=null | stats count by Account_Name, Service_Name | where count>10`<br>**KQL:** `SecurityEvent | where EventID==4769 and ServiceName != "" | summarize count() by Account, ServiceName | where count_ > 10`   |
| Timeroasting                                 | Like Kerberoasting, but targets short ticket lifetimes                                       | Limit SPNs; monitor short-lifetime tickets                                                  | 4769                                                                   | **Splunk:** `index=wineventlog EventCode=4769 Ticket_Options="renewable" | stats min(Ticket_Options), max(Ticket_Options) by Account_Name`                                                                                                                              |
| AS-REP Roasting                              | Requests AS-REP for accounts without pre-auth, cracks hash offline                           | Require pre-auth for all users                                                              | 4768                                                                   | **Splunk:** `index=wineventlog EventCode=4768 "Pre-Authentication Type"="NONE" | stats count by Account_Name`<br>**KQL:** `SecurityEvent | where EventID==4768 and PreAuthType == "0"`                                                                                                           |
| AS-REQ Roasting                              | Initial AS-REQs for users without pre-authentication                                         | Require pre-auth for all users                                                              | 4768                                                                   | *(Same as AS-REP Roasting)*                                                                                                                                                                                                                                                                                 |
| Kerberos Diamond Ticket                      | Forged TGT with custom attributes/SIDs                                                       | Regularly reset KRBTGT; monitor for abnormal tickets                                        | 4768, 4769                                                            | **KQL:** `SecurityEvent | where EventID == 4768 and TicketOptions has "unusual" or TicketEncryptionType has "unusual"`                                                                                                   |
| Kerberos Golden Ticket                       | Forged TGT using KRBTGT hash, unlimited access                                               | Reset KRBTGT twice; monitor for long TGT lifetimes                                          | 4768, 4769                                                            | **Splunk:** `index=wineventlog EventCode=4768 OR EventCode=4769 Ticket_Encryption_Type="0x17" OR Ticket_Options="forwardable" | where Ticket_Lifetime>10h`                                                                                         |
| Kerberos Silver Ticket                       | Forged TGS using service account hash                                                        | Strong/rotated service account passwords; monitor TGS                                       | 4624, 4769                                                            | **Splunk:** `index=wineventlog EventCode=4624 LogonType=3 OR 9 | search NOT [search index=wineventlog EventCode=4768]`                                                              |
| Kerberos Bronze Ticket                       | Forged TGT for KDC S4U2Self, bypasses mitigations                                            | Patch and monitor KDC                                                                       | 4769                                                                   | **Splunk:** `index=wineventlog EventCode=4769 Ticket_Options="S4U2Self"`                                                                                                                   |
| Kerberos Sapphire Ticket                     | Advanced/rare, ticket forging with non-standard extensions                                   | Patch KDC; harden delegation                                                                | 4768, 4769                                                            | **KQL:** `SecurityEvent | where EventID == 4769 and TicketEncryptionType in ("unusual value")`                                                                                                                           |
| Kerberos Pass-The-Ticket (PTT)               | Injects Kerberos tickets into session memory                                                 | Credential Guard; restrict privileged account access                                        | 4624                                                                   | **Splunk:** `index=wineventlog EventCode=4624 LogonType=9 OR 3 | where LogonProcessName="Kerberos" and NOT src_ip in (allowed hosts)`                                            |
| Kerberos Unconstrained Delegation            | TGTs extracted from memory on unconstrained delegation hosts                                 | Remove unconstrained delegation; use constrained delegation                                 | 4769                                                                   | **Splunk:** `index=wineventlog EventCode=4769 Service_Name="krbtgt" | where ComputerName in [list of unconstrained hosts]`                                                                |
| Kerberos Constrained Delegation              | Abuses constrained delegation to impersonate users                                           | Limit accounts for constrained delegation; audit delegation                                 | 4769                                                                   | **Splunk:** `index=wineventlog EventCode=4769 | search ServiceName="krbtgt" | stats count by Account_Name, Service_Name`                                                                           |
| Kerberos Resource-Based Constrained Delegation (RBCD) | Attacker adds own computer to msDS-AllowedToActOnBehalfOfOtherIdentity               | Restrict who can write msDS-AllowedToActOnBehalfOfOtherIdentity; monitor changes            | 5136, 4662                                                            | **KQL:** `SecurityEvent | where EventID == 5136 and AttributeChanged == "msDS-AllowedToActOnBehalfOfOtherIdentity"`                                                                  |
| Kerberos Pass The Certificate                | Uses stolen certificate for PKINIT authentication                                            | Restrict certificate issuance; monitor certificate logons                                   | 4768, 4769                                                            | **KQL:** `SecurityEvent | where EventID==4768 and LogonProcessName == "Kerberos" and AuthenticationPackageName == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"`                      |
| Kerberos UnPAC The Hash                      | Exploits PAC validation for impersonation                                                    | Patch DCs (CVE-2021-42287/42278); harden KDC                                               | 4768                                                                   | **KQL:** `SecurityEvent | where EventID==4768 and (PACValidationStatus == "Failure" or PAC has unusual fields)`                                                                    |
| Kerberos OverPass The Hash (Pass-the-Key)    | Uses NTLM hash to request Kerberos TGT                                                       | Credential Guard; limit privileged account NTLM                                             | 4768                                                                   | **Splunk:** `index=wineventlog EventCode=4768 LogonProcessName="seclogon" | stats count by Account_Name, LogonProcessName`                                                                     |
| Kerberos Pre-Authentication Bruteforce       | Brute force Kerberos via pre-auth requests                                                   | Account lockout; monitor authentication failures                                            | 4771                                                                   | **Splunk:** `index=wineventlog EventCode=4771 | stats count by Account_Name, src_ip | where count > 20`<br>**KQL:** `SecurityEvent | where EventID == 4771 | summarize count() by Account, IpAddress | where count_ > 20`                 |

General AD NTLM Attacks & Defenses: 

| **Attack/Technique**         | **Description**                                                                              | **Mitigation**                                               | **Detection Rule/Event**                            | **SIEM Detection Query (Splunk/KQL)**                                                                                         |
|-----------------------------|----------------------------------------------------------------------------------------------|--------------------------------------------------------------|-----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| **NTLM Relay**               | Relays NTLM authentication to another service (e.g., SMB, LDAP) to escalate privileges      | Enforce SMB/LDAP signing; restrict NTLM; block SMB/LDAP relay| 4624 (Logon Type 3/9/10), 4776, anomalous connections| Splunk: `index=wineventlog (EventCode=4624 OR EventCode=4776) LogonType=3 OR 9 OR 10 | stats count by src_ip, Workstation_Name`          |
| **Pass-the-Hash (PtH)**      | Uses stolen NTLM hash to authenticate without knowing the plaintext password                | Disable NTLM; Credential Guard; LAPS; patch                  | 4624, 4776, 4625 (failed logon)                     | KQL: `SecurityEvent | where EventID==4624 and LogonType in (3,9,10) and Account != expected`                       |
| **NTLMv1 Downgrade**         | Downgrade negotiation to weak NTLMv1 and capture/crack challenge-response                   | Disable NTLMv1; enforce NTLMv2/modern auth                   | 4624 (NTLM logon with old protocol)                 | Splunk: `index=wineventlog EventCode=4624 AuthenticationPackageName="NTLM"`                                                   |
| **SMB Relay**                | Uses SMB protocol for relaying NTLM auth to access files or execute code                     | SMB signing required; disable SMBv1; restrict outbound SMB   | 5140, 4624 (SMB logon), unexpected shares           | Splunk: `index=wineventlog (EventCode=5140 OR EventCode=4624) Share_Name="ADMIN$" OR Share_Name="C$"`                         |
| **HTTP Relay**               | Relays NTLM credentials via HTTP-based services (e.g., WebDAV, IIS)                         | Restrict NTLM over HTTP; use Kerberos/modern auth            | Web logs, 4624, 4776                                | Splunk: `index=web sourcetype=web_proxy (status=401 OR status=407) | stats count by src_ip, user`                                                            |
| **LDAP Relay**               | Relay NTLM authentication to LDAP for privilege escalation or account changes                | Enforce LDAP signing; restrict anonymous binds; use LDAPS    | 4662, 4624, abnormal LDAP writes                    | KQL: `SecurityEvent | where EventID==4662 and ObjectType contains "LDAP"`                                         |
| **LLMNR/NBT-NS Poisoning**   | Responds to LLMNR/NBT-NS name requests to capture/relay NTLM credentials                   | Disable LLMNR/NBT-NS; restrict legacy name resolution        | LLMNR/NBT-NS network logs; unusual NetBIOS traffic  | Splunk: `index=network sourcetype=llmnr OR sourcetype=netbios | stats count by src_ip, query`                                                            |
| **NTLM Credential Capture (Responder/SMB Trap)** | Set up rogue SMB/HTTP/other services to capture NTLM hashes from unsuspecting users | Disable NTLM where possible; restrict outbound connections   | 4624 (unexpected SMB/HTTP logons), 5140             | Splunk: `index=wineventlog EventCode=4624 LogonType=3 OR 9 OR 10 | where Workstation_Name NOT IN (allowed list)`       |
| **NTLM Reflection**          | An attacker tricks a client into authenticating to itself, reflecting NTLM challenge        | SMB/LDAP signing; patch Windows                              | 4624, 4776, loopback auth events                    | KQL: `SecurityEvent | where EventID==4624 and IpAddress == WorkstationName`                                      |
| **NTLMv1/LM Hash Cracking**  | Offline cracking of weak NTLMv1 or LM hash responses                                       | Enforce NTLMv2 only; disallow LM/NTLMv1                      | N/A (capture on wire, check for LM/NTLMv1 usage)    | Splunk: `index=wineventlog AuthenticationPackageName="LM" OR AuthenticationPackageName="NTLM"`                                |
| **NTLM Authentication Over SMB Signing Disabled** | Relay/capture NTLM credentials over unsigned SMB sessions                          | Require SMB signing; monitor for unsigned SMB connections    | 4624, 5140, unsigned SMB logs                       | KQL: `SecurityEvent | where EventID==5140 and (SMBSigning == "No")`                                               |

General AD CS Attacks & Defenses:

| **ESC #** | **Technique/Attack**         | **Description**                                                                                                  | **Mitigation**                                                           | **Detection/Log Event**                                 | **SIEM Detection Query (Splunk/KQL Example)**                                                                            |
|-----------|-----------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| ESC1      | Misconfigured Template (ENROLLEE SUPPLIES SUBJECT)   | User supplies their own subject alternative names, allowing privilege escalation                                 | Restrict template permissions; set "ENROLLEE SUPPLIES SUBJECT" = No      | CA logs, event 4886/4887, template changes              | Splunk: `index=wineventlog EventCode=4887 OR EventCode=4886 | search Template_Name="*" Subject_Alt_Name="*"`                                     |
| ESC2      | Dangerous EKU                | Templates allow "Any Purpose" or authentication EKU, allowing dangerous certificate issuance                     | Limit EKUs on templates; audit existing templates                        | CA logs, event 4887, template changes                   | Splunk: `index=wineventlog EventCode=4887 EKU="Any Purpose"`                                                            |
| ESC3      | EDITF_ATTRIBUTESUBJECTALTNAME2| Anyone can request SANs (Subject Alternative Names) via legacy issuance flags                                    | Set EDITF_ATTRIBUTESUBJECTALTNAME2=0; audit registry                     | CA logs, registry audit (EDITF), 4887                   | KQL: `DeviceRegistryEvents | where RegistryKey has "EDITF_ATTRIBUTESUBJECTALTNAME2"`                              |
| ESC4      | Over-permissive Template     | Low-privilege users have enrollment rights on high-priv templates                                                | Restrict enrollment rights; limit template access                         | 4887, template permission changes                       | Splunk: `index=wineventlog EventCode=4887 Template_Permissions="*"`                                                     |
| ESC5      | ESC1+ESC2 Combination        | A dangerous template is both over-permissive and allows subject alternative name supply                          | Both ESC1 & ESC2 mitigations                                             | 4887, CA logs, template config                          | *(Combine ESC1 and ESC2 queries)*                                                                                        |
| ESC6      | Dangerous Publisher Rights   | Authenticated users can publish or modify templates, allowing for persistence                                    | Restrict template management to admins                                    | 4887, template creation/modification events             | Splunk: `index=wineventlog EventCode=4887 Operation="Modify Template"`                                                   |
| ESC7      | Weak Certificate Authority ACLs| Users/groups can manage CA, templates, or issuance policies                                                      | Harden CA object permissions; regular reviews                             | 4899, 4898, AD ACL logs                                 | KQL: `SecurityEvent | where EventID==4899 or EventID==4898`                                                      |
| ESC8      | Dangerous Enrollment Agents  | Users/groups have "Certificate Request Agent" rights to enroll on behalf of others                               | Restrict enrollment agent permissions                                     | 4887, enrollment agent logs                             | Splunk: `index=wineventlog EventCode=4887 EnrollmentAgent="*"`                                                          |
| ESC9      | NTLM Relay to AD CS          | AD CS allows NTLM authentication, making it vulnerable to relay attacks (PetitPotam, etc.)                       | Disable NTLM on CA; enforce Kerberos/authentication                       | 4624, 5140, 4886 (request w/ NTLM)                      | Splunk: `index=wineventlog EventCode=4624 LogonType=3 ServiceName="certsvc"`                                            |
| ESC10     | Vulnerable HTTP Endpoints    | Web Enrollment / Enrollment Web Services endpoints allow dangerous relay attacks                                 | Disable unused HTTP endpoints; restrict access                             | IIS logs, 4624, HTTP event logs                         | Splunk: `index=wineventlog sourcetype=iis | search cs-uri-stem="/certsrv"`                                                    |
| ESC11     | Compromise of Enterprise CA  | Direct compromise of the CA or its signing keys allows arbitrary certificate issuance                            | Secure CA host; use HSMs; restrict access                                 | 4886, 4899, 4898, CA host security logs                 | Splunk: `index=wineventlog (EventCode=4886 OR EventCode=4899 OR EventCode=4898)`                                       |
| ESC12     | Private Key Access on CA     | Access to CA's private key enables attackers to sign certificates at will                                        | Use HSMs; restrict private key access; audit key usage                    | HSM logs, 4889, 4890                                   | KQL: `SecurityEvent | where EventID==4889 or EventID==4890`                                                     |
| ESC13     | Subordinate CA Compromise    | Compromise of a subordinate CA in the chain allows for issuance abuse                                            | Secure subordinate CAs as tightly as roots                                | 4886, 4887, 4889 on subordinate CA                      | Splunk: `index=wineventlog EventCode=4889 ComputerName="SubordinateCA"`                                                 |
| ESC14     | Misused Application Policies | Templates or CAs that allow "Any Purpose" EKUs (bypass intended restrictions)                                    | Audit & restrict EKUs; enforce least privilege                             | 4887, template config logs                              | Splunk: `index=wineventlog EventCode=4887 EKU="Any Purpose"`                                                            |
| ESC15     | Vulnerable Certificate Mapping| Certificate mapping rules allow logon with arbitrary certificates                                                | Harden mapping rules; audit logon mappings                                 | 4624, 4776, mapping rule change logs                     | Splunk: `index=wineventlog EventCode=4624 LogonProcessName="certreq"`                                                    |
| ESC16     | Key Recovery Agent (KRA) Abuse| Malicious KRA can recover private keys from issued certificates                                                  | Limit KRA permissions; audit key recovery processes                        | 4887, KRA event logs                                    | Splunk: `index=wineventlog EventCode=4887 KeyRecoveryAgent="*"`                                                         |

General AD FS Attacks & Defenses:

| **Technique**                       | **Description**                                                                              | **Mitigation**                                                   | **Detection Rule/Event**                              | **SIEM Detection Query (Splunk/KQL)**                                                                                              |
|-------------------------------------|----------------------------------------------------------------------------------------------|------------------------------------------------------------------|-------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| **Golden SAML**                     | Forge SAML tokens using stolen AD FS Token-Signing certificate/private key; bypass MFA       | Protect AD FS signing keys (HSM, restrict access); monitor exports | 411 (AD FS Audit), 1202 (AD FS Token Signing), HSM logs| Splunk: `index=adfs EventCode=1202 | stats count by User, Issuer`                                                                |
| **Stolen Token-Signing Certificate**| Steal/export AD FS private key, allowing SAML forgery or replay                              | Restrict/monitor cert exports; use HSM for key storage           | 1200, 1202, certificate export events                 | KQL: `SecurityEvent | where EventID == 1200 or EventID == 1202`                                                       |
| **AD FS Configuration Abuse**       | Misconfigure claim rules, add malicious relying parties, or alter federation trust           | Restrict config access; audit changes; enable AD FS logging      | 100, 105 (config changes), 307 (trust added/removed)  | Splunk: `index=adfs (EventCode=100 OR EventCode=105 OR EventCode=307)`                                                           |
| **Relay Attacks (WS-Trust, SAML)**  | Relay SAML/WS-Trust auth messages to impersonate users (SSO abuse)                           | Restrict endpoints; patch; use signed/encrypted tokens           | 1200, 1202, abnormal client IPs in AD FS logs         | KQL: `SecurityEvent | where EventID==1200 or EventID==1202 and IpAddress != expected`                               |
| **Replay Attacks**                  | Reuse valid SAML/WS-Fed/WS-Trust tokens for unauthorized access                              | Short token lifetime; enforce unique audience and timestamps     | 411 (AD FS Audit), repeated token use                 | Splunk: `index=adfs EventCode=411 | stats count by TokenID, User | where count > 1`                                         |
| **Password Spray via AD FS**        | Brute force passwords via AD FS endpoints (forms, WS-Trust, etc.)                            | Enable lockout policies; monitor failed logins; MFA              | 1203, 1204, repeated login failures                   | Splunk: `index=adfs (EventCode=1203 OR EventCode=1204) | stats count by src_ip, User | where count > threshold`                                |
| **Abuse of Alternate Login (Extranet Smart Lockout)** | Abuse "smart lockout" bypass or alternate login features                              | Tighten extranet policies; monitor lockout/bypass events         | 1203, 1204, lockout logs                              | Splunk: `index=adfs EventCode=1204 | search "Smart Lockout"`                                                                     |
| **Relying Party Trust Manipulation**| Add malicious relying parties to issue or accept tokens on behalf of attackers               | Restrict relying party management to admins                      | 307, 105 (trust changes)                              | Splunk: `index=adfs (EventCode=307 OR EventCode=105) | search "Add Relying Party"`                                                                  |
| **Service Account Compromise**      | Compromise AD FS or WAP service accounts to gain privileged access                           | Use gMSA for AD FS; strong password policy; limit membership     | 4624, 4625, 4672 (privileged logons)                  | Splunk: `index=wineventlog (EventCode=4624 OR EventCode=4625 OR EventCode=4672) Account_Name="adfs"`                              |
| **WAP Abuse**                       | Exploit vulnerabilities or misconfigurations in Web Application Proxy fronting AD FS         | Patch WAP; restrict exposed endpoints; monitor access            | 1202, IIS logs, abnormal requests                     | KQL: `SecurityEvent | where EventID==1202 or sourcetype=="iis" and cs-uri-stem contains "/adfs/"`                   |
| **Certificate Trust Abuse**         | Add rogue/trusted root/intermediate CA to AD FS trust store, enabling malicious token signing| Restrict trust store management; monitor CA imports              | 1200, 1202, CA event logs                             | Splunk: `index=adfs (EventCode=1200 OR EventCode=1202) | search "CA" or "Trust"`                                                                      |
| **Misconfigured Claim Rules**       | Modify claim rules to allow privilege escalation or group assignment                         | Restrict claim editing; review claim rules                       | 105 (claim rule changes)                              | Splunk: `index=adfs EventCode=105 | search "Claim Rule"`                                                                         |

General AD Forest Attacks & Defenses:

| **Attack/Technique**                   | **Description**                                                                                  | **Mitigation**                                                      | **Detection Rule/Event**                           | **SIEM Detection Query (Splunk/KQL)**                                                                                              |
|----------------------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| **SIDHistory Abuse Across Forests**    | Attacker leverages SIDHistory attributes to escalate privileges across trusted forests            | Audit/remove unnecessary SIDHistory; restrict trust permissions      | 4738 (user changes), 4765 (SIDHistory mods)        | Splunk: `index=wineventlog (EventCode=4738 OR EventCode=4765) Attribute_Name="SIDHistory"`                                         |
| **MSSQL/Service Account Trust Abuse**  | Abusing service accounts with permissions in multiple forests for lateral movement                | Use separate service accounts per forest; minimize cross-forest perms| 4624, 4672 (cross-forest logons)                   | KQL: `SecurityEvent | where EventID==4624 and AccountDomain != expected and WorkstationName in trusted forests`                                            |
| **Kerberos TGT Delegation Across Forests** | Abuse of TGT delegation in trust relationships, leading to impersonation                     | Use selective/authentication trust; disable unconstrained delegation | 4769 (cross-forest TGS), 4624 (delegated logon)    | Splunk: `index=wineventlog EventCode=4769 | search TicketOptions="forwardable" | stats count by TargetDomainName, Account_Name`                                                |
| **Selective Authentication Bypass**    | Adding users/groups to "Allowed to Authenticate" to gain unintended access                       | Review "Allowed to Authenticate" groups; audit trust permissions     | 4742 (computer changes), 4728 (group changes)      | Splunk: `index=wineventlog (EventCode=4742 OR EventCode=4728) Group_Name="Allowed to Authenticate"`                                |
| **AdminSDHolder/ACL Abuse Across Trusts** | Modify AdminSDHolder/ACL in one forest to gain rights in another forest                       | Harden AdminSDHolder; regular cross-forest ACL reviews              | 4662 (ACL changes), 5136 (object mods)             | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Object_Name="AdminSDHolder"`                                         |
| **Kerberos Trust Ticket Forging**      | Forge cross-forest trust TGTs (with golden ticket/krbtgt hash of trusted forest)                 | Regularly reset krbtgt passwords in all forests                      | 4768, 4769, long ticket lifetimes                  | KQL: `SecurityEvent | where EventID==4768 or EventID==4769 and TicketOptions has "unusual"`                           |
| **NTLM Trust Abuse**                   | Relaying/capturing NTLM creds over trust boundaries                                              | Restrict NTLM; require SMB/LDAP signing; block legacy protocols      | 4624, 4776, cross-forest logons                    | Splunk: `index=wineventlog (EventCode=4624 OR EventCode=4776) LogonType=3 OR 9 | stats count by AccountDomain, src_ip`                      |
| **Trust Object Compromise**            | Direct modification or compromise of trust objects (msDS-TrustForestTrustInfo, etc.)             | Monitor trust object changes; restrict who can modify trusts         | 4743 (trust object mod), 5136 (object mod)         | Splunk: `index=wineventlog (EventCode=4743 OR EventCode=5136) Object_Type="trustedDomain"`                                         |
| **Transitive Trust Exploitation**      | Use of chained trusts to gain access deep into nested or transitive forest trusts                | Use only explicit/required trusts; review transitive trust configs   | 4769 (unexpected domains), 4624                    | KQL: `SecurityEvent | where EventID==4769 and TargetDomainName != expected`                                            |
| **Trust Path Enumeration & Mapping**   | Attackers map trust topology to identify pivot points for escalation                             | Limit trust enumeration; monitor LDAP/Netlogon trust queries         | LDAP/Netlogon logs, 4662 (trust object reads)       | Splunk: `index=wineventlog EventCode=4662 Object_Type="trustedDomain"`                                                              |

General Network Protocols in AD Attacks & Defenses:

| **Protocol** | **Common Attacks**                                   | **Mitigation**                                                    | **Detection Rule/Event**                                      | **SIEM Detection Query (Splunk/KQL)**                                                                                                                                      |
|--------------|------------------------------------------------------|-------------------------------------------------------------------|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **ARP**      | ARP spoofing/poisoning (MITM)                        | Static ARP entries; Dynamic ARP Inspection (DAI); VLAN isolation  | Unusual ARP changes or traffic                                 | Splunk: `index=network sourcetype=arp | stats count by src_mac, src_ip | where count > threshold`                                                                        |
| **DHCP**     | Rogue DHCP server; DHCP starvation; poisoning         | DHCP snooping; trusted DHCP; VLAN separation                      | Multiple DHCP offers from untrusted sources                    | Splunk: `index=network sourcetype=dhcp MessageType=Offer | stats count by src_ip`                                                                          |
| **DHCPv6**   | Rogue DHCPv6 server; address assignment abuse         | DHCPv6 guard; secure router configuration                         | Multiple DHCPv6 offers/advertisements from non-authorized      | Splunk: `index=network sourcetype=dhcpv6 | stats count by src_ip`                                                                       |
| **SMB**      | SMB relay; credential theft; RCE (EternalBlue, etc.) | SMB signing; disable SMBv1; restrict share permissions            | 4624 (SMB logons), 5140 (share access), anomalous connections  | KQL: `SecurityEvent | where EventID==5140 or EventID==4624 | summarize count() by IpAddress, Account | where count_ > threshold`                              |
| **LDAP**     | Enumeration; credential spray; injection; relay       | LDAPS (SSL/TLS); restrict anonymous binds; monitor queries        | 4662, 5136 (modifications); excessive queries                  | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=5136) Object_Type="user"`                                                  |
| **DNS**      | DNS poisoning/spoofing; exfiltration via DNS tunnels | DNSSEC; split DNS; restrict external DNS; monitor query patterns  | Unusual queries, long/rare domains, high volume                | Splunk: `index=dns sourcetype=dns | regex query=".*\\..*\\..*\\..*" | stats count by src_ip, query`                                                                  |
| **LLMNR**    | LLMNR spoofing/poisoning (credential relay/MITM)      | Disable LLMNR/NBT-NS; use DNS only                                | LLMNR requests/replies outside norm                            | Splunk: `index=network sourcetype=llmnr | stats count by src_ip, query`                                                                |
| **NetBIOS**  | NetBIOS spoofing; relay; info leakage                 | Disable NetBIOS where possible; use modern protocols              | NetBIOS traffic from unusual hosts                             | Splunk: `index=network sourcetype=netbios | stats count by src_ip, name_query`                                                           |
| **WPAD**     | WPAD spoofing; proxy auto-config hijack               | Disable WPAD; set static proxy configs; restrict wpad.* DNS       | DNS requests for wpad; proxy config file access                | Splunk: `index=dns query="wpad" | stats count by src_ip`                                                                        |
| **RPC**      | DCOM/RPC relay; lateral movement; RCE                 | Firewall restrictions; restrict allowed hosts/ports               | 5156 (allowed connections), high-volume RPC traffic            | KQL: `SecurityEvent | where EventID==5156 and Application == "svchost.exe" and RemotePort in (135, 445)`                |
| **SAMRPC**   | SAM enumeration; SID brute-forcing                    | Restrict anonymous SAMRPC; apply group policy restrictions        | SAM access attempts from non-admin hosts                       | Splunk: `index=wineventlog Message="SAM" | stats count by src_ip, user`                                                                 |
| **WinRM**    | Remote code execution; credential relay               | Restrict WinRM access; use HTTPS; strong auth; audit connections  | 4624, 4688 (remote process creation)                           | KQL: `SecurityEvent | where EventID==4624 and LogonProcessName=="Advapi"`                                              |
| **RDP**      | Brute-force; session hijack; RDP relay                | NLA; strong passwords; MFA; restrict access; session monitoring   | 4625 (failed logon), 4624 (success), new/unusual sessions      | Splunk: `index=wineventlog (EventCode=4624 OR EventCode=4625) LogonType=10 | stats count by src_ip`                                  |
| **IIS**      | Webshells; privilege escalation; path traversal       | Patch IIS; restrict file uploads; use Web Application Firewall    | 4624, 4688 (w3wp.exe spawns unusual processes)                 | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*w3wp.exe*" | stats count by Parent_Process_Name`                      |
| **WSUS**     | Rogue update servers; update poisoning                | TLS for WSUS; limit update approval; GPO restrictions             | Unexpected WSUS connections; changes in update source          | Splunk: `index=wineventlog sourcetype=wsus | stats count by Computer, UpdateServer`                                                      |
| **MSSQL**    | Brute-force; xp_cmdshell abuse; lateral movement; injection | Restrict access; disable xp_cmdshell; patch; monitor failed logins| 18456 (failed logon); 4688 (cmd.exe from sqlservr.exe)         | Splunk: `index=wineventlog EventCode=18456 | stats count by src_ip`<br>Splunk: `index=wineventlog EventCode=4688 Parent_Process_Name="sqlservr.exe" New_Process_Name="cmd.exe"` |
| **DFS**      | Enumeration; data exfiltration via shares; relay      | Limit DFS share permissions; audit access; SMB hardening          | 5140 (share access); large/odd DFS copy events                 | Splunk: `index=wineventlog EventCode=5140 Share_Name="*DFS*" | stats count by src_ip, Object_Name`                                                           |
                                                    |

General AD Coercion Attacks & Defenses:

| **Technique/Service**    | **Description**                                                                                                   | **Mitigation**                                                                                   | **Detection Rule/Event**                       | **SIEM Detection Query (Splunk/KQL)**                                                                                                                                  |
|--------------------------|-------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Print Spooler (PrintNightmare / MS-RPRN)** | Coerces system to authenticate via printer-related remote calls (RpcAddPrinterDriver, etc.)           | Disable Print Spooler on DCs/servers; patch; limit access                                       | 316, 5145, abnormal outbound connections       | Splunk: `index=wineventlog EventCode=316 OR EventCode=5145 | search "AddPrinterDriver"`                                                                  |
| **MS-RPRN (Remote Printing Protocol)**        | Forces authentication by invoking remote printer API calls                                            | Same as above                                                                                    | 5145 (SMB), 4624 (logon), new outbound SMB     | Splunk: `index=wineventlog EventCode=5145 Share_Name="IPC$" | stats count by src_ip, Account_Name`                                                        |
| **MS-RSAT (Remote Server Administration Tools)** | RPC calls (e.g., via ServerManager) to trigger NTLM authentication                                 | Restrict RPC; firewall; patch                                                                   | 5156, 4624, anomalous admin connections        | KQL: `SecurityEvent | where EventID==5156 and RemotePort==445 and Application == "svchost.exe"`                        |
| **MS-DFSNM (Distributed File System Namespace Management)** | Coerce authentication using DFS namespace API                                                        | Harden DFS; limit admin to DFS; restrict shares                                                  | 5140 (DFS shares), 4624 (new logons)           | Splunk: `index=wineventlog EventCode=5140 Share_Name="*DFS*" | stats count by src_ip`                                                                     |
| **MS-FSRVP (File Server Remote VSS Protocol)**  | Coercion via Volume Shadow Copy Service operations, causing system to authenticate                   | Restrict FSRVP usage to necessary servers                                                        | 5140, 4672 (special privileges assigned)        | Splunk: `index=wineventlog EventCode=5140 | search "Shadow Copy"`                                                                       |
| **MS-EFSRPC (Encrypting File System Remote Protocol)** | Coerce authentication by invoking EFSRPC calls (EfsRpcOpenFileRaw, PetitPotam, etc.)               | Block EFSRPC over SMB; patch (PetitPotam CVE-2021-36942)                                        | 5145 (IPC$), anomalous SMB traffic             | Splunk: `index=wineventlog EventCode=5145 Share_Name="IPC$" | search "EfsRpcOpenFileRaw"`                                                                 |
| **MS-SSDP (Shadow Copies via DCOM/SSDP)**       | Using DCOM or Shadow Copy API to coerce authentication                                               | Restrict DCOM access; harden firewall rules                                                      | 5156, new outbound connections                  | KQL: `SecurityEvent | where EventID==5156 and Application == "dllhost.exe"`                                        |
| **MS-T120 (Remote Desktop Session Directory)**   | Abusing session directory APIs to force authentication                                               | Patch; restrict RDP Session Directory usage                                                      | 4624, 5140, unexpected session activity         | Splunk: `index=wineventlog EventCode=4624 LogonType=10 | stats count by src_ip`                                                                      |
| **MS-SAMR (Security Account Manager Remote Protocol)** | Forces authentication via user/group enumeration, SID lookups, etc.                                | Restrict SAMR to admins; block anonymous/broad queries                                           | 4662 (object access), 4798/4799 (SAM queries)   | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=4798 OR EventCode=4799) | stats count by src_ip, Account_Name`                  |
| **MS-LSAT (Local Security Authority Remote Protocol)** | Coerce via LSA policy lookups, causing authentication flows                                       | Limit LSARPC access; restrict to admins                                                          | 4662, 4624, unexpected LSA requests             | KQL: `SecurityEvent | where EventID==4662 and ObjectName contains "LSA"`                                            |
| **WebDAV (HTTP)**                              | Coerce authentication via malicious WebDAV shares (over HTTP/S)                                    | Disable WebDAV where not needed; restrict outbound web                                           | 4624, web proxy logs (401, 407)                 | Splunk: `index=web sourcetype=web_proxy (status=401 OR status=407) | stats count by src_ip, user`                           |
| **MS-SMB (Server Message Block)**               | Induce SMB authentication (UNC paths, shares, etc.)                                                | Restrict SMB outbound; enforce SMB signing; firewall                                             | 4624, 5140, unusual outbound SMB connections    | KQL: `SecurityEvent | where EventID==4624 and LogonType==3 and WorkstationName != "<expected>"`                      |
| **MS-RPC**                                     | Coerce authentication by initiating RPC connections                                                | Restrict RPC; monitor for anomalous connections                                                  | 5156, 4624                                     | KQL: `SecurityEvent | where EventID==5156 and RemotePort in (135,445,593)`                                         |

General Credentials Attacks & Defenses:

| **Attack/Source**                    | **Description**                                                                         | **Mitigation**                                                    | **Detection Rule/Event**                   | **SIEM Detection Query (Splunk/KQL)**                                                                                                                          |
|--------------------------------------|-----------------------------------------------------------------------------------------|-------------------------------------------------------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **LSASS**                            | Dumping cleartext passwords, hashes, and Kerberos tickets from LSASS process memory     | Credential Guard; restrict admin rights; EDR/Sysmon monitoring; patch | Sysmon 10, 4688 (suspicious process), 4656 | Splunk: `index=sysmon EventCode=10 TargetImage="*lsass.exe*" | stats count by ProcessId, User`<br>KQL: `Sysmon | where EventID==10 and TargetImage endswith "lsass.exe"`                     |
| **SAM**                              | Extracting local user password hashes from the SAM registry hive                        | Restrict SAM access; LSASS protection; patch                      | 4662, 4656, 4663 (object access)           | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=4663) Object_Name="*\\SAM"`                                       |
| **NTDS.dit**                         | Dumping Active Directory database (NTDS.dit) to extract domain hashes                   | Restrict DC access; enable auditing; Secure Boot; EDR             | 4662 (object access), 4688 (ntdsutil, ntds.dit) | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*ntdsutil.exe*" OR New_Process_Name="*esentutl.exe*"`       |
| **Windows Credential Manager**        | Extracting saved credentials via tools or scripts                                       | Restrict logon rights; clear credentials on logout; EDR           | 4624, unusual access to vaultcli.dll        | Splunk: `index=wineventlog (EventCode=4624) Message="vaultcli"`                                                          |
| **Registry Hive Credentials**         | Dumping SYSTEM, SAM, SECURITY hives to retrieve hashes and secrets                      | Restrict registry access; monitor hive exports; EDR               | 4656, 4663 (access/export of registry hives)| Splunk: `index=wineventlog EventCode=4663 Object_Name="*\\SYSTEM" OR Object_Name="*\\SECURITY" OR Object_Name="*\\SAM"`  |
| **DPAPI**                            | Dumping user secrets protected by DPAPI (browser creds, WiFi, etc.)                     | Protect master keys; restrict admin; EDR/Sysmon                   | 4663, 4688 (dpapi-related process)          | Splunk: `index=wineventlog EventCode=4663 Object_Name="*\\Microsoft\\Protect"`                                            |
| **LSA Secrets**                       | Dumping LSA secrets (service, scheduled task passwords, trust keys)                     | Enable LSASS protection; restrict registry/LSA access; EDR        | 4662, 4656, 4688 (reg.exe/lsadump tools)    | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=4688) CommandLine="*lsadump*"`                                   |
| **Directory Services Restore Mode (DSRM)** | Extracting or abusing DSRM account on Domain Controllers                         | Disable/unset DSRM password; monitor DSRM logins; restrict DC logon | 4624 (LogonType=3/10 with DSRM account)     | Splunk: `index=wineventlog EventCode=4624 Account_Name="Administrator" | where ComputerName="DC" LogonType=3 OR 10`                                        |
| **RunAs Saved Credentials**           | Dumping credentials saved for RunAs sessions                                            | Avoid saving credentials; clear stored credentials                | 4624 (with explicit credentials)             | Splunk: `index=wineventlog EventCode=4624 LogonProcessName="Advapi" LogonType=9`                                          |
| **Azure AD Connect**                  | Extracting credentials or cleartext passwords/sync keys from AD Connect installation    | Secure and audit AD Connect; restrict access; patch               | 4688 (powershell, mimikatz, ntdsutil.exe)    | Splunk: `index=wineventlog EventCode=4688 Parent_Process_Name="*AzureADConnect*" | stats count by Account_Name`                                                      |
| **PowerShell History Credentials**    | Extracting passwords from PowerShell command history files                              | Clear history; educate users; use secure credentials management   | File access logs for `ConsoleHost_history.txt` | Splunk: `index=oswinlog path="*ConsoleHost_history.txt"`                                                                 |
| **Clipboard Credentials**             | Scraping credentials copied to clipboard by users or malware                            | User education; EDR with clipboard monitoring                    | EDR logs, clipboard API use, suspicious processes | Splunk: `index=sysmon EventCode=1 CommandLine="*clip*" OR CommandLine="*Get-Clipboard*"`                                |
| **Credentials** (Generic)             | Any attempt to collect/dump credentials using tools or system calls                     | EDR; credential guard; restrict admin; robust logging            | 4688 (known tools), 4104 (PowerShell script) | Splunk: `index=wineventlog (EventCode=4688 OR EventCode=4104) CommandLine="*mimikatz*"`                                   |

General Application Control Attacks & Defenses:

| **Attack/Technique**                | **Description**                                                                                 | **Mitigation**                                              | **Detection Rule/Event**                   | **SIEM Detection Query (Splunk/KQL)**                                                                               |
|-------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **Living-off-the-Land Binaries (LOLBins)** | Abuse signed Windows binaries (e.g., regsvr32, mshta, rundll32, powershell) to bypass controls | Block/limit LOLBins in AppLocker/WDAC; EDR alerting         | 4688 (proc exec), 8003 (AppLocker bypass)  | Splunk: `index=wineventlog EventCode=4688 (New_Process_Name="*regsvr32.exe*" OR New_Process_Name="*rundll32.exe*" OR New_Process_Name="*mshta.exe*")` |
| **Signed Binary Proxy Execution**   | Use Microsoft-signed binaries to proxy or launch malicious payloads                            | Restrict allowed binaries; monitor unusual parent/child procs| 4688, 8003                                 | Splunk: `index=wineventlog EventCode=4688 (Parent_Process_Name!="explorer.exe" AND (New_Process_Name="*cscript.exe*" OR New_Process_Name="*wscript.exe*"))` |
| **DLL Search Order Hijacking**      | Place malicious DLLs in locations searched before the legitimate ones                          | Block untrusted DLLs; audit load locations; code signing     | 4688, Sysmon 7 (DLL load)                  | Splunk: `index=sysmon EventCode=7 ImageLoaded="*\\Temp\\*.dll"`                                                     |
| **Untrusted Script Execution**      | Running scripts (PowerShell, HTA, JS, VBS) from untrusted locations                            | Restrict script execution; use Constrained Language Mode     | 4104 (PS script), 4688, AppLocker logs     | Splunk: `index=wineventlog (EventCode=4104 OR EventCode=4688) CommandLine="*ps1" OR CommandLine="*hta"`             |
| **AppLocker Bypass via Whitelisted Folders** | Dropping executables in locations allowed by default (e.g., C:\Windows\Tasks)          | Remove/limit whitelisted paths; enforce allowlist            | 4688, 8003 (AppLocker)                     | Splunk: `index=wineventlog EventCode=4688 Parent_Process_Name="*\\Tasks\\*"`                                        |
| **Office Macro Execution**          | Malicious macros to execute code or payloads                                                   | Disable macros; block unsigned macros; use Defender ASR      | 3008 (Office), 4104 (PS), 4688             | Splunk: `index=wineventlog (EventCode=4104 OR EventCode=4688) Parent_Process_Name="*winword.exe*" OR Parent_Process_Name="*excel.exe*"`                  |
| **AppLocker Policy Tampering**      | Modifying or disabling AppLocker/App Control policy                                            | Restrict policy access; monitor GPO/AppLocker changes        | 4719 (Audit Policy), 4688, 8004 (AppLocker) | Splunk: `index=wineventlog (EventCode=4719 OR EventCode=8004) Message="AppLocker"`                                  |
| **Memory Injection (Reflective/Process Hollowing)** | Injecting code into trusted processes to bypass control                                 | EDR; block unsigned memory modifications                     | Sysmon 7, 10, 11                           | Splunk: `index=sysmon (EventCode=7 OR EventCode=10 OR EventCode=11) ImageLoaded="*"`                                |
| **Unconstrained File Unblocking**   | Attackers remove the Zone.Identifier "mark-of-the-web" from files to allow execution           | Enable "Do not preserve zone information"; audit unblocking  | 4663 (file access), file creation logs      | Splunk: `index=wineventlog EventCode=4663 Object_Name="*:Zone.Identifier"`                                          |
| **WDAC Bypass via Policy Downgrade**| Rollback or tamper with WDAC policies to allow unsigned/malicious code                        | Secure WDAC policy storage; enforce code integrity           | 3099, 3089 (WDAC events), 4688              | KQL: `DeviceEvents | where ActionType contains "wdac" and AdditionalFields contains "rollback"`                    |
| **InstallUtil/Regasm Bypass**       | Use .NET utilities (installutil.exe, regasm.exe) to execute arbitrary code                     | Block/monitor use of .NET utilities; limit dev tools         | 4688                                        | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*installutil.exe*" OR New_Process_Name="*regasm.exe*"`  |
| **Script Interpreter Proxying**     | Chaining interpreters (e.g., mshta.exe > powershell.exe) to evade controls                     | Restrict/monitor chained process creation                    | 4688, 4104                                  | Splunk: `index=wineventlog EventCode=4688 Parent_Process_Name="*mshta.exe*" AND New_Process_Name="*powershell.exe*"`|

General AD Lateral Movements Attacks & Defenses:

| **Technique**                      | **Description**                                                                                     | **Mitigation**                                                             | **Detection Rule/Event**                     | **SIEM Detection Query (Splunk/KQL)**                                                                                                       |
|------------------------------------|-----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| **Pass-the-Hash (PtH)**            | Use stolen NTLM hashes to authenticate as user on remote systems                                    | Disable NTLM; use LAPS; Credential Guard; patch                              | 4624 (Logon Type 3/9/10), abnormal logon     | Splunk: `index=wineventlog EventCode=4624 LogonType=3 OR 9 OR 10 | stats count by Account_Name, Workstation_Name`                    |
| **Pass-the-Ticket (PtT)**          | Use stolen Kerberos tickets to authenticate as user                                                 | Credential Guard; patch; monitor ticket reuse                                | 4624 (Logon Type 3), 4768/4769               | KQL: `SecurityEvent | where EventID==4624 and LogonType==3 and AccountName in (privileged users)`                               |
| **OverPass-the-Hash (Pass-the-Key)**| Use NTLM hash to request Kerberos TGT and move laterally                                           | Credential Guard; patch; monitor abnormal ticket requests                     | 4768                                         | Splunk: `index=wineventlog EventCode=4768 LogonProcessName="seclogon"`                                 |
| **Remote Desktop Protocol (RDP)**  | Login to remote systems via RDP (interactive or via stolen creds)                                   | Restrict RDP access; MFA; strong passwords; NLA                               | 4624 (Logon Type 10), 4625 (failed RDP)      | Splunk: `index=wineventlog (EventCode=4624 OR EventCode=4625) LogonType=10 | stats count by src_ip`                                            |
| **Windows Admin Shares (C$, ADMIN$)** | Lateral move via default admin shares (SMB) to drop or execute payloads                           | Restrict admin shares; firewall; monitor share access                         | 5140 (share access), 5145                    | Splunk: `index=wineventlog (EventCode=5140 OR EventCode=5145) Share_Name="ADMIN$" OR Share_Name="C$"`                   |
| **PsExec / PAExec / SMBexec**      | Execute commands on remote systems via SMB and service creation                                     | Restrict remote service creation; monitor for PsExec binaries                 | 7045 (new service install), 4688 (proc exec) | Splunk: `index=wineventlog EventCode=7045 | search Service_File_Name="*psexec*" OR "paexec"`                                 |
| **Windows Remote Management (WinRM)** | Remotely execute PowerShell or scripts via WinRM                                                  | Restrict/monitor WinRM; allow HTTPS only; limit admin rights                  | 4624, 4688                                   | KQL: `SecurityEvent | where EventID==4624 and LogonProcessName=="Advapi"`                                  |
| **WMI (Windows Management Instrumentation)** | Execute code remotely using WMI (wmic.exe, PowerShell)                                       | Limit WMI remote use; monitor WMI processes                                   | 4688 (wmic.exe), 5861 (WMI-Activity log)     | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*wmic.exe*"`                                 |
| **Remote Services (sc.exe, service creation)** | Create and start services on remote systems to run attacker code                               | Restrict service creation rights; monitor remote service creation              | 7045, 4697                                   | Splunk: `index=wineventlog EventCode=7045 | stats count by Service_File_Name, Account_Name`                                   |
| **Scheduled Tasks (schtasks.exe)** | Create malicious scheduled tasks on remote hosts                                                   | Restrict schtasks usage; monitor remote task creation                          | 4698 (task creation), 4688 (schtasks.exe)    | Splunk: `index=wineventlog (EventCode=4688 OR EventCode=4698) New_Process_Name="*schtasks.exe*"`                        |
| **Remote PowerShell (Enter-PSSession/Invoke-Command)** | Use PowerShell remoting to execute code on remote machines                                | Restrict PowerShell Remoting; enable logging; use JEA/Constrained Language Mode| 4104, 4688                                   | KQL: `SecurityEvent | where EventID==4104 and ScriptBlockText contains "Enter-PSSession" or "Invoke-Command"`                    |
| **DCOM (Distributed COM)**         | Execute code via DCOM objects on remote hosts                                                      | Restrict DCOM; monitor unusual DCOM activity                                   | 10016 (DCOM), 4688 (proc exec)               | Splunk: `index=wineventlog EventCode=10016 | stats count by User, Computer`                                                    |
| **RDP Clipboard/Drive Mapping**    | Move files or credentials via mapped drives or clipboard in RDP sessions                           | Restrict RDP device redirection; disable clipboard/drive mapping               | 4624 (RDP), 5140 (share access)              | Splunk: `index=wineventlog EventCode=5140 Share_Name="*TSCLIENT*"`                                     |
| **Token Impersonation/Delegation** | Impersonate tokens of privileged users for remote access                                           | Limit privileged tokens; use credential guard                                  | 4624 (delegated logon), 4672 (special privs) | Splunk: `index=wineventlog (EventCode=4624 OR EventCode=4672) LogonType=9 OR 11`                                     |
| **Kerberos Delegation (Unconstrained/Constrained/RBCD)** | Abusing Kerberos delegation to move laterally using impersonated tickets                  | Remove unconstrained delegation; restrict constrained delegation                | 4769, 4672                                   | KQL: `SecurityEvent | where EventID==4769 and ServiceName contains "krbtgt"`                                    |
| **Shadow Copy Abuse**              | Abuse VSS to access/copy protected files for lateral move or data theft                            | Restrict shadow copy usage; monitor VSS activities                              | 5140, 4688                                   | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*vssadmin.exe*"`                                       |

General AD Privilege Escalation Attacks & Defenses:

| **Technique**                   | **Description**                                                                 | **Mitigation**                                                | **Detection Rule/Event**                          | **SIEM Detection Query (Splunk/KQL)**                                                                                                   |
|---------------------------------|---------------------------------------------------------------------------------|---------------------------------------------------------------|---------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| **Credential Dumping**          | Dumping credentials from LSASS, SAM, NTDS, etc., to reuse/abuse                 | EDR; Credential Guard; patching; limit local admin rights      | 4688, 10 (Sysmon), 4662/4663                      | Splunk: `index=sysmon EventCode=10 TargetImage="*lsass.exe*"`<br>Splunk: `index=wineventlog EventCode=4688 CommandLine="*mimikatz*"`   |
| **Token Impersonation/Manipulation** | Stealing/impersonating tokens of higher-privileged users                    | Restrict token privileges; Credential Guard                    | 4624 (Logon Type 9/11), 4672                      | Splunk: `index=wineventlog EventCode=4624 LogonType=9 OR LogonType=11`                                                                 |
| **Bypassing UAC (User Account Control)** | Run as admin by bypassing UAC via hijacks or auto-elevated binaries         | Enable UAC; only admins can approve elevation; patch           | 4688 (auto-elevated proc), 7045                   | Splunk: `index=wineventlog EventCode=4688 (New_Process_Name="*fodhelper.exe*" OR New_Process_Name="*eventvwr.exe*")`                   |
| **Service Misconfiguration**    | Abusing weak service permissions (modifying binaries, unquoted paths, etc.)     | Use least privilege for service accounts; audit service perms  | 7045 (service install), 4697 (service config)     | Splunk: `index=wineventlog EventCode=7045 | stats count by Service_File_Name, Account_Name`                                                  |
| **DLL Hijacking/Planting**      | Placing malicious DLL in search path for a service/process                      | Audit service DLL paths; code signing; restrict folders        | Sysmon 7 (DLL load), 4688                         | Splunk: `index=sysmon EventCode=7 ImageLoaded="*\\Temp\\*.dll"`                                                                        |
| **Scheduled Task/Job Abuse**    | Creating or modifying scheduled tasks to run attacker code with higher rights   | Limit who can create/modify tasks; monitor task creation       | 4698 (task created), 4688 (schtasks.exe)          | Splunk: `index=wineventlog EventCode=4698`                                                                                             |
| **Startup/Logon Script Hijack** | Planting or modifying scripts run at logon/startup                              | Limit write access to logon scripts; monitor script changes    | 4688, 5145, 5136                                  | Splunk: `index=wineventlog EventCode=4688 CommandLine="*logon*" OR CommandLine="*startup*"`                                            |
| **GPO Abuse**                   | Modifying Group Policy Objects for code execution or privilege escalation       | Limit GPO editing rights; monitor GPO changes                  | 5136 (GPO modified), 4688                         | Splunk: `index=wineventlog EventCode=5136 Object_Type="groupPolicyContainer"`                                                          |
| **AdminSDHolder/ACL Abuse**     | Changing ACLs or AdminSDHolder to grant self persistent admin rights            | Regular ACL review; restrict ACL write; monitor changes        | 4662, 5136                                        | Splunk: `index=wineventlog EventCode=4662 Object_Name="AdminSDHolder"`                                                                 |
| **SIDHistory Injection**        | Abusing SIDHistory to add high-privilege SIDs to accounts                       | Remove unneeded SIDHistory entries; monitor changes            | 4738, 4765                                        | Splunk: `index=wineventlog EventCode=4738 Attribute_Name="SIDHistory"`                                                                 |
| **Exploit Vulnerable Drivers**  | Load unsigned/signed vulnerable drivers to run code in kernel mode              | Device Guard; block unsigned drivers; patch vulnerable drivers | 7045 (service install), EDR alerts                 | Splunk: `index=wineventlog EventCode=7045 | search Service_File_Name="*.sys"`                                                               |
| **Kerberos Delegation Abuse**   | Exploit unconstrained/constrained delegation to escalate privileges             | Remove unconstrained delegation; review constrained delegation | 4769, 4672                                        | Splunk: `index=wineventlog EventCode=4769 Service_Name="krbtgt"`                                                                       |
| **DSRM Account Abuse**          | Log in using Directory Services Restore Mode (DSRM) admin credentials           | Set random DSRM password; monitor DSRM usage                   | 4624 (on DC, DSRM account)                        | Splunk: `index=wineventlog EventCode=4624 Account_Name="Administrator" | where ComputerName="DC"`                                   |
| **Named Pipe Impersonation**    | Trick privileged processes/services into connecting to attacker’s named pipe    | EDR; restrict privileged service communications                | Sysmon 17 (Pipe created), 4688                    | Splunk: `index=sysmon EventCode=17 PipeName="*"`                                                                                       |
| **Exploit OS Vulnerabilities**  | Exploit zero-days or unpatched flaws (e.g., PrintNightmare, Escalation of Privilege CVEs) | Timely patching; EDR; least privilege                       | Varies by vuln, 4688, EDR alerts                  | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*printspooler.exe*"`                                                      |
| **Shadow Credentials (msDS-KeyCredentialLink)** | Attacker adds keys to accounts to gain persistent admin access               | Limit attribute modification rights; monitor changes           | 4662 (attribute write), 5136                      | Splunk: `index=wineventlog EventCode=4662 Attribute_Name="msDS-KeyCredentialLink"`                                                     |

General AD Attacks & Defenses:

| **Attack**                              | **Description**                                                      | **Mitigation**                                                | **Detection Rule (Event IDs)**             | **SIEM Detection Query (Splunk/KQL)**                                                                                                                                                           |
|-----------------------------------------|----------------------------------------------------------------------|---------------------------------------------------------------|--------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Pass-the-Hash                           | Use NTLM hashes for authentication                                  | Disable NTLM; patch; LAPS; Credential Guard                   | 4624 (Logon Types 3, 9, 10)                | **Splunk:** `index=wineventlog EventCode=4624 LogonType=3 OR 9 OR 10 | stats count by Account_Name, Workstation_Name`                                                                      |
| Pass-the-Ticket                         | Use stolen Kerberos tickets to authenticate                          | Clear cached tickets; Credential Guard                        | 4624, 4768                                 | **KQL:** `SecurityEvent | where EventID==4624 and (LogonProcessName == "Kerberos") and AccountName in (list of privileged accounts)`             |
| DCShadow                                | Malicious DC registers and pushes AD changes                         | Limit admin rights; monitor DC registration                   | 4662, 4929, 5136                           | **Splunk:** `index=wineventlog (EventCode=4662 OR EventCode=4929 OR EventCode=5136) | search "DS-Replica-Add"`                                                      |
| DCSync                                  | Use replication rights to pull password data                         | Restrict replication; monitor Get-Changes                     | 4662                                       | **Splunk:** `index=wineventlog EventCode=4662 Object_Type="DS-Replication-Get-Changes" | stats count by Account_Name`                                                  |
| NTLM Relay                              | Relaying NTLM authentication                                        | SMB/LDAP signing; block SMB/LDAP; restrict relay              | 4624, 4776                                 | **KQL:** `SecurityEvent | where EventID==4624 and LogonType in (3,9,10) and AccountDomain != "expected"`                                       |
| LDAP Enumeration                        | Enumerate users, groups, ACLs via LDAP                              | Limit anonymous LDAP binds; harden ACLs                       | 4662, 5136                                 | **Splunk:** `index=wineventlog (EventCode=4662 OR EventCode=5136) | search Object_Type="user" | stats count by Account_Name, src_ip`                                           |
| LAPS Password Theft                     | Extracts local admin passwords from LAPS in AD                       | Limit access; monitor attribute reads                         | 4662                                       | **KQL:** `SecurityEvent | where EventID==4662 and AttributeChanged=="ms-Mcs-AdmPwd"`                                                           |
| ACL Abuse / Object Takeover              | Modifies AD ACLs for persistence/privilege                          | Audit/harden ACLs; regular reviews                            | 4662, 5136                                 | **Splunk:** `index=wineventlog (EventCode=4662 OR EventCode=5136) | search Object_Type="controlAccess"`                                            |
| AdminSDHolder Abuse                      | Persistence by modifying AdminSDHolder ACLs                          | Monitor changes; limit write access                           | 4662, 5136                                 | **KQL:** `SecurityEvent | where EventID==4662 and ObjectName contains "AdminSDHolder"`                                                         |
| Group Policy Modification                | Abuses GPOs for code execution/persistence                          | Restrict GPO edit rights; GPO change notifications            | 5136                                       | **Splunk:** `index=wineventlog EventCode=5136 Object_Type="groupPolicyContainer" | stats count by Account_Name`                                                  |
| Unconstrained Delegation Abuse           | Extract TGTs from unconstrained delegation hosts                     | Remove unconstrained delegation                               | 4769                                       | **KQL:** `SecurityEvent | where EventID==4769 and WorkstationName in (list of unconstrained hosts)`                                            |
| Kerberos Delegation Abuse                | Abuses (constrained) delegation to impersonate users                 | Audit/limit constrained delegation                            | 4769                                       | **Splunk:** `index=wineventlog EventCode=4769 | stats count by Account_Name, Service_Name`                                    |
| SIDHistory Injection                     | Uses SIDHistory to escalate privilege                                | Audit/remove unnecessary SIDHistory entries                    | 4738, 4765                                 | **KQL:** `SecurityEvent | where EventID in (4738,4765) and AttributeChanged == "SIDHistory"`                                                   |
| Abusing Disabled/Expired Accounts        | Reactivates old accounts to escalate                                 | Remove unused accounts; monitor reactivations                  | 4722, 4725                                 | **Splunk:** `index=wineventlog (EventCode=4722 OR EventCode=4725) | stats count by Target_Account`                                                 |
| Credential Dumping (LSASS)               | Dump credentials from LSASS process                                  | Credential Guard; limit admin; patch systems                   | Sysmon 10                                  | **KQL:** `Sysmon | where EventID==10 and TargetImage endswith "lsass.exe"`                                                                  |
| Brute Force / Spray Attacks              | Many repeated login attempts                                         | Account lockout; MFA; monitor failures                         | 4625                                       | **Splunk:** `index=wineventlog EventCode=4625 | stats count by src_ip, Account_Name | where count > 20`                                                             |
| Enumeration via SMB                      | Enumerates shares, users, sessions                                   | Restrict SMB; firewall; disable SMBv1                          | 5140                                       | **KQL:** `SecurityEvent | where EventID==5140 | summarize count() by IpAddress | where count_ > 10`                                                             |
| PrintNightmare & Printer Spooler Abuse   | RCE or escalation via print spooler                                  | Disable Spooler on DCs/critical; patch systems                 | 316                                        | **Splunk:** `index=wineventlog EventCode=316 | stats count by ComputerName`                                                   |
| Service Installation/Abuse               | Malicious service installation for persistence/escalation            | Restrict install permissions; monitor service creation         | 7045                                       | **KQL:** `SecurityEvent | where EventID==7045 | summarize count() by Account, ServiceName`                                     |
| Shadow Credentials (msDS-KeyCredentialLink abuse) | Adds keys to persist via Kerberos                              | Limit msDS-KeyCredentialLink writes; monitor changes           | 4662                                       | **KQL:** `SecurityEvent | where EventID==4662 and AttributeChanged=="msDS-KeyCredentialLink"`                                                  |

General AD Evasion Techniques Attacks & Detections:

| **Attack/Vector**               | **Description**                                 | **Mitigation**                               | **Detection Event/Rule**             | **SIEM Detection Query (Splunk/KQL)**                         |
|---------------------------------|-------------------------------------------------|----------------------------------------------|--------------------------------------|---------------------------------------------------------------|
| Disable AV/EDR/SIEM Agent       | Stop/uninstall or tamper with endpoint security  | Restrict uninstall; monitor agent status     | 7036 (service stop), EDR alerts      | Splunk: `index=wineventlog EventCode=7036 Message="stopped"`  |
| Logging Policy Manipulation     | Change or weaken audit policies                 | GPO enforcement; monitor 4719                | 4719 (audit policy change)           | Splunk: `index=wineventlog EventCode=4719`                    |
| PowerShell/Script Obfuscation   | Hide malicious code from detection              | Script block logging; monitor encoding       | 4104 (PS), 4688                      | Splunk: `index=wineventlog EventCode=4104 ScriptBlockText="*FromBase64String*"` |
| WMI Process/Script Tampering    | Obfuscate or hide via WMI scripts/processes     | Monitor WMI events and script logs           | 5861 (WMI), 4688                      | Splunk: `index=wineventlog EventCode=5861`                    |


General AD Enumeration & Detections:

| **Technique/Tool**            | **Description**                                                                 | **Mitigation**                                         | **Detection Event/Rule**                        | **SIEM Detection Query (Splunk/KQL)**                                                                |
|-------------------------------|---------------------------------------------------------------------------------|--------------------------------------------------------|-------------------------------------------------|------------------------------------------------------------------------------------------------------|
| **Net Commands (net user / net group)** | Enumerate users, groups, sessions, shares, DCs via built-in Windows tools             | Restrict command-line access; monitor command usage    | 4688 (proc creation), 4104 (PS)                  | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*net.exe*"`                             |
| **LDAP Enumeration (ldapsearch, PowerView)** | Enumerate users, groups, ACLs, GPOs, trusts via LDAP queries                       | Harden LDAP; restrict anonymous binds                  | 4662 (object access), 1644 (LDAP query)           | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=1644) Object_Type="user"`                   |
| **BloodHound**                 | Automated AD graph analysis: users, groups, ACLs, sessions, admins                  | Detect large volumes of LDAP/SAMR/Netlogon queries     | 4662, 1644, high-frequency LDAP/Netlogon queries  | Splunk: `index=wineventlog EventCode=1644 | stats count by src_ip | where count > threshold`                                         |
| **PowerView/SharpHound**       | PowerShell/.NET tools for AD recon: shares, trusts, local admins, ACLs, sessions   | Block known binaries/scripts; log PowerShell events    | 4104 (PS), 4688 (proc creation)                   | Splunk: `index=wineventlog EventCode=4104 ScriptBlockText="*PowerView*"`                            |
| **NLTEST**                     | Enumerate domain trusts, DCs, forest structure                                      | Limit use to admins; monitor execution                 | 4688 (nltest.exe)                                 | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*nltest.exe*"`                          |
| **DSQuery/DSGet**              | Query AD objects for discovery (users, groups, OUs, computers, GPOs)                | Limit admin tools to privileged users                  | 4688 (dsquery.exe, dsget.exe)                     | Splunk: `index=wineventlog EventCode=4688 (New_Process_Name="*dsquery.exe*" OR New_Process_Name="*dsget.exe*")`        |
| **Netstat/Port Scanning**      | Identify listening services/ports for lateral movement                              | Restrict tools; monitor excessive scans                | 4688 (netstat.exe), 5156 (network events)          | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*netstat.exe*"`                          |
| **Service Principal Name (SPN) Enumeration** | Enumerate service accounts for Kerberoasting                              | Limit SPN queries; monitor high-volume requests        | 4768/4769 (TGT/TGS), 1644 (LDAP SPN query)         | KQL: `SecurityEvent | where EventID==4769 and ServiceName != "" | summarize count() by Account | where count_ > threshold`     |
| **SMB Enumeration**            | Enumerate shares, users, sessions via SMB (e.g., smbclient, net view)               | Harden shares; restrict access; monitor share use      | 5140 (share access), 5145 (file access)            | Splunk: `index=wineventlog EventCode=5140`                                                          |
| **RPC/SAMR Enumeration**       | Enumerate users, groups, policies via SAMR/RPC                                      | Harden RPC; restrict anonymous SAMR                    | 4662, 4798/4799 (SAM access)                       | Splunk: `index=wineventlog (EventCode=4662 OR EventCode=4798 OR EventCode=4799) Object_Type="SAM"`   |
| **DNS Zone Transfer/Recon**    | Dump all DNS records for AD via zone transfer or DNS queries                        | Disable zone transfers; restrict DNS                   | 6001 (zone transfer), 5156 (DNS query)             | Splunk: `index=dnsevent EventCode=6001 | stats count by src_ip, zone`                                   |
| **Group Policy Enumeration**   | List all GPOs and linked OUs to find misconfigurations and privileged scripts       | Limit GPO read access; review GPO permissions          | 5136 (GPO mod), 4104 (PS GPO recon)                | Splunk: `index=wineventlog EventCode=4104 ScriptBlockText="Get-GPO*"`                               |
| **WMI Query**                  | Use WMI to enumerate local and remote information                                   | Restrict WMI; monitor WMI process use                  | 4688 (wmic.exe), 5861 (WMI-Activity log)           | Splunk: `index=wineventlog EventCode=4688 New_Process_Name="*wmic.exe*"`                            |
| **User/Group Membership Recon**| Query user/group memberships (e.g., net group, PowerView Get-NetGroupMember)        | Limit group membership queries; monitor high volume    | 4688 (net.exe), 4104 (PowerShell)                  | Splunk: `index=wineventlog EventCode=4688 CommandLine="*group*"`                                    |
| **Trust Relationship Mapping** | Enumerate forest/domain trusts to map potential lateral movement paths               | Harden trusts; monitor trust enumeration               | 4688 (nltest.exe), 1644 (LDAP trust query)          | Splunk: `index=wineventlog EventCode=4688 CommandLine="*nltest*"`                                   |
| **Kerberos Pre-Auth/AS-REP Scan** | Scan for accounts without pre-auth (AS-REP Roasting)                           | Require pre-auth; monitor for AS-REQs w/o pre-auth     | 4768 (AS-REQ), 4771 (pre-auth failed)               | Splunk: `index=wineventlog EventCode=4768 PreAuthType="NONE"`                                       |

General AD Evasion Techniques:

| **Technique**                             | **Description / Example**                                                                                   | **Mitigation / Hardening**                                                      | **Detection/Logging**                                        |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|--------------------------------------------------------------|
| **Clearing Security Logs**                | Use of `wevtutil cl`, EventID 1102, 517; tools/scripts to erase evidence                                   | Restrict log clear rights; Forward logs to SIEM; Alert on 1102/517              | Alert on EventID 1102, 517 (log cleared); SIEM/WEF correlation|
| **Disabling/Bypassing AV/EDR/SIEM**       | Uninstall/stop Defender, CrowdStrike, Sysmon, etc.; tamper with agent settings                              | GPO/tamper protection; restrict uninstall; alert on 7036 (service stop)          | Sysmon, EventID 7036 (“stopped”); EDR/SIEM health monitoring  |
| **Disabling or Downgrading Audit Policy**  | Weaken or disable Windows audit policy (4719), modify GPO or local settings                                | Enforce via GPO; monitor for EventID 4719; baseline audit policy                 | Alert on 4719; compare GPO settings; monitor audit policy changes|
| **Script/Command Obfuscation**             | PowerShell obfuscation, base64 encoding, LOLBins, encoded scripts                                           | Enable Script Block Logging (4104); Constrained Language Mode; PowerShell v5+    | Log EventID 4104/4103; alert on FromBase64String, Invoke-Expression, etc.|
| **WMI Obfuscation/Abuse**                  | Use WMI for process/script execution, or persistence (WMI Event Subscriptions)                              | Restrict WMI; alert on unusual WMI events; log Sysmon EventID 19, 20, 21         | Monitor Sysmon 19/20/21; EventID 5861 (WMI Activity); analyze persistence|
| **Living off the Land (LOLBin) Bypass**    | Use built-in tools (e.g., `rundll32`, `wmic`, `mshta`, `certutil`, etc.) to evade security tools            | Block/uninstall unnecessary tools; monitor process creation                      | Log EventID 4688; alert on LOLBin usage with suspicious args |
| **Alternate Data Streams (ADS)**           | Hide payloads/scripts in NTFS ADS (e.g., `file.txt:secret.exe`)                                             | Enable auditing for FileStream; limit write/exec rights; analyze for ADS usage    | Sysmon FileStream, FileCreate events; hunt for “:” in file paths|
| **Masquerading/Binary Name Impersonation** | Rename malicious tools to look like `svchost.exe`, `lsass.exe`, or similar system processes                 | Enable process command line logging; check hash/signatures                        | EventID 4688, Sysmon ProcessCreate; flag suspicious file locations|
| **Service/Task Name Masquerading**         | Create services/tasks with system-like names (`WindowsUpdate`, `svchost`, etc.)                             | Alert on service/task creation (7045, 4698); validate image paths                 | Log 7045, 4698; alert on suspicious service/task names         |
| **GPO/SYSVOL Script Tampering**            | Alter GPO scripts to re-run malware or persist via logon/startup scripts                                    | Restrict GPO/SYSVOL edits; enable file integrity monitoring                       | FileCreate/Change in SYSVOL; EventID 5136 (GPO change); alert on script mods|
| **Obfuscation via Registry (Persistence)** | Hide code in obscure registry keys or use rarely-used persistence locations                                 | Audit/alert on registry key changes (Sysmon, 13/14/15); monitor known autoruns    | Sysmon RegistryEvent; hunt for unusual Run/RunOnce/IFEO/COM keys|
| **Use of Custom/Non-standard Ports**       | Lateral movement or C2 using non-default ports (e.g., SMB on 4445, custom RDP port)                        | Block non-standard ports at firewall; monitor network events for new ports        | Sysmon NetworkConnect; SIEM alert on unexpected dest ports    |
| **Timestomping/Anti-Forensics**            | Modify timestamps of files/artifacts to hide evidence                                                       | Monitor FileCreateTime; enable integrity monitoring                               | Sysmon FileCreateTime events; compare with known baselines    |
| **Disabling Windows Defender via GPO/Registry** | Change Defender settings via GPO or direct registry edits                                               | Enforce Defender via GPO; restrict GPO rights; alert on registry changes          | EventID 5136 (GPO), Sysmon RegistryEvent; SIEM on Defender keys|
| **Log Forwarding Tampering**               | Disable or manipulate Windows Event Forwarding to SIEM                                                     | Monitor collector server health; alert on dropped hosts, EventID 1115             | WEF logs, 1115 (WEF error); SIEM dashboard for host status    |
| **In-Memory/Ephemeral Payloads**           | Fileless malware in memory, reflective DLL injection, memory-only beacons                                   | Enable and monitor AMSI, EDR memory scanning; hunt on process injection           | Sysmon CreateRemoteThread, EventID 10; EDR/AV memory events   |
| **Disabling Security Tools via Scheduled Tasks/Services** | Use scheduled tasks or services to stop, remove, or block EDR/logging                                | Alert on suspicious 4698/7045 events, especially with security tools as targets    | Log 4698/7045 with keywords (defender, sysmon, crowdstrike, etc)|


# Active Directory Hardening Tables

Crucial categories for blue teams:

| **Category**         | **Requirement / Control**                                                    | **Why / Benefit**                                              | **How to Implement**                                      | **Priority** |
|----------------------|------------------------------------------------------------------------------|---------------------------------------------------------------|-----------------------------------------------------------|--------------|
| **Logging**          | Collect Security, Sysmon, PowerShell Operational, and DNS logs               | Visibility for attacks, lateral movement, persistence          | Enable Windows Event Forwarding (WEF), deploy Sysmon       | High         |
| **PowerShell Logging** | Enable ScriptBlock Logging (4104), Module Logging (4103)                    | Capture all executed PS code, even obfuscated                  | GPO: Turn on PowerShell logging policies                   | High         |
| **Process Auditing** | Audit process creation (4688), command-line logging                          | Detect LOLBins, suspicious tools, script execution             | Advanced audit policy, Sysmon config                       | High         |
| **Admin Group Changes** | Log changes to Domain Admins, Enterprise Admins, DNSAdmins, etc.           | Detect privilege escalation, shadow admins                     | Audit Security logs (4728-4732), alert in SIEM             | High         |
| **Service/Task Auditing** | Log new service (7045), scheduled task (4698) creation                   | Detect persistence, privilege escalation, lateral movement      | System log collection, monitor with SIEM                   | Medium       |
| **Registry Auditing** | Log autoruns, LSA, security key changes                                     | Catch persistence, credential theft, GPO bypass                | Sysmon RegistryEvent, Audit registry changes               | Medium       |
| **Network Connection Monitoring** | Log RDP, WinRM, SMB, LDAP, Kerberos, DNS connections              | Identify lateral movement, relay, C2 channels                  | Sysmon NetworkConnect, firewall logs                       | Medium       |
| **Object/ACL Changes** | Monitor changes to ACLs, delegation, msDS-*, AdminSDHolder                 | Spot privilege abuse, shadow credentials                       | Audit logs (4662, 5136), SIEM alerts                       | High         |
| **GPO/SYSVOL Integrity** | File integrity monitoring on GPO, SYSVOL, login scripts                   | Detect backdooring, persistence, ransomware                    | Use FIM, FileCreate/FileChange logging                     | Medium       |
| **Audit Policy Integrity** | Monitor/alert on changes to audit policy (4719)                         | Catch attempts to evade logging and detection                   | Baseline and compare, alert on changes                     | High         |
| **EDR/AV Monitoring** | Deploy and monitor EDR (Defender, CrowdStrike, etc.), ensure it's running    | Stop malware, credential theft, fileless attacks               | Health checks, SIEM integration, tamper alerts             | High         |
| **Cloud/Hybrid Logging** | Collect logs from Azure AD, ADFS, and hybrid sync                         | Detect attacks bridging on-prem and cloud                      | Integrate Azure/Sentinel/Defender with SIEM                | Medium       |
| **Backup/Recovery Protection** | Secure backup files, audit backup operator rights                   | Prevent offline credential dumping, backup hijack              | Limit backup operators, monitor access                      | Medium       |
| **User/Computer Inventory** | Maintain asset inventory and baselines                                 | Spot rogue/new devices, unauthorized changes                   | AD asset inventory, CMDB, SIEM asset management            | High         |
| **DNS Auditing**      | Log and monitor changes to DNS records, zone transfers                      | Detect DNS tunneling, AD CS/relay, and exfil                   | DNS server logs, 5136, 257, 6001, SIEM dashboards          | Medium       |
| **Training & Awareness** | Regular blue team and IT staff training                                   | Maintain readiness, reduce social engineering risk             | Scheduled tabletop and technical exercises                  | High         |

General AD quick check for blue teams:

| **Attack Category**                      | **Preventive Actions/Hardening**                                                                                                                                      | **Logging & Auditing Controls**                                                | **Monitoring/Detection Recommendations**                                 |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| **Password Policy & Auth Attacks**       | - Enforce strong passwords (length & complexity) <br> - Set lockout/MFA policies <br> - Eliminate "password never expires" <br> - Require Kerberos pre-auth           | - Audit password policy, FGPP, PSO assignments <br> - Log 4625/4738/4722      | - Alert on failed logon spikes, changes to password flags/settings      |
| **Credential Dumping**                   | - Enable Credential Guard/LSASS protection <br> - Patch regularly <br> - Restrict local admin rights                                                                 | - Enable Sysmon 10, 4688 <br> - Log 4656/4662/4663/4624/4104                  | - Alert on suspicious proc access (lsass, ntds.dit), tool/process launches|
| **Privilege Escalation**                 | - Limit service, scheduled task, GPO, and ACL delegation <br> - Remove unused admin rights/groups                                                                    | - Log 7045, 4697/4698/4662/5136/4728/4732                                    | - Alert on new service/task creation, sensitive group membership change  |
| **Lateral Movement**                     | - Restrict SMB/RDP/WinRM/WMI to required systems <br> - Harden admin shares <br> - Use Just Enough Admin (JEA) <br> - Use network segmentation                       | - Log 4624/4625, 5140/5145, 4688                                              | - Alert on remote logons, unusual share access, process launches         |
| **Kerberos/NTLM Attacks**                | - Enforce Kerberos/NTLM signing <br> - Disable NTLM where possible <br> - Reset krbtgt regularly                                                                     | - Log 4768/4769/4776/4624                                                     | - Detect abnormal ticket use, replay, ticket lifetimes, NTLM logons      |
| **AD CS Attacks (ESC1-16, Shadow Creds)**| - Secure CA servers (HSM, access, network) <br> - Limit/monitor template rights <br> - Patch CA/Web Enrollment/NTLM relay paths                                      | - Enable 4886/4887/4899 <br> - Log CA/template changes                        | - Alert on template/CA modification, certificate issuance to odd users   |
| **AD FS Attacks**                        | - Secure AD FS signing keys (HSM, restrict export) <br> - Limit AD FS/WAP admin access <br> - Patch endpoints                    | - Enable AD FS logs: 100, 105, 307, 411, 1200-1204                            | - Alert on token signing changes, failed logons, config changes          |
| **Trust Forest Attacks**                 | - Harden/limit trusts, use selective authentication <br> - Audit trust permissions <br> - Reset trust passwords regularly                                            | - Log 4743, 4738, 4769, 4624, 5136                                            | - Detect new trust objects, SIDHistory abuse, cross-forest logons        |
| **ACL/Delegation/OU Abuse**              | - Restrict WriteDACL/WriteOwner/GenericAll/Extended Rights <br> - Regularly review permissions on sensitive objects/OUs                                              | - Log 4662/5136/4738/4732/4728                                                | - Alert on ACL/group/OU changes, especially to Tier 0/1 assets           |
| **Group Policy & SYSVOL Attacks**        | - Restrict GPO/SYSVOL modification rights <br> - Use script integrity monitoring <br> - Remove GPP cPassword artifacts                                              | - Log 5136 (GPO), 4663 (SYSVOL/script), 4104 (PS)                             | - Detect script/GPO modifications, cPassword presence, odd GPO linking   |
| **DNS Attacks**                          | - Restrict dynamic/zone transfers <br> - Limit DNSAdmins <br> - Audit sensitive record changes <br> - Use DNSSEC                                                    | - Log 5136 (DNS changes), 257/6001 (DNS server), 4728/4732 (DNSAdmins)        | - Alert on record/zone change, DNSAdmins modification, zone transfers    |
| **Discovery/Enumeration**                | - Limit non-admin access to enumeration tools <br> - Restrict LDAP/SAMR/Netlogon/DSQuery/PowerShell to admins                                                        | - Log 4688, 1644, 4662, 5140, 4104                                            | - Detect high-volume queries, new use of recon tools, large LDAP queries |
| **Backup/Recovery Abuse**                | - Limit Backup Operators group <br> - Secure backup tools and NTDS/SAM copies <br> - Use full disk encryption                                                        | - Log 4728/4732 (Backup Operators), 4663/7045                                 | - Alert on backup group changes, access to backup files                   |
| **Service Account Attacks (SPN/gMSA)**   | - Strong, unique passwords <br> - Limit who can set SPNs <br> - Monitor gMSA usage <br> - Restrict service account delegation                                       | - Log 4769 (TGS), 4662/5136 (gMSA), 4728 (service accounts)                   | - Alert on service account changes, high TGS requests                     |
| **Malicious Replication (DCShadow/Sync)**| - Restrict replication rights <br> - Monitor for new DCs, replication permission grants                                                                              | - Log 4662 (Get-Changes), 4929 (new DC), 5136                                 | - Alert on replication rights granted, new DC registration                |
| **Physical/Offline Attacks**             | - Use full disk encryption <br> - Limit domain-joined laptop admin rights <br> - Physical security for DCs                                                          | - N/A for offline, but monitor 4624/1102/517 (post-incident)                  | - Alert on log clears, new device DC logon                                |
| **Detection Evasion**                    | - Prevent disabling audit/EDR/AV/SIEM agents <br> - Enforce GPO logging <br> - Disable legacy protocols (LLMNR, NetBIOS, SMBv1)                                    | - Log 7036, 4719, 1102/517, network logs                                      | - Alert on service stops, logging policy changes, legacy protocol use      |
| **LOL Persistence & Movement**           | - Limit task/service creation to admins <br> - Disable WSL if unused <br> - Harden WMI                                        | - Log 7045, 4698, 4688 (schtasks/wsl), 5861 (WMI)                             | - Detect new tasks, services, WSL/PowerShell abuse, WMI events            |
| **Cloud/Hybrid (AAD Connect/PTA/SSO)**   | - Secure and patch hybrid sync servers <br> - Restrict access <br> - Monitor Azure AD Connect and token issuance                                                  | - Log 4688 (AAD Connect proc), 4769, Azure AD logs                            | - Alert on new AADC processes, unexpected token activity                   |

# Sysmon for Blue Teams

| **Feature / Category**      | **Sysmon**                                                        | **ScriptBlock Logging**                                                |
|----------------------------|--------------------------------------------------------------------|------------------------------------------------------------------------|
| **What it is**             | Sysinternals Sysmon: advanced Windows event monitoring agent       | PowerShell feature for logging all parsed/executed code blocks         |
| **Log Source**              | Windows Event Log: Microsoft-Windows-Sysmon/Operational           | Windows Event Log: Microsoft-Windows-PowerShell/Operational (4104)     |
| **Core Purpose**            | Monitor process, file, registry, network, WMI, and more           | Capture all PowerShell script contents, even if obfuscated or encoded   |
| **Detects**                | Process execution, persistence, lateral movement, credential access, code injection, DLLs, network connections, registry abuse, WMI, ADS | Malicious PowerShell (fileless attacks, obfuscation, C2, credential theft), red team frameworks (Empire, PowerView), AMSI bypass, encoded attacks |
| **Example Events**          | 1 (ProcessCreate), 3 (NetworkConnect), 7 (ImageLoad), 10 (ProcAccess), 11 (FileCreate), 13-15 (Registry), 19-21 (WMI), etc. | 4104 (ScriptBlock Logging), 4103 (Module Logging)                      |
| **Configuration**           | Custom XML config (allow/deny, include filters, granular control)  | GPO or registry setting; enabled per host or via domain policy          |
| **Best Use**                | Endpoint/server visibility, correlation with Security logs, high-fidelity alerting | Catching PowerShell-based attacks, hunting for encoded or hidden code   |
| **Performance Impact**      | Low to moderate (tune config for noise/volume)                    | Low to moderate (depends on PS script volume)                           |
| **SIEM Integration**        | Forward Sysmon logs to SIEM/XDR; hunt/correlate with 4688, 4624   | Forward 4104 logs to SIEM; alert on suspicious PS commands/scripts      |
| **Sample Detection**        | Hunt for Mimikatz, DCShadow, WMI persistence, Kerberoasting, lateral movement | Hunt for Invoke-Mimikatz, Invoke-Obfuscation, Empire/PowerSploit usage, encoded/base64|
| **Key Benefits**            | Monitors *all* processes, not just PowerShell; covers binary attacks| Reveals *all* PowerShell activity, including decoded obfuscated commands|
| **Weaknesses**              | Does not decode obfuscated scripts or catch inline PS code unless script is written to disk | Only covers PowerShell, not binary/process/other script attacks         |
| **How to Enable**           | Deploy sysmon.exe with XML config (see [config sample](#))         | GPO: Enable “Turn on PowerShell ScriptBlock Logging” (see [how-to](#))  |

Here's a basic Sysmon config example:
- https://github.com/pwnlog/ALinks/Sysmon/sysmon-config.xml

Then in the SIEM add the following log source (if needed):

- `Microsoft-Windows-Sysmon/Operational`

# PowerShell ScriptBlock for Blue Teams

| **Feature**                   | **ScriptBlock Logging**                                                                                                  |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **What it does**              | Logs every block of PowerShell code (script, function, command), including decoded obfuscated code                      |
| **Event Log Source**          | Microsoft-Windows-PowerShell/Operational                                                                                |
| **Key Event ID**              | 4104                                                                                                                    |
| **What it catches**           | Fileless attacks, encoded (Base64) commands, malicious PowerShell, red team frameworks, LOLBins                         |
| **Best for**                  | Detecting advanced PowerShell-based attacks and forensics                                                               |
| **Where to enable**           | All servers, workstations, especially Domain Controllers and admin endpoints                                            |
| **How to enable via GPO**     | Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → “Turn on PowerShell Script Block Logging” → Set to “Enabled” |
| **How to enable via PowerShell** | `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1` |
| **Where to hunt**             | Look for suspicious/encoded commands, Invoke-Mimikatz, download/execution, obfuscation, Empire                         |
| **SIEM Integration**          | Forward 4104 to SIEM/SOC; write rules for keywords and unusual patterns                                                 |
| **Performance impact**        | Low to moderate, increases with script volume                                                                           |
| **Log retention**             | Ensure retention covers incident dwell time                                                                             |
| **Common false positives**    | Legitimate automation or monitoring scripts; tune out known-good patterns                                               |

Enable ScriptBlock Logging via GPO
- Open `gpedit.msc` or `Group Policy Management Console`.

Go to:
1. Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell
2. Double-click Turn on PowerShell Script Block Logging.
3. Set to Enabled.

Enable Locally via PowerShell:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

Then in the SIEM add the following log source (if needed):

- `Microsoft-Windows-PowerShell/Operational`

# SIGMA Rules for Blue Teams

This SIGMA rules examples are generated by AI but they work as an example to learn:
- https://github.com/pwnlog/ALinks/SIGMA/

> Note: SIGMA YAML format is supported by most SIEMs so they can be imported into some SIEMs.

# Compliance

A compliance framework ensures that an organization follows legal and industry standards.

Compliance Frameworks:
- General Data Protection Regulation (GDPR)
- Payment Card Industry Data Security Standard (PCI DSS)
- Health Insurance Portability and Accountability Act (HIPAA)
- National Institute of Standards and Technology (NIST)

CIS Benchmarks:
- https://cisecurity.org/cis-benchmarks 
- https://learn.cisecurity.org/benchmarks

DISA STIG Benchmarks:
- https://public.cyber.mil/stigs/

Microsoft Security Compliance Toolkit: 
- https://www.microsoft.com/en-us/download/details.aspx?id=55319

Microsoft Purview Compliance Manager:
- https://www.microsoft.com/en-us/security/business/risk-management/microsoft-purview-compliance-manager
- https://learn.microsoft.com/en-us/purview/purview-compliance-portal

Security policies documentation:
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings

# Security Baselines

Security baselines are a set of information security controls that has been established through information security strategic planning activities to address one or more specified security categorizations.

Windows Security Baselines:
- Microsoft Security Blog: https://www.microsoft.com/en-us/security/blog/
- Microsoft TechCommunity Security Compliance and Identity Blog: https://techcommunity.microsoft.com/t5/security-compliance-and-identity/bg-p/MicrosoftSecurityandCompliance
- Microsoft Security Baselines: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- Microsoft Security Baselines Blog: https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/Microsoft-Security-Baselines

# Microsoft Security Blog

Microsoft Security Blog:
- https://www.microsoft.com/en-us/security/blog/

# Hardening 

Hardening projects:
- https://github.com/HotCakeX/Harden-Windows-Security
- https://github.com/0x6d69636b/windows_hardening

Microsoft Defender for Cloud:
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/apply-security-baseline

Microsoft Defender for Cloud Adaptive Network Hardening:
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-network-hardening

# Monitoring

Data Collection:
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection

File Integrity Monitoring:
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview

Just In Time (JIT):
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-overview?tabs=defender-for-container-arch-aks

Endpoint Detection & Response (EDR):
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/integration-defender-for-endpoint

Vulnerability Assessments:
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/remediate-vulnerability-findings-vm

DNS Alerts:
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-alerts

# Honeys

Honey projects:
- https://github.com/0x4D31/deception-as-detection/

# Red Team

Red Team Infrastructure projects:
- https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki

# Evasion

Hiding Operations:
- https://attl4s.github.io/assets/pdf/UNDERSTANDING_AND_HIDING_YOUR_OPERATIONS.pdf

Syscalls:
- https://d01a.github.io/syscalls/

Malware Development Basics:
- https://otterhacker.github.io/Malware/Introduction/0%20-%20Introduction.html
- https://cocomelonc.github.io/

Bypass AV/EDR summary:
- https://matro7sh.github.io/BypassAV/
- https://luemmelsec.github.io/Circumventing-Countermeasures-In-AD/
- https://synzack.github.io/Blinding-EDR-On-Windows/
- https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/

Shellcoding:
- https://xacone.github.io/custom_shellcode.html

Windows API:
- https://noelit911.github.io/Introduction-to-the-Windows-API/#
- https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list
- https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets

Bypass AMSI:
- https://rxored.github.io/post/csharploader/bypassing-amsi-with-csharp/
- https://ret2desync.github.io/using-msbuild-bypass-powershell-clm-amsi-scriptlogging/
- https://icyguider.github.io/2021/07/21/Bypass-AMSI-via-PowerShell-with-Zero-Effort.html

Process PID Spoofing Detection:
- https://detection.fyi/elastic/detection-rules/windows/defense_evasion_parent_process_pid_spoofing/?query=process

Process Hollowing:
- https://rxored.github.io/post/malware/process-hollowing/process-hollowing/
- https://alexfrancow.github.io/red-team/OffensiVe-Security-with-V-2-Process-Hollowing/
- https://alexfrancow.github.io/red-team/OffensiVe-Security-with-V-Shellcode-Execution/
- https://alexfrancow.github.io/red-team/OffensiVe-Security-with-V-3-XOR/
- https://alexfrancow.github.io/red-team/OffensiVe-Security-with-V-4-Caesar/

Under Radar:
- https://crypt0ace.github.io/posts/Staying-under-the-Radar/
- https://crypt0ace.github.io/posts/Staying-under-the-Radar-Part-2/
- https://crypt0ace.github.io/posts/Staying-under-the-Radar-Part-3/

Shellcode Injection:
- https://noelit911.github.io/Payload-Unleashed-Shellcode-Injection/

COFF Loader:
- https://otterhacker.github.io/Malware/CoffLoader.html

APC Injection:
- https://noelit911.github.io/Payload-Unleashed-APC-Injection/

DLL Injection:
- https://noelit911.github.io/Payload-Unleashed-DLL-Injection/
- https://skr1x.github.io/reflective-loading-portable-executable-memory/
- https://xacone.github.io/remote-reflective-dll-injection.html
- https://otterhacker.github.io/Malware/Remote%20DLL%20Injection.html
- https://otterhacker.github.io/Malware/Reflective%20DLL%20injection.html

DLL Sideloading:
- https://github.com/georgesotiriadis/Chimera
- https://www.redpacketsecurity.com/chimera-automated-dll-sideloading-tool-with-edr-evasion-capabilities/
- https://www.crowdstrike.com/blog/dll-side-loading-how-to-combat-threat-actor-evasion-techniques/

ETW:
- https://otterhacker.github.io/Malware/ETW.html
- https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/
- https://thewover.github.io/Cruller/
- https://0xstarlight.github.io/posts/Bypassing-Windows-Defender/
- https://benjitrapp.github.io/attacks/2024-02-11-offensive-etw/
- https://reprgm.github.io/2023/08/30/lets-make-malware-part-11/
- https://lougerard.github.io/me/posts/THM-monitoringevasion/
- https://damonmohammadbagher.github.io/Posts/11Feb2021x.html

Function Hooking:
- https://otterhacker.github.io/Malware/Function%20hooking.html

Kernel Callback:
- https://otterhacker.github.io/Malware/Kernel%20callback.html

Module Stomping:
- https://otterhacker.github.io/Malware/Module%20stomping.html

Gate Techniques:
- https://trickster0.github.io/posts/Halo's-Gate-Evolves-to-Tartarus-Gate/

# Active Directory

AD DS Models:
- Directory System Agent:
    - https://learn.microsoft.com/en-us/windows/win32/ad/directory-system-agent
- Global Catalog:
    - https://learn.microsoft.com/en-us/windows/win32/ad/global-catalog
- Data Model:
    - https://learn.microsoft.com/en-us/windows/win32/ad/data-model
- Schema:
    - https://learn.microsoft.com/en-us/windows/win32/ad/schema
- Administration Model:
    - https://learn.microsoft.com/en-us/windows/win32/ad/administration-model

AD Schema:
- https://learn.microsoft.com/en-us/windows/win32/ad/active-directory-schema
- https://learn.microsoft.com/en-us/windows/win32/ad/about-the-active-directory-schema

Delegation:
- https://learn.microsoft.com/en-us/windows/win32/ad/delegation

Inheritance:
- https://learn.microsoft.com/en-us/windows/win32/ad/inheritance

# Authentication Protocols Security

## Logon Types

Types of Logons:
- https://www.manageengine.com/products/active-directory-audit/learn/what-are-logon-types.html
- https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types

## LANMAN

LANMAN wiki:
- https://en.wikipedia.org/wiki/LAN_Manager

### LM

LM Authentication
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password

### NTLM

NTLM Authentication:
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4
- https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4

### NTLMv1

NTLMv1 Authentication:
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5

### NTLMv2

NTLMv2 Authentication:
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3

## Kerberos

Kerberos Protocol:
- https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9
- https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-kerberos
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/kerberos-policy

### Kerberos 5 

Kerrberos 5:
- https://web.mit.edu/kerberos/www/krb5-1.16/krb5-1.16.html


## MsCache2

MsCache2
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials
- https://security.stackexchange.com/questions/30889/cracking-ms-cache-v2-hashes-using-gpu
- https://openwall.info/wiki/john/MSCash2

## GSS-API/SSPI

SSPI:
- https://learn.microsoft.com/en-us/windows/win32/rpc/sspi-architectural-overview

GSS-API:
- https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi

### SSP

SSP:
- https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-

### Kerberos SSP

Kerberos SSP:
- https://learn.microsoft.com/en-us/windows/win32/secauthn/kerberos-ssp-ap

### NTLM SSP

NTLM SSP:
- https://en.wikipedia.org/wiki/NTLMSSP
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-minimum-session-security-for-ntlm-ssp-based-including-secure-rpc-servers

### Negotiate SSP

Negotiate SSP:
- https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-negotiate

### Digest SSP

Microsoft Digest SSP:
- https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-digest-ssp
- https://learn.microsoft.com/en-us/windows/win32/secauthn/the-digest-access-protocol

### Secure Channel SSP

Secure Channel SSP:
- https://learn.microsoft.com/en-us/windows/win32/secauthn/secure-channel

### Cred SSP

Cred SSP:
- https://learn.microsoft.com/en-us/windows/win32/secauthn/credssp-group-policy-settings

### Custom SSP

Custom SSP:
- https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/custom-ssp.md

# Network Protocols Security

## NTLM

### Pass The Hash

- Pass The Hash Attacks/Detections/Mitigations/Respond:
    - https://www.netwrix.com/pass_the_hash_attack_explained.html

## Kerberos

### Kerberoasting

- Kerberoasting: 
    - https://www.netwrix.com/cracking_kerberos_tgs_tickets_using_kerberoasting.html 
    - https://deephacking.tech/as-reqroasting-as-reproasting-y-tgs-reproasting-kerberoasting-kerberos/
- Kerberoasting Attacks:
    - https://www.crowdstrike.com/cybersecurity-101/kerberoasting/
    - https://www.sentinelone.com/cybersecurity-101/what-is-kerberoasting-attack/
    - https://www.rapid7.com/fundamentals/kerberoasting-attack/
    - https://www.netwrix.com/cracking_kerberos_tgs_tickets_using_kerberoasting.html
    - https://www.splunk.com/en_us/blog/security/detecting-active-directory-kerberos-attacks-threat-research-release-march-2022.html
    - https://www.thehacker.recipes/ad/movement/kerberos/kerberoast
- Kerberoasting Detections:
    - https://adsecurity.org/?p=3458
    - https://adsecurity.org/?p=3513
    - https://redsiege.com/tools-techniques/2020/10/detecting-kerberoasting/
    - https://detection.fyi/tsale/sigma_rules/windows_exploitation/kerberoasting_activity/?query=kerber
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_posh_request_ticket/?query=kerberos
- Kerberoasting Defenses:
    - https://www.lepide.com/blog/how-to-prevent-kerberoasting-attacks/
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf

### Timeroasting

- Timeroasting Attacks:
    - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-kerberoasting/

### AS-REP Roasting

- AS-REP Roasting:
    - https://deephacking.tech/as-reqroasting-as-reproasting-y-tgs-reproasting-kerberoasting-kerberos/
- AS-REP Roasting Attacks:
    - https://redfoxsec.com/blog/as-rep-roasting/
    - https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/
    - https://redbotsecurity.com/as-rep-roasting/
    - https://www.netwrix.com/as-rep-roasting.html
    - https://juggernaut-sec.com/as-rep-roasting/
    - https://www.thehacker.recipes/ad/movement/kerberos/asreproast
- AS-REP Roasting Detections:
    - https://www.blumira.com/how-to-detect-as-rep-roasting/
- AS-REP Roasting Defenses:
    - https://techcommunity.microsoft.com/t5/security-compliance-and-identity/helping-protect-against-as-rep-roasting-with-microsoft-defender/ba-p/2244089

### AS-REQ Roasting

- AS-REQ Roasting Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/asreqroast

### Kerberos Diamond Tickets 

- Kerberos Diamond Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/diamond-ticket.md
    - https://www.trustedsec.com/blog/a-diamond-in-the-ruff
- Kerberos Diamond Tickets Detections:
    - https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/
- Kerberos Diamond Tickets Defenses:
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf

### Kerberos Golden Tickets

- Kerberos Golden Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden
    - https://www.youtube.com/watch?v=v0xKYSkyI6Q
- Kerberos Golden Tickets Detections:
    - https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/
    - https://www.netwrix.com/how_golden_ticket_attack_works.html
- Kerberos Golden Tickets Defenses:
    - https://www.semperis.com/blog/how-to-defend-against-golden-ticket-attacks/
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf
    - https://medium.com/attivotechblogs/protecting-against-kerberos-golden-silver-and-pass-the-ticket-ptt-attacks-9e5b0e262975
    - https://www.netwrix.com/how_golden_ticket_attack_works.html

### Kerberos Silver Tickets

- Kerberos Silver Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/silver-ticket.md
    - https://www.youtube.com/watch?v=k9IGSmZaEHk
- Kerberos Silver Tickets Detections:
    - https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/
- Kerberos Silver Tickets Defenses:
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf
    - https://www.netwrix.com/silver_ticket_attack_forged_service_tickets.html

### Kerberos Bronze Tickets

- Kerberos Bronze Tickets Attacks:
    - https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/bronze-bit
    - https://www.hub.trimarcsecurity.com/post/leveraging-the-kerberos-bronze-bit-attack-cve-2020-17049-scenarios-to-compromise-active-directory
- Kerberos Bronze Tickets Detections:
    - https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/
- Kerberos Bronze Tickets Defenses:
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf

### Kerberos Sapphire Tickets

- Kerberos Sapphire Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire
- Kerberos Sapphire Tickets Detections:
    - https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/
- Kerberos Sapphire Tickets Defenses:
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf

### Kerberos Pass-The-Ticket (PTT)

- Kerberos Pass-The-Ticket Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/ptt
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/pass-the-ticket.md
- Kerberos Pass-The-Ticket Detections:
    - https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/
- Kerberos Pass-The-Ticket Defenses:
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf
    - https://www.netwrix.com/pass_the_ticket.html

### Kerberos Unconstrained Delegation

- Kerberos Delegation: 
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unconstrained-kerberos
- Kerberos Unconstrained Delegation Attacks:
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
    - https://deephacking.tech/unconstrained-delegation-kerberos/
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained
- Kerberos Unconstrained Delegation Detections:
- Kerberos Unconstrained Delegation Defenses:
    - https://hdm.io/writing/Mitigating%20Service%20Account%20Credential%20Theft%20on%20Windows.pdf
    - https://blog.netwrix.com/2022/12/02/unconstrained-delegation/

### Kerberos Constrained Delegation

- Kerberos Constrained Configurations:
    - S4U2Proxy
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a
    - S4U2Self
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13
        - https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse
    - S4U2Self and S4U2Proxy
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/1fb9caca-449f-4183-8f7a-1a5fc7e7290a
- Kerberos Constrained Delegation Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- Kerberos Constrained Delegation Detections:
- Kerberos Constrained Delegation Defenses:
    - https://blog.netwrix.com/2023/04/21/attacking-constrained-delegation-to-elevate-access/

### Kerberos Resource-Based Constrained Delegation (RBCD)

- Kerberos Resource-Based Constrained Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.md
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
- Kerberos Resource-Based Constrained Delegation Detections:
- Kerberos Resource-Based Constrained Delegation Defenses:
    - https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/

### Kerberos Pass The Certificate

- Kerberos Pass The Certificate Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate
- Kerberos Pass The Certificate Detections:
- Kerberos Pass The Certificate Defenses:

### Kerberos UnPAC The Hash

- Kerberos UnPAC The Hash Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash
    - https://shenaniganslabs.io/2021/06/21/Shadow-Credentials.html
- Kerberos UnPAC The Hash Detections:
- Kerberos UnPAC The Hash Defenses:

### Kerberos OverPass The Hash / Pass The Key

- Pass The Key:
    - https://www.thehacker.recipes/ad/movement/kerberos/ptk

### Kerberos Pre-Authentication Bruteforce

- Kerberos Pre-Authentication Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/pre-auth-bruteforce
- Kerberos Pre-Authentication Detections:
- Kerberos Pre-Authentication Defenses:
    - https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory

## ARP

- ARP documentations:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/address-resolution-protocol-arp-caching-behavior
    - https://www.varonis.com/blog/arp-poisoning
- ARP Spoofing:
    - https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/core/arp_cache/arp.py
    - https://github.com/SySS-Research/Seth
    - https://github.com/flashnuke/deadnet
- ARP Spoofing Prevention:
    - https://www.crowdstrike.com/cybersecurity-101/spoofing-attacks/arp-spoofing/
    - https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_pon/software/configuration_guide/sec/b-gpon-config-security/preventing_arf_spoofing_and_flood_attack.html

## DHCP

- DHCP Spoofing / Rogue DHCP Attacks:
    - https://trustedsec.com/blog/injecting-rogue-dns-records-using-dhcp
    - https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp
    - https://github.com/carlospolop/hacktricks/blob/master/generic-methodologies-and-resources/pentesting-network/dhcpv6.md
- Enable DHCP Guard / Snooping:
    - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr_dhcp/configuration/15-sy/dhcp-15-sy-book/ip6-dhcpv6-guard.pdf
    - https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/31sga/configuration/guide/config/dhcp.html
- Prevent DHCP Spoofing:
    - https://www.virtualizationhowto.com/2023/12/dhcp-snooping-configuration-protect-against-rogue-dhcp-servers/
- Disable DHCP:
    - https://learn.microsoft.com/en-us/services-hub/unified/health/remediation-steps-ad/disable-or-remove-the-dhcp-server-service-installed-on-any-domain-controllers

## DHCPv6

- IPv6 Takeover:
    - https://redfoxsec.com/blog/ipv6-dns-takeover/
    - https://medium.com/@huseyin.eksi/how-to-ipv6-dns-takeover-via-mitm6-24b64dac2db5
    - https://notes.justin-p.me/notes/methodology/internal/active-directory/ipv6-dns-takeover/
- IPv4 over IPv6 priority:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows
    - https://kb.firedaemon.com/support/solutions/articles/4000160803-prioritising-ipv4-over-ipv6-on-windows-10-and-11
- Disable IPv6 via GPO:
    - https://4sysops.com/archives/disable-ipv6-in-windows/#:~:text=Disable%20IPv6%20or%20change%20priority,-Microsoft%20provides%20a&text=To%20do%20so%2C%20create%20a,command%20from%20the%20context%20menu.
- Disable IPv6 via GUI:
    - https://adamtheautomator.com/disable-ipv6/

## SMB

- Default Shares:
    - https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/
- Named Pipes
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/4de75e21-36fd-440a-859b-75accc74487c
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/8b6a2986-531d-4702-b83d-43c83b41f68c
    - https://bherunda.medium.com/hunting-detecting-smb-named-pipe-pivoting-lateral-movement-b4382bd1df4
- Protecting Writable Shares:
    - Disable SCF Files
    - Disable URL Files
    - Disable Windows Library Files
    - Disable Windows Search Connectors Files
- Enable SMB Signing:
    - https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server
- SMB Relay Attacks:
    - https://notes.justin-p.me/notes/methodology/internal/active-directory/smb-relay/

## LDAP

- LDAP Attack:
    - https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ldap-injection.md
    - https://github.com/doosec101/LDAP-Anonymous
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-ldap.md
- LDAP Detection:
    - https://detection.fyi/sigmahq/sigma/windows/builtin/ldap/win_ldap_recon/?query=ldap
    - https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_susp_ldap_dataexchange/?query=ldap
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_ldap_attributes/?query=ldap
- LDAP Defense: 
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority
    - https://support.microsoft.com/en-gb/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a
- LDAPS in Clients:
    - https://www.miniorange.com/guide-to-setup-ldaps-on-windows-server
- Enable LDAP Signing:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server

## DNS

- DNS Attack:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/dns-spoofing
- DNS Detection:
    - https://www.fortinet.com/resources/cyberglossary/dns-poisoning
    - https://detection.fyi/elastic/detection-rules/ml/command_and_control_ml_packetbeat_dns_tunneling/?query=dns
    - https://detection.fyi/elastic/detection-rules/ml/command_and_control_ml_packetbeat_rare_dns_question/?query=dns
- DNS Defense:
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj200221(v=ws.11)
- Enable DNSSEC: 
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831411(v=ws.11)
    - https://www.petenetlive.com/KB/Article/0001524

## LLMNR

- LLMNR Attack:
    - https://stridergearhead.medium.com/llmnr-poisoning-an-ad-attack-1265f5365332#:~:text=LLMNR%20Stands%20for%20Link%20Local,hash%20when%20appropriately%20responded%20to.
    - https://www.advantio.com/blog/attacking-active-directory-by-llmnr-nbsn
    - https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it/
    - https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing
    - https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks
    - https://docs.fluidattacks.com/criteria/vulnerabilities/084/
    - https://www.infosecmatter.com/metasploit-module-library/?mm=auxiliary/spoof/mdns/mdns_response
- LLMNR Detection:
    - Monitor port 5353/UDP traffic
- Disable LLMNR: 
    - https://www.blumira.com/integration/disable-llmnr-netbios-wpad-lm-hash/
    - https://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/

## NetBIOS

- NetBIOS Attack:
    - https://hackernoon.com/an-introductory-guide-to-hacking-netbios-bq2w34ay
    - https://www.crowe.com/cybersecurity-watch/netbios-llmnr-giving-away-credentials
- NetBIOS Detection:
- Microsoft Protocol Resolution: 
    - https://techcommunity.microsoft.com/t5/networking-blog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/ba-p/3290816

## WPAD

- WPAD Attacks:
    - https://notes.justin-p.me/notes/methodology/internal/active-directory/wpad/
- WPAD Detections:
    - https://www.extrahop.com/company/blog/2017/detect-wpad-exploit/
    - https://www.sentinelone.com/blog/in-the-wild-wpad-attack-how-threat-actors-abused-flawed-protocol-for-years/
- WPAD Defenses:
    - https://www.thewindowsclub.com/how-to-disable-web-proxy-auto-discovery-wpad-in-windows
- Disable WPAD via Registry: 
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features

## RPC

- RPC Attacks:
    - https://cqr.company/web-vulnerabilities/unsecured-remote-procedure-calls-rpc/
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/135-pentesting-msrpc.md
- RPC Detections:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
- RPC Defenses:
    - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.RemoteProcedureCalls::RpcRestrictRemoteClients
    - https://learn.microsoft.com/en-us/windows-server/security/rpc-interface-restrict
- Unauthenticated clients blog post: 
    - https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/restrictions-for-unauthenticated-rpc-clients-the-group-policy/ba-p/399128

## SAMRPC

- SAMRPC Attacks:
    - https://notes.qazeer.io/active-directory/exploitation-credentials_theft_shuffling
- Restrict SAMRPC calls:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls#audit-only-mode
- SAMRPC Detections:
    - https://threathunterplaybook.com/library/windows/security_account_manager_protocol.html

## WinRM

- WinRM Attacks:
    - https://github.com/Hackplayers/evil-winrm
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/5985-5986-pentesting-winrm.md
- Disable WinRM:
    - https://4sysops.com/wiki/disable-powershell-remoting-disable-psremoting-winrm-listener-firewall-and-localaccounttokenfilterpolicy/
    - https://www.eventsentry.com/validationscripts/guid/1c1e3c39-98a3-41cb-8bf1-1a5f36a6c950
    - https://learn.microsoft.com/en-us/windows-server/administration/server-manager/configure-remote-management-in-server-manager#to-enable-server-manager-remote-management-by-using-the-command-line
    - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/disable-psremoting?view=powershell-7.4&viewFallbackFrom=powershell-7
- WinRM Detections:
    - https://www.elastic.co/guide/en/security/current/incoming-execution-via-winrm-remote-shell.html
    - https://in.security/2021/05/03/detecting-lateral-movement-via-winrm-using-kql/
    - https://cyberwarfare.live/a-unified-purple-teaming-approach-on-winrm-investigation-and-detection/
    - https://detection.fyi/elastic/detection-rules/windows/lateral_movement_incoming_winrm_shell_execution/?query=winrm

## RDP

- RDP Attacks:
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/adversary-in-the-middle/rdp-mitm
    - https://medium.com/@abdullahbeyhan/rdp-mitm-attack-seth-333fe4ee9b07
- RDP Detections:
    - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
    - https://github.com/0x4D31/deception-as-detection/blob/master/Techniques/Lateral_movement/Remote_desktop_protocol.md
- RDP Defenses:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/shell-experience/fips-encryption-not-allow-remote-assistance-connection
- Disable RDP:
    - https://www.cisecurity.org/insights/white-papers/intel-insights-how-to-disable-remote-desktop-protocol
- RDP Configuration via GPO / Registry:
    - https://learn.microsoft.com/en-us/answers/questions/304178/enable-disable-rdp-gpo-from-regedit
- RDP Configuration via PowerShell:
    - https://www.byteinthesky.com/powershell/enable-or-disable-remote-desktop-connection-using-powershell/

## IIS

- IIS Attacks:
    - https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-web/iis-internet-information-services.md
- IIS Detections:
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_iis_apppoolsa_pwd_appcmd/?query=iis
    - https://detection.fyi/elastic/detection-rules/windows/defense_evasion_iis_httplogging_disabled/?query=iis
- IIS Defenses:
    - https://www.cisecurity.org/benchmark/microsoft_iis

## WSUS 

- WSUS Attacks:
    - WSUSpect: 
        - https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf
    - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/deployment-wsus/
    - https://github.com/nettitude/SharpWSUS
    - https://sixdub.medium.com/remote-weaponization-of-wsus-mitm-89c47a8c2561
- Prevent Rogue WSUS Updates:
    - https://4sysops.com/archives/wsus-security-changes/

## Active Directory Federation Services

ADFS Golden SAML:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adfs-federation-services/
- https://www.netwrix.com/golden_saml_attack.html

## SSH

- PowerShell OpenSSH:
    - https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=gui
- PowerShell OpenSSH Attack:
    - https://sensei-infosec.netlify.app/attacks/ssh-bruteforcing/2020/05/07/ssh-bruteforcing.html
- PowerShell OpenSSH Detection:
- PowerShell OpenSSH Defense:

## DFS

- DFS Attack:
    - https://github.com/Wh04m1001/DFSCoerce
    - https://www.praetorian.com/blog/how-to-leverage-dfscoerce/
    - https://www.malwarebytes.com/blog/news/2022/06/dfscoerce-a-new-ntlm-relay-attack-can-take-control-over-a-windows-domain
- DFS Detection:
- DFS Defense:

## MSSQL

- MSSQL Attacks:
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-mssql-microsoft-sql-server/types-of-mssql-users.md
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-mssql-microsoft-sql-server/README.md
    - https://pentestbook.nexixsecuritylabs.com/windows-hardening/active-directory-methodology/abusing-ad-mssql
- MSSQL Detections:
    - https://detection.fyi/search/?query=mssql
    - https://detection.fyi/sigmahq/sigma/windows/builtin/application/mssqlserver/win_mssql_failed_logon/?query=mssql
    - https://detection.fyi/sigmahq/sigma/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change/?query=mssql
    - https://detection.fyi/sigmahq/sigma/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_audit_log/?query=mssql
    - https://detection.fyi/sigmahq/sigma/windows/builtin/application/mssqlserver/win_mssql_disable_audit_settings/?query=mssql
- MSSQL Defenses:
    - https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-server-security-best-practices?view=sql-server-ver16

## Active Directory Integrated DNS (ADIDNS)

- ADIDNS Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing
- ADIDNS Detections:
- ADIDNS Defenses:

## Microsoft's Encrypting File System Remote (MS-EFSR)

- MS-EFSR Attacks:
    - https://www.truesec.com/hub/blog/mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-adv210003-kb5005413-petitpotam
    - https://threatmon.io/blog/petitpotam-ms-efsrpc-exploit-cve2021-36942/
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr
- MS-EFSR Detections:
- MS-EFSR Defenses:

## Microsoft’s Print Spooler (MS-RPRN)

- MS-RPRN Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn
- MS-RPRN Detections:
- MS-RPRN Defenses:

## Microsoft's File Server Remote VSS (MS-FSRVP)

- MS-FSRVP Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp
- MS-FSRVP Detections:
- MS-FSRVP Defenses:

## Microsoft's Distributed File System Namespace Management (MS-DFSNM)

- MDS-DFSNM:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979
- MS-DFSNM Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-dfsnm
- MS-DFSNM Detections:
- MS-DFSNM Defenses:

# Read Only Domain Controller

RODC Attacks:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-rodc/

# Active Directory Certificate Services

Active Directory Certificate Services documentations:
- https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview

AD CS Labs:
- https://github.com/arth0sz/Practice-AD-CS-Domain-Escalation

AD CS All in One:
- https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation/

AD CS Blog:
- https://www.adcs-security.com/
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
- https://redfoxsec.com/blog/exploiting-active-directory-certificate-services-ad-cs/
- https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/

CA PKI Tiers:
- https://www.keytos.io/blog/pki/what-is-a-ca-hierarchy-and-which-ca-hierarchy-should-i-use.html

CA PKI Two Tier:
- https://www.informaticar.net/implementing-two-tier-pki-on-windows-server-2022-part-1/

PKI as a Service:
- https://www.digicert.com/faq/trust-and-pki/what-is-pki-as-a-service

Certificate Enrollment Protocols:
- ACME
    - https://datatracker.ietf.org/doc/html/rfc8555/
    - https://www.rfc-editor.org/rfc/rfc9447.html
- MS-WINACME
    - https://www.win-acme.com
- SCEP:
    - https://learn.microsoft.com/en-us/mem/intune/protect/certificates-scep-configure
- EST
- CMP

## ESC1

- ESC1 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc1
    - https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/
- ESC1 Detections:
- ESC1 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-prevent-users-request-certificate

## ESC2

- ESC2 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc2
- ESC2 Detections:
- ESC2 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-overly-permissive-template

## ESC3

- ESC3 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc3
- ESC3 Detections:
- ESC3 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-misconfigured-enrollment-agent

## ESC4

- ESC4 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc4
- ESC4 Detections:
- ESC4 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-misconfigured-owner

## ESC5

- ESC5 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc5
- ESC5 Detections:
- ESC5 Defenses:

## ESC6

- ESC6 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc6
- ESC6 Detections:
- ESC6 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting

## ESC7

- ESC7 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc7
- ESC7 Detections:
- ESC7 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-misconfigured-ca-acl

## ESC8

- ESC8 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc8
- ESC8 Detections:
- ESC8 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-enforce-encryption-rpc

## ESC9

- ESC9 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc9
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate
- ESC9 Detections:
- ESC9 Defenses:

## ESC10

- ESC10 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc10
- ESC10 Detections:
- ESC10 Defenses:

## ESC11

- ESC11 Attacks:
    - https://heartburn.dev/exploiting-active-directory-certificate-services-esc11-walkthrough/
    - https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/
- ESC11 Detections:
- ESC11 Defenses:

## ESC12

ESC12:
- https://www.adcs-security.com/attacks/esc12

## ESC13

ESC13:
- https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53

## ESC14

ESC14:
- https://www.adcs-security.com/attacks/esc14

## ESC15

ESC15:
- https://www.adcs-security.com/attacks/esc15

## ESC16

ESC16:
- https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation/61512c1e1bc98b60dfc4f32c8099b18f40bd9d34#esc16-security-extension-disabled-on-ca-globally

# Trust Relationships

- Trust Relationships
    - https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust
    - https://www.linkedin.com/pulse/understanding-active-directory-trust-relationships-deep-yasseri/

## Trust Direction

> [!NOTE]
> AI Generated Text

In Active Directory, a trust direction is the direction in which a trust relationship flows between two domains ¹. There are two types of trust directions: **one-way trusts** and **two-way trusts** ¹. 

- **One-way trusts**: When one domain trusts another domain, that trust doesn’t replicate vice versa. Hence, the trust flows only one way ¹². For example, if domain A has a one-way trust with domain B, then domain A trusts domain B and can access resources from domain B. However, domain B does not trust domain A and cannot access resources from domain A ¹².

- **Two-way trusts**: In two-way trusts, when one domain trusts another domain, the other way is also trust. So, both domains can access the resources of the other ¹². For example, if domain A has a two-way trust with domain B, it automatically means that domain B also trusts domain A, and both these domains can share resources between themselves ¹².

Source: 
(1) Trusts in Active Directory: An overview. https://www.windows-active-directory.com/active-directory-trusts.html.
(2) TrustDirection Enum (System.DirectoryServices.ActiveDirectory). https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.trustdirection?view=dotnet-plat-ext-8.0.
(3) [MS-ADTS]: trustDirection | Microsoft Learn. https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04.
(4) How trust relationships work for forests in Active Directory. https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust.

- Trust Direction
    - https://bohops.com/2017/12/02/trust-direction-an-enabler-for-active-directory-enumeration-and-trust-exploitation/

## Trust Transitivity

> [!NOTE]
> AI Generated Text

Active Directory Trust Transitivity is a feature of Active Directory Domain Services (AD DS) that provides security across multiple domains or forests through domain and forest trust relationships ¹. In simple terms, it allows users in one domain to access resources in another domain, provided that the two domains have a trust relationship ¹. 

A transitive trust is a trust that is extended not only to a child object, but also to each object that the child trusts ². In contrast, a non-transitive trust extends only to one object ². Transitive trusts are trusts that can extend beyond the two domains that the trust connects ⁴. When a domain has a transitive trust with another domain, it can also trust and communicate between other domains that the trusted domain has established trust with ⁴.

Source:
(1) How trust relationships work for forests in Active Directory. https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust.
(2) Trust Relationships within Active Directory Directory Services. https://medium.com/tech-jobs-academy/trust-relationships-within-active-directory-directory-services-9f18b3a9e7da.
(3) Trusts in Active Directory: An overview. https://www.windows-active-directory.com/active-directory-trusts.html.
(4) Understanding Trust Transitivity - ITPro Today: IT News, How-Tos .... https://www.itprotoday.com/windows-8/understanding-trust-transitivity.

## SID Filtering

SID filtering is a secuirty feature that's used to prevent users from having rights in a trusted from which they should not have permissions to access.

## Selective Authentication

Selective authentication is used to restrict access to certain users or groups from the trusted forest.

## Trust Types

> [!NOTE]
> AI Generated Text

1. Two-Way Trust: Two domains trust each other. Users in either domain can access resources in the other.
2. One-Way Trust: One domain trusts another, but not vice versa. Users in the trusted domain can access resources in the trusting domain, but not the other way around.
3. Transitive Trust: If domain A trusts domain B, and domain B trusts domain C, then domain A trusts domain C.
4. Non-Transitive Trust: Trust is limited to the two domains in the trust relationship.
5. Forest Trust: A transitive trust between two forests.
6. Shortcut Trust: A transitive trust within a forest, created to shorten the trust path in a large and complex domain structure.


Source:
- https://www.linkedin.com/pulse/understanding-active-directory-trust-relationships-deep-yasseri

## Trust Key

Trust key:
- https://zer1t0.gitlab.io/posts/attacking_ad/#trust-key

## Forest to Forest

### Extra SID / SID History

- Extra SID Attacks:
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/access-token-manipultion/sid-history-injection
    - https://www.thehacker.recipes/ad/persistence/sid-history
    - https://attack.mitre.org/techniques/T1134/005/
    - https://adsecurity.org/?p=1772
    - https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/sid-history-injection
- Extra SID Detections:
    - https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/
- Extra SID Defenses:
    - https://activedirectoryfaq.com/2015/10/active-directory-sid-filtering/
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute

> Remediation: Remove SIDHistory attribute.
> Mitigation: Apply SID filtering. However, SID filtering could be bypassed.

- SID Filtering Bypass:
    - https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research

### MSSQL Trusted Links

- MSSQL Trusted Links Attacks:
    - https://www.offsec-journey.com/post/attacking-ms-sql-servers
    - https://redfoxsec.com/blog/exploiting-ms-sql-servers/
    - https://www.adversify.co.uk/escalating-privileges-via-linked-database-servers/
    - https://github.com/carlospolop/hacktricks/tree/master/network-services-pentesting/pentesting-mssql-microsoft-sql-server
    - https://github.com/gmh5225/awesome-hacktricks/blob/master/windows-hardening/active-directory-methodology/mssql-trusted-links.md

> Remediation: Disable MSSQL Trusted Links. However, this could impact the network.
> Mitigation: Reduce the permissions to specific authorized users and apply the principle of least privilege.

## Child Domain to Forest

### Known Parent/Child

- Kerberos Parent/Child or Child/Parent Attacks:
    - https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent
- Golden gMSA Trust:
    - https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent
- Extra SID Parent/Child Attacks:
    - https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/attack-trusts
    - https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d
- Extra SID Child/Parent Attacks:
    - https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent

# Access Tokens

Access Tokens:
- https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens

Access Tokens Attacks:
- https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all
- https://github.com/foxglovesec/Potato
- https://github.com/foxglovesec/RottenPotato
- https://github.com/decoder-it/lonelypotato
- https://github.com/ohpe/juicy-potato
- https://shenaniganslabs.io/2019/11/12/Ghost-Potato.html
- https://github.com/CCob/SweetPotato
- https://github.com/itm4n/PrintSpoofer
- https://github.com/antonioCoco/RoguePotato
- https://github.com/micahvandeusen/GenericPotato
- https://github.com/antonioCoco/RemotePotato0
- https://github.com/antonioCoco/JuicyPotatoNG
- https://github.com/decoder-it/LocalPotato
- https://github.com/hackvens/CoercedPotato

# Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs)

Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs) documentations:
- https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
- https://learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces

Empty/Null DACLs:
- https://learn.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls

Allowing Anonymous:
- https://learn.microsoft.com/en-us/windows/win32/secauthz/allowing-anonymous-access

Security Descriptor Definition Language (SDDL):
- https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language

Overview Attacks and Defense:
- https://techcommunity.microsoft.com/t5/security-compliance-and-identity/active-directory-access-control-list-8211-attacks-and-defense/ba-p/250315

ACL/ACE:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-acl-ace/

DACL:
- https://www.thehacker.recipes/ad/movement/dacl

AddMember:
- https://www.thehacker.recipes/ad/movement/dacl/addmember

ForceChangePassword:
- https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword

Kerberoasting:
- https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting

ReadLAPSPassword:
- https://www.thehacker.recipes/ad/movement/dacl/readlapspassword

ReadGMSAPassword:
- https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword

Grant ownership:
- https://www.thehacker.recipes/ad/movement/dacl/grant-ownership

Grant rights:
- https://www.thehacker.recipes/ad/movement/dacl/grant-rights

Logon script:
- https://www.thehacker.recipes/ad/movement/dacl/logon-script

DACL Detections:
- https://trustedsec.com/blog/a-hitch-hackers-guide-to-dacl-based-detections-part-2

Privileged Users and Groups:
- https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_account_discovery/?query=groups

# Group Policy Object (GPO)

Group Policy Objects (GPOs) documentation:
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/linking-gpos-to-active-directory-containers
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-hierarchy
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/policy-processing

GPO Attacks:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-group-policy-objects/

## GPO Scopes

GPO scopes documentations:
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/filtering-the-scope-of-a-gpo

## Group Policy Template

Group Policy Templates:
- https://admx.help/

## Group Policy Container

Group Policy Container:
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/Policy/group-policy-storage


## GPO Inheritance

GPO Inheritance documentation:
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/Policy/group-policy-hierarchy
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/overriding-and-blocking-group-policy

# Users

The different kind of users.

## Local Users

Local users are user that only exists in the local machine.

Now a days, you can create local administrators from Microsoft Intune:
- https://whackasstech.com/microsoft/msintune/how-to-create-a-local-admin-with-microsoft-intune/

Built-in users:
- https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts

## Domain Users

Domain users exists in the Active Directory domain.

## Azure AD Users

Azure / Microsoft Entra ID exists in the cloud.

## Built-in Privileged Users

The most common built-in privileged user is the local administrator.

# Groups

Active Directory groups:
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#default-active-directory-security-groups

# DCOM

- DCOM Attacks:
    - DCOM:
        - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/internal-dcom/
        - https://github.com/ScorpionesLabs/DVS
        - https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/
    - DCOM via MMC Application Class
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-mmc-application-class
    - DCOM via Excel
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-office
    - DCOM via ShellExecute
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-shellexecute
    - DCOM via ShellBrowserWindow
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-shellbrowserwindow
- DCOM Defenses:
    - https://www.flexwareinnovation.com/hardening-your-systems-against-the-dcom-vulnerability-what-manufacturers-need-to-know/
    - https://support.microsoft.com/en-us/topic/how-to-disable-dcom-support-in-windows-2bb8c280-9698-7f9c-bf67-2625a5873c7b

# Comments

Comments attribute:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-comments/

# Pre-Created Computer Account

Pre-Created Computer Account:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-precreated-computer/

# Shadow Credentials

Shadow Credentials:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-shadow-credentials/

# Group Managed Service Accounts (gMSA)

- Group Managed Service Accounts (gMSA):
    - https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
    - https://youtu.be/E_-iABSDx0Q?si=8dQbvpMcitpvvah7&t=444
    - https://www.youtube.com/watch?v=mHZ6MqWubd8&t=24s
- Group Managed Service Accounts (gMSA) Attacks:
    - https://www.semperis.com/blog/golden-gmsa-attack/
    - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-gmsa/
    - https://www.youtube.com/watch?v=mHZ6MqWubd8
- Group Managed Service Accounts (gMSA) Detections:
    - https://www.trustedsec.com/blog/splunk-spl-queries-for-detecting-gmsa-attacks
    - https://www.netwrix.com/gmsa_exploitation_attack.html
- Group Managed Service Accounts (gMSA) Defenses:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-
    - https://www.netwrix.com/gmsa_exploitation_attack.html

# System Services

System services:
- https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/privilege-escalation/untitled-1/windows-services

# Task Scheduler

> [!NOTE]
> AI Generated Text

The Task Scheduler service allows you to perform automated tasks on a chosen computer. It can schedule any program to run at a convenient time or when a specific event occurs. The Task Scheduler monitors the time or event criteria that you choose and then executes the task when those criteria are met.

# Local Administrator Password Solution (LAPS)

> [!NOTE]
> AI Generated Text

The Local Administrator Password Solution (LAPS) is a Microsoft tool that provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset.

Local Administrator Password Solution (LAPS) documentation:
- https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords
- https://learn.microsoft.com/en-us/mem/intune/protect/windows-laps-overview
- https://whackasstech.com/microsoft/msintune/configure-laps-local-administrator-password-solution/

LAPS Attacks:
- https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/laps.md
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-laps/

# Application Control

Application Control documentation:
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac

## AppLocker

AppLocker Whitelisting Bypass:
- https://github.com/api0cradle/UltimateAppLockerByPassList
- https://juggernaut-sec.com/applocker-bypass/

## WDAC

WDAC Bypass Techniques:
- Block: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac
- Attack: https://github.com/bohops/UltimateWDACBypassList

WDAC Configuration via Intune:
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/deploy-wdac-policies-using-intune

WDAC Configuration via Microsoft Endpoint Configuration Manager:
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/deploy-wdac-policies-with-memcm

WDAC Configuration via GPO:
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/deploy-wdac-policies-using-group-policy

WDAC Configuration via PowerShell:
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/deploy-wdac-policies-with-script

# Backups

This section contains backup recovery techniques that involve Microsoft's features.

## Windows Shadow Copies

> [!NOTE]
> AI Generated Text

Windows Shadow Copies, also known as Volume Shadow Copy Service, Volume Snapshot Service, or VSS, is a technology that can create backup copies or snapshots of computer files or volumes, even when they are in use. It is implemented as a Windows service and requires NTFS file system. It works by periodically crawling the system and looking for file changes and recording them to disk. Shadow copies can be stored on a local disk, external hard drive, or network drive.

- Windows Shadow Copies:
    - https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service
- Windows Shadow Copies Attacks:
    - https://www.cybersecurity-help.cz/vdb/SB2023071252
    - https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop---abusing-shadow-copies
- Windows Shadow Copies Detections:
    - https://car.mitre.org/analytics/CAR-2021-01-009/
- Windows Shadow Copies Defenses:
    - https://ransomware.org/how-to-prevent-ransomware/threat-hunting/this-is-your-last-chance/

## Active Directory Recycle Bin

The Active Directory Recycle Bin is a feature in the Active Directory Domain Services (AD DS) that allows administrators to recover deleted Active Directory objects, such as user accounts, groups, and computers, without the need to restore from a backup.

- Active Directory Recycle Bin:
    - https://blog.netwrix.com/2021/11/30/active-directory-object-recovery-recycle-bin/
- Active Directory Recycle Bin Attacks:
    - https://learn.microsoft.com/en-us/answers/questions/472286/active-directory-recycle-bin-risks
- Active Directory Recycle Bin Defenses:
    - https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944

# Windows Subsystem for Linux

The Windows Subsystem for Linux is a Microsoft feature that enables a system to run a Linux subsystem operating system.

- Windows Subsystem for Linux:
    - https://learn.microsoft.com/en-us/windows/wsl/about
- Windows Subsystem for Linux Attacks:
      https://blog.lumen.com/windows-subsystem-for-linux-wsl-threats/
- Windows Subsystem for Linux Detections:
    - https://learn.microsoft.com/en-us/windows/wsl/troubleshooting
    - https://github.com/Microsoft/WSL/blob/master/CONTRIBUTING.md#8-detailed-logs
- Windows Subsystem for Linux Defenses:
    - https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1

# Drivers

There are two types of drivers:
- User space drivers run in user space
- Kernel drivers run in kernel space

| **Attack/Vector**                  | **Description / Example**                                                            | **Logging / Detection Method**                        | **Key Events / Logs**                                               | **Blue Team Notes**                                     |
|------------------------------------|-------------------------------------------------------------------------------------|-------------------------------------------------------|---------------------------------------------------------------------|---------------------------------------------------------|
| **BYOVD (Bring Your Own Vulnerable Driver)** | Attacker installs a signed but vulnerable driver to gain kernel/system access     | Sysmon DriverLoad, Windows System logs, EDR           | Sysmon EventID 6 (DriverLoad), Windows 7045, 20001, EDR alerts      | Hunt for unexpected drivers, new .sys files in system dirs  |
| **Malicious Driver Installation**  | Unsigned or custom malicious driver for persistence or code execution                | Sysmon DriverLoad, Windows 7045, EDR, Defender logs   | Sysmon 6, Windows 7045 (service install), Defender AV, EDR logs     | Alert on non-whitelisted driver loads, service installs     |
| **PrintNightmare / Print Spooler Exploit** | Loading vulnerable print drivers for RCE/privesc                                  | Windows PrintService logs, Sysmon DriverLoad           | PrintService 808, 7036, Sysmon 6                                    | Monitor print driver loads, changes to spooler config         |
| **Driver Tampering / Modification**| Changing, patching, or replacing legitimate drivers                                 | Sysmon FileCreate, EDR, File Integrity Monitoring      | Sysmon 11 (FileCreate), FIM/EDR, 7045                              | Alert on driver file changes, new or altered .sys binaries    |
| **Driver Unloading / Stopping**    | Unloading or disabling security/AV drivers to evade detection                        | Windows 7036, EDR, Sysmon, AV logs                     | EventID 7036 (“stopped”), EDR agent logs, Defender/AV warnings      | Alert on stop/uninstall of critical drivers (Defender, EDR)   |
| **Rootkit / Kernel Exploitation**  | Exploiting kernel/driver bugs for stealth, hiding processes, files, or disabling security | EDR, Sysmon, AV, Event Log (kernel errors)        | Sysmon 6, 7036, EDR kernel events, AV logs, 1001 (system errors)    | Look for system instability, unsigned/unknown drivers loaded  |
| **Driver Elevation (Signed Driver Abuse)** | Attacker uses a legitimate signed driver with dangerous capabilities                | Sysmon 6, EDR, driver blocklist policy, Defender logs  | Sysmon 6, EDR driver telemetry, Microsoft driver blocklist events   | Enforce driver blocklists, alert on blocklisted driver hashes |


- Drivers Attacks:
    - https://www.loldrivers.io/
    - https://github.com/magicsword-io/LOLDrivers
- Drivers Detections:
- Drivers Defenses:
    - https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/

# Unquoted Paths

Unquoted Paths aren't enclosed with quotation marks (") and therefore it's interpreted by spaces.

- Unquoted Paths Attacks:
    - https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop---unquoted-service-paths
    - https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths
    - https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
    - https://www.youtube.com/watch?v=WWE7VIpgd5I
- Unquoted Paths Detections:
- Unquoted Paths Defenses:
    - https://isgovern.com/blog/how-to-fix-the-windows-unquoted-service-path-vulnerability/
    - https://help.defense.com/en/articles/6302817-microsoft-windows-unquoted-service-path-enumeration-vulnerability

# JIT & JEA

> [!NOTE]
> AI Generated Text

Microsoft JIT stands for **Just-In-Time**. It is a feature that provides temporary privileged access to production environments when such access is required to support Microsoft online services ². 

In the context of Azure, JIT access enables you to request elevated access to a managed application's resources for troubleshooting or maintenance ³. 

In the context of Microsoft Defender for Cloud, JIT VM access is a feature that allows you to lock down the inbound traffic to your VMs, reducing exposure to attacks while providing easy access to connect to VMs when needed ¹. With JIT, you can allow access to your VMs only when the access is needed, on the ports needed, and for the period of time needed ⁴. 

Source:
(1) Identity and access management overview - Microsoft Service Assurance. https://learn.microsoft.com/en-us/compliance/assurance/assurance-identity-and-access-management.
(2) Request just-in-time access - Azure Managed Applications. https://learn.microsoft.com/en-us/azure/azure-resource-manager/managed-applications/request-just-in-time-access.
(3) Understanding just-in-time (JIT) VM access - learn.microsoft.com. https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-overview.
(4) Enable just-in-time access on VMs - Microsoft Defender for Cloud. https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage.

**JIT** stands for **Just-In-Time** and **JEA** stands for **Just-Enough-Access** ¹. 

JIT is a feature that provides temporary privileged access to production environments when such access is required to support Microsoft online services ². It enables you to request elevated access to a managed application's resources for troubleshooting or maintenance ³. 

In contrast, JEA is a security technology that allows you to delegate administrative privileges to users on a "just enough" basis ¹. It provides a way to grant users administrative access to specific resources without giving them full administrative rights ¹. This helps to reduce the risk of accidental or intentional damage to systems and data ¹.

Source: 
(1) Identity and access management overview - Microsoft Service Assurance. https://learn.microsoft.com/en-us/compliance/assurance/assurance-identity-and-access-management.
(2) Just In Time Versus Just In Sequence • Insequence Corporation. https://insequence.com/just-in-time-versus-just-in-sequence/.
(3) What is the difference between Java components (JRE, JDK, JVM, JIT, and .... https://stackoverflow.com/questions/42851098/what-is-the-difference-between-java-components-jre-jdk-jvm-jit-and-javac.
(4) Modernize secure access for your on-premises resources with Zero Trust. https://www.microsoft.com/en-us/security/blog/2020/11/19/modernize-secure-access-for-your-on-premises-resources-with-zero-trust/.

# Microsoft Defender for Identity (MDI)

> [!NOTE]
> AI Generated Text

In the context of Microsoft, **MDI** stands for **Microsoft Defender for Identity** ¹. It is a cloud-based security solution that helps secure your identity monitoring across your organization ¹. MDI is fully integrated with Microsoft Defender XDR, and leverages signals from both on-premises Active Directory and cloud identities to help you better identify, detect, and investigate advanced threats directed at your organization ¹. 

MDI was formerly known as **Azure Advanced Threat Protection (Azure ATP)** ¹. It provides you with invaluable insights on identity configurations and suggested security best-practices ¹. Through security reports and user profile analytics, MDI helps dramatically reduce your organizational attack surface, making it harder to compromise user credentials, and advance an attack ¹. 

Source:
(1) What is Microsoft Defender for Identity? - Microsoft Defender for .... https://learn.microsoft.com/en-us/defender-for-identity/what-is.
(2) What is the difference between MCAS and MDI while both provides .... https://techcommunity.microsoft.com/t5/microsoft-defender-for-identity/what-is-the-difference-between-mcas-and-mdi-while-both-provides/td-p/2089702.
(3) Microsoft Defender for Identity Ninja Training. https://techcommunity.microsoft.com/t5/security-compliance-and-identity/microsoft-defender-for-identity-ninja-training/ba-p/2117904.
(4) Microsoft Defender for Identity in Microsoft Defender XDR. https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-365-security-center-mdi?view=o365-worldwide.
(5) Microsoft Defender for Identity | Microsoft Security. https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-identity.

# Credentials

This section contains credential dumping techniques that involve Microsoft's features.

## Directory Service Restore Mode (DSRM)

DSRM articles:
- https://adsecurity.org/?p=1714

DSRM documentation:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731865(v=ws.11)

DSRM:
- DSRM Attacks:
    - https://adsecurity.org/?p=1785
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/persistence/dsrm
- DSRM Detections:
- DSRM Defenses:

## DPAPI

> [!NOTE]
> AI Generated Text

DPAPI stands for Data Protection API, a feature provided by Microsoft Windows operating systems for encrypting and decrypting data using a system-specific key. Here's a breakdown of DPAPI and its functionalities:

1. **Encryption and Decryption:**
   - DPAPI enables applications to encrypt sensitive data using encryption keys tied to the current user or machine.
   - It also allows for the decryption of data that has been encrypted using DPAPI, provided the application is running under the same user context or on the same machine.

2. **Key Management:**
   - DPAPI manages encryption keys transparently for applications. It uses master keys derived from the user's credentials to protect the encryption keys.
   - DPAPI uses symmetric encryption, meaning the same key is used for both encryption and decryption. The encryption keys are protected using the user's credentials or machine-specific keys, ensuring that only authorized users or processes can decrypt the data.

3. **Scenarios:**
   - DPAPI is commonly used by applications to securely store passwords, encryption keys, and other sensitive data on the local system.
   - It's often used for encrypting configuration settings, credentials, and other sensitive information stored in files or the Windows registry.
   - DPAPI is also utilized by various system components and services in Windows for securely managing sensitive data.

4. **User and Machine Context:**
   - DPAPI can operate in two contexts: user-specific and machine-specific.
   - User-specific DPAPI keys are derived from the user's logon credentials, ensuring that only the user who encrypted the data can decrypt it.
   - Machine-specific DPAPI keys are derived from machine-specific information, allowing processes running under any user context on the same machine to decrypt the data.

5. **Security Considerations:**
   - DPAPI provides strong encryption for protecting sensitive data, but it's crucial to ensure that the user's credentials or machine-specific keys are adequately protected to prevent unauthorized access.
   - DPAPI relies on the security of the user's logon credentials or machine-specific information. Compromising these can potentially lead to unauthorized access to encrypted data.

Overall, DPAPI is a powerful tool provided by Windows for developers to securely encrypt and decrypt sensitive data, leveraging user or machine-specific keys to ensure confidentiality and integrity.


DPAPI documentation:
- https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection
- https://learn.microsoft.com/en-us/windows/win32/api/dpapi/

DPAPI:
- DPAPI Attacks:
    - https://z3r0th.medium.com/abusing-dpapi-40b76d3ff5eb
    - https://www.dsinternals.com/en/dpapi-backup-key-theft-auditing/
    - https://blog.sygnia.co/the-downfall-of-dpapis-top-secret-weapon
    - https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++
- DPAPI Detections:
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_domain_backup_dpapi_private_keys/?query=mimik
- DPAPI Defenses:

## LSASS

- LSASS Attacks:
    - https://notes.justin-p.me/notes/methodology/internal/active-directory/credential-access/
    - https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass
- LSASS Detections:
    - https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
    - https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_memdump/
- LSASS Defenses:
    - https://en.wikipedia.org/wiki/Credential_Guard

## SAM

- SAM Attacks:
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credential-dumping/security-account-manager-sam
- SAM Detections:
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_copy_ntds_sam_volshadowcp_cmdline/?query=sam
- SAM Defenses:

## NTDS

- NTDS Attacks:
    - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-ntds-dumping/
    - https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds
    - https://attack.mitre.org/techniques/T1003/003/
    - https://www.youtube.com/watch?v=Qy8INpl0Al4
    - https://blog.netwrix.com/2021/11/30/extracting-password-hashes-from-the-ntds-dit-file/
- NTDS Detections:
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_copy_ntds_sam_volshadowcp_cmdline/?query=sam

## Windows Credential Manager

- Windows Credential Manager Attacks:
    - https://systemweakness.com/windows-credential-manager-for-hackers-e67aad9c2a75
    - https://attack.mitre.org/techniques/T1555/004/
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credentials-from-password-stores/windows-credential-manager
- Windows Credential Manager Detections:
    - https://wazuh.com/blog/hunting-for-windows-credential-access-attacks/
- Windows Credential Manager Defenses:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication

## Azure AD Connect

- Azure AD Connect Attacks:
    - https://blog.sygnia.co/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect
- Azure AD Connect Detections:
- Azure AD Connect Defenses:

## LSA

> [!NOTE]
> AI Generated Text

LSA (Local Security Authority) and LSASS (Local Security Authority Subsystem Service) are related components in the Windows operating system, but they serve different purposes:

1. **LSA (Local Security Authority):**
   - LSA is a subsystem in Windows responsible for security policies and authentication.
   - It manages local security policies, such as user rights assignments, auditing policies, and security options.
   - LSA also handles authentication processes, including validating user credentials during logon and managing security tokens.
   - It interacts with various authentication protocols, such as NTLM (NT LAN Manager), Kerberos, and newer authentication mechanisms.

2. **LSASS (Local Security Authority Subsystem Service):**
   - LSASS is the actual system service that hosts the LSA process.
   - It runs as a process (`lsass.exe`) in Windows and is responsible for enforcing security policies and performing security-related functions.
   - LSASS manages the LSA database, handles authentication requests, and generates security audit logs.
   - It's a critical component of the Windows security architecture and is essential for the proper functioning of authentication and security mechanisms.

In summary, LSA is the conceptual framework and set of processes responsible for security policies and authentication, while LSASS is the specific system service that implements and manages LSA functionality within the Windows operating system.

- LSA Configuration:
    - https://www.thewindowsclub.com/how-to-enable-local-security-authority-lsa-protection-in-windows
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- LSA Attacks:
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credential-dumping/lsa-secrets
    - https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets
    - https://attack.mitre.org/techniques/T1003/004/
    - https://itm4n.github.io/lsass-runasppl/
- LSA Detections:
    - https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- LSA Defenses:
    - https://blog.netwrix.com/2022/01/11/understanding-lsa-protection/
    - https://learn.microsoft.com/en-us/answers/questions/1422926/lsa-protection-and-attack-surface-rules

## RunAs Saved Credentials

- RunAs Attacks:
    - https://systemweakness.com/runas-for-hackers-6b2243633091
    - https://medium.com/falconforce/falconfriday-e4554e9e6665
- RunAs Detections:
    - https://www.splunk.com/en_us/blog/security/from-registry-with-love-malware-registry-abuses.html
- RunAs Defenses:
    - Remove `/savecred` from `runas.exe` commands
    - https://stackoverflow.com/a/23634095

## Registry Hive Credentials

- Registry Hive Attacks:
    - https://redcanary.com/blog/windows-registry-attacks-threat-detection/
    - https://www.darkreading.com/cyberattacks-data-breaches/detecting-the-undetectable-windows-registry-attacks
- Registry Hive Detections:
    - https://detection.fyi/elastic/detection-rules/_deprecated/discovery_query_registry_via_reg/?query=registry
    - https://detection.fyi/elastic/detection-rules/windows/persistence_registry_uncommon/?query=registry

## PowerShell History Credentials

- PowerShell History Attacks:
    - https://securityintelligence.com/articles/all-about-powershell-attacks/
    - https://michaelkoczwara.medium.com/windows-privilege-escalation-dbb908cce8d4
- PowerShell History Detections:
    - https://superuser.com/a/1509327
- PowerShell History Defenses:
    - Disable PowerShell History
- Disable PowerShell History:
    - `Set-PSReadlineOption –HistorySaveStyle SaveNothing`

## Clipboard Credentials

- Clipboard Credentials Attacks:
    - https://attack.mitre.org/techniques/T1414/
- Clipboard Credentials Detections:
- Clipboard Credentials Defenses:
    - https://www.elastic.co/guide/en/security/current/powershell-suspicious-script-with-clipboard-retrieval-capabilities.html

# Persistence

## DCShadow

- DCShadow Attacks:
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/dcshadow.md
    - https://www.youtube.com/watch?v=iGcei7yk2Pk
- DCShadow Detections:
- DCShadow Defenses:
    - https://blog.quest.com/dcshadow-attacks-what-they-are-and-how-to-defend-against-them/
    - https://www.netwrix.com/how_dcshadow_persistence_attack_works.html

## DCSync

- DCSync Attacks:
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/dcsync.md
    - https://www.youtube.com/watch?v=_m3u13Df7Fc
- DCSync Detections:
    - https://www.netwrix.com/privilege_escalation_using_mimikatz_dcsync.html
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_dcsync_replication_rights/?query=dcsync
    - https://detection.fyi/elastic/detection-rules/windows/credential_access_dcsync_newterm_subjectuser/?query=dcsync
- DCSync Defenses:
    - https://www.netwrix.com/privilege_escalation_using_mimikatz_dcsync.html

## AdminDSHolder

- AdminSDHolder Attacks:
    - https://www.youtube.com/watch?v=lY35jQ46iPo
- AdminSDHolder Detections:
    - https://www.netwrix.com/adminsdholder_modification_ad_persistence.html
- AdminSDHolder Defenses:
    - https://www.netwrix.com/adminsdholder_modification_ad_persistence.html

## DLL Hijacking Persistence

- DLL Hijacking Attacks:
    - https://www.youtube.com/watch?v=3eROsG_WNpE
- DLL Hijacking
    - https://www.mandiant.com/resources/blog/abusing-dll-misconfigurations

# Account Takeover

## AD Attribute 

- AD Attribute Takeover Attacks:
    - https://www.youtube.com/watch?v=tFb3ow25iNg

## Shadow Credentials

- Shadow Credentials via Key Trust:
    - https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab

# MiTM

MiTM Attacks:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/internal-mitm-relay/
- https://github.com/frostbits-security/MITM-cheatsheet

# Classic Vulnerabilities

> Mitigation: Overall recommendation is to use a patch management platform to keep every asset updated with the latests patches.

Certifried CVE-2022-26923: 
- MSRC: 
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923
- Microsoft Documentation: 
    - https://support.microsoft.com/en-us/topic/april-11-2023-kb5025230-os-build-20348-1668-28a5446e-6389-4a5b-ae3f-e942a604f2d3

EternalBlue MS17-010:
- Microsoft Documentation: 
    - https://support.microsoft.com/en-us/topic/ms17-010-security-update-for-windows-smb-server-march-14-2017-435c22fb-5f9b-f0b3-3c4b-b605f4e6a655

HiveNightmare CVE-2021-36934:
- MSRC: 
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
- Article: 
    - https://news.sophos.com/en-us/2021/07/22/hivenightmare-aka-serioussam-vulnerability-what-to-do/

Log4Shell CVE-2021-44228:
- Microsoft Defender for Endpoint mitigation: 
    - https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-manage-log4shell-guidance?view=o365-worldwide

Kerberos Could Allow Elevation of Privilege MS14-068 / CVE-2014-6324:
- Microsoft documentation: 
    - https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-068

SamAccountName CVE-2021-42287 / NoPAC CVE-2021-42278:
- MSRC: 
    - https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-42278

PrintNightmare CVE-2021-1675 / CVE 2021-42278:
- MSRC: 
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527

PrivExchange CVE-2019-0724 / CVE 2019-0686:
- Tool: 
    - https://github.com/dirkjanm/PrivExchange
- Article: 
    - https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/
- Patch: 
    - https://techcommunity.microsoft.com/t5/exchange-team-blog/released-february-2019-quarterly-exchange-updates/ba-p/609061

ProxyLogon CVE-2021-26855:
- CISA Advisory: 
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a
- Blog Post: 
    - https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
- Patch: 
    - https://msrc.microsoft.com/blog/2021/03/multiple-security-updates-released-for-exchange-server/

ProxyShell CVE-2021-31207 / CVE-2021-34473 / CVE-2021-34523:
- Blog Post: 
    - https://techcommunity.microsoft.com/t5/exchange-team-blog/proxyshell-vulnerabilities-and-your-exchange-server/ba-p/2684705
- Workarounds: 
    - https://news.sophos.com/en-us/2021/08/23/proxyshell-vulnerabilities-in-microsoft-exchange-what-to-do/
    - https://www.mandiant.com/resources/blog/pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers

SMBGhost CVE-2020-0796:
- Patch: 
    - https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-0796

SYSVOL GPP MS14-025:
- Article: 
    - https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30
- Security Bulletin: 
    - https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025?redirectedfrom=MSDN

ZeroLogon CVE-2020-1472:
- Article: 
    - https://www.tenable.com/blog/cve-2020-1472-microsoft-finalizes-patch-for-zerologon-to-enable-enforcement-mode-by-default
- Patch: 
    - https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-1472
