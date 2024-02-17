# AD Purple

Collection of Active Directory links for purple teamers.

> [!NOTE]
> This is in-progress :)

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

Security policies documentation:
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings

# Security Baselines

Security baselines are a set of information security controls that has been established through information security strategic planning activities to address one or more specified security categorizations.

Windows Security Baselines:
- Microsoft Security Blog: https://www.microsoft.com/en-us/security/blog/
- Microsoft TechCommunity Security Compliance and Identity Blog: https://techcommunity.microsoft.com/t5/security-compliance-and-identity/bg-p/MicrosoftSecurityandCompliance
- Microsoft Security Baselines: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- Microsoft Security Baselines Blog: https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/Microsoft-Security-Baselines

# Blogs

- https://www.microsoft.com/en-us/security/blog/

# Honeys

- https://github.com/0x4D31/deception-as-detection/S

# Authentication Protocols Security

## Logon Types

Types of Logons:
- https://www.manageengine.com/products/active-directory-audit/learn/what-are-logon-types.html
- https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types

### LM

Prevent LM hash: 
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password

### NTLM

NTLM Authentication:
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4
- https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4

### NTLMv1

NTLMv1 Authentication:
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5

### NTMLv2

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

## Kerberos

### Kerberoasting

- Kerberoasting: 
    - https://www.netwrix.com/cracking_kerberos_tgs_tickets_using_kerberoasting.html 
    - https://deephacking.tech/as-reqroasting-as-reproasting-y-tgs-reproasting-kerberoasting-kerberos/
- Kerberoasting Configurations:
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
- Kerberoasting Defenses:
    - https://www.lepide.com/blog/how-to-prevent-kerberoasting-attacks/

### AS-REP Roasting

- AS-REP Roasting:
    - https://deephacking.tech/as-reqroasting-as-reproasting-y-tgs-reproasting-kerberoasting-kerberos/
- AS-REP Roasting Configurations:
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
- AS-REQ Roasting Detections:
- AS-REQ Roasting Defenses:


### Kerberos Diamond Tickets 

- Kerberos Diamond Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/diamond-ticket.md
    - https://www.trustedsec.com/blog/a-diamond-in-the-ruff
- Kerberos Diamond Tickets Detections:
- Kerberos Diamond Tickets Defenses:
- Prevent Kerberos Diamond Tickets:

### Kerberos Golden Tickets

- Kerberos Golden Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden
- Kerberos Golden Tickets Detections:
- Kerberos Golden Tickets Defenses:
- Prevent Kerberos Golden Tickets:
    - https://medium.com/attivotechblogs/protecting-against-kerberos-golden-silver-and-pass-the-ticket-ptt-attacks-9e5b0e262975

### Kerberos Silver Tickets

- Kerberos Silver Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/silver-ticket.md
- Kerberos Silver Tickets Detections:
- Kerberos Silver Tickets Defenses:
- Prevent Kerberos Silver Tickets:

### Kerberos Bronze Tickets

- Kerberos Bronze Tickets Attacks:
    - https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/bronze-bit
    - https://www.hub.trimarcsecurity.com/post/leveraging-the-kerberos-bronze-bit-attack-cve-2020-17049-scenarios-to-compromise-active-directory
- Kerberos Bronze Tickets Detections:
- Kerberos Bronze Tickets Defenses:
- Prevent Kerberos Bronze Tickets:

### Kerberos Sapphire Tickets

- Kerberos Sapphire Tickets Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire
- Kerberos Sapphire Tickets Detections:
- Kerberos Sapphire Tickets Defenses:
- Prevent Kerberos Sapphire Tickets:

### Kerberos Pass-The-Ticket (PTT)

- Kerberos Pass-The-Ticket Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/ptt
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/pass-the-ticket.md
- Kerberos Pass-The-Ticket Detections:
- Kerberos Pass-The-Ticket Defenses:
- Prevent Kerberos Pass-The-Ticket (PTT):

### Kerberos Unconstrained Delegation

- Kerberos Delegation: 
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unconstrained-kerberos
- Kerberos Unconstrained Delegation:
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
    - https://deephacking.tech/unconstrained-delegation-kerberos/
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained
- Kerberos Unconstrained Configurations:
- Kerberos Unconstrained Attacks:
- Kerberos Unconstrained Detections:
- Kerberos Unconstrained Defenses:


### Kerberos Constrained Delegation

- Kerberos Constrained Configurations:
    - S4U2Proxy
    - S4U2Self
        - https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse
    - S4U2Self and S4U2Proxy
- Kerberos Constrained Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained
- Kerberos Constrained Detections:
- Kerberos Constrained Defenses:
- Kerberos Constrained Delegation:
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation


### Kerberos Resource-Based Constrained Delegation (RBCD)

- Kerberos Resource-Based Constrained Configurations:
- Kerberos Resource-Based Constrained Attacks:
    - https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.md
- Kerberos Resource-Based Constrained Detections:
- Kerberos Resource-Based Constrained Defenses:
- Kerberos Resource-Based Constrained Delegation:
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution

### Kerberos Pass The Certificate

- Kerberos Pass The Certificate Configurations:
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
- LDAP Defense:
- Enable LDAPS: 
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
- LLMNR Detection:
- Disable LLMNR: 
    - https://www.blumira.com/integration/disable-llmnr-netbios-wpad-lm-hash/
    - https://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/

## mDNS

- mDNS Attack:
    - https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks
    - https://docs.fluidattacks.com/criteria/vulnerabilities/084/
    - https://www.infosecmatter.com/metasploit-module-library/?mm=auxiliary/spoof/mdns/mdns_response
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing
- mDNS Detection:
- Disable mDNS: 
    - https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777

## NetBIOS

- NetBIOS Attack:
    - https://hackernoon.com/an-introductory-guide-to-hacking-netbios-bq2w34ay
    - https://www.crowe.com/cybersecurity-watch/netbios-llmnr-giving-away-credentials
- NetBIOS Detection:
- Microsoft Protocol Resolution: 
    - https://techcommunity.microsoft.com/t5/networking-blog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/ba-p/3290816

## WPAD

- WPAD Configurations:
- WPAD Attacks:
    - https://notes.justin-p.me/notes/methodology/internal/active-directory/wpad/
- WPAD Detections:
- WPAD Defenses:
- Disable WPAD via Registry: 
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features

## RPC

- RPC Attacks:
    - https://cqr.company/web-vulnerabilities/unsecured-remote-procedure-calls-rpc/
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/135-pentesting-msrpc.md
- RPC Detections:
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
- WinRM Configuration via GPO:
- WinRM Configuration via PowerShell:
- WinRM Detections:
    - https://www.elastic.co/guide/en/security/current/incoming-execution-via-winrm-remote-shell.html
    - https://in.security/2021/05/03/detecting-lateral-movement-via-winrm-using-kql/
    - https://cyberwarfare.live/a-unified-purple-teaming-approach-on-winrm-investigation-and-detection/

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
- IIS Defenses:
- IIS CIS Benchmarks: 
    - https://www.cisecurity.org/benchmark/microsoft_iis

## WSUS 

- WSUS Attacks:
    - WSUSpect: 
        - https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf
    - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/deployment-wsus/
    - https://github.com/nettitude/SharpWSUS
    - https://sixdub.medium.com/remote-weaponization-of-wsus-mitm-89c47a8c2561
- WSUS Configuration via GPO:
- WSUS Configuration via PowerShell:
- Prevent Rogue WSUS Updates:
    - https://4sysops.com/archives/wsus-security-changes/

## SSH

- PowerShell OpenSSH:
    - https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=gui
- PowerShell OpenSSH Attack:
    - https://sensei-infosec.netlify.app/attacks/ssh-bruteforcing/2020/05/07/ssh-bruteforcing.html
- PowerShell OpenSSH Detection:
- PowerShell OpenSSH Defense:

## DFS

- DFS Configuration:
- DFS Attack:
    - https://github.com/Wh04m1001/DFSCoerce
    - https://www.praetorian.com/blog/how-to-leverage-dfscoerce/
    - https://www.malwarebytes.com/blog/news/2022/06/dfscoerce-a-new-ntlm-relay-attack-can-take-control-over-a-windows-domain
- DFS Detection:
- DFS Defense:

## MSSQL

- MSSQL Configurations:
- MSSQL Attacks:
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-mssql-microsoft-sql-server/types-of-mssql-users.md
    - https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-mssql-microsoft-sql-server/README.md
- MSSQL Detections:
- MSSQL Defenses:

## Active Directory Integrated DNS (ADIDNS)

- ADIDNS Configurations:
- ADIDNS Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing
- ADIDNS Detections:
- ADIDNS Defenses:

## Microsoft's Encrypting File System Remote (MS-EFSR)

- MS-EFSR Configurations:
- MS-EFSR Attacks:
    - https://www.truesec.com/hub/blog/mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-adv210003-kb5005413-petitpotam
    - https://threatmon.io/blog/petitpotam-ms-efsrpc-exploit-cve2021-36942/
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr
- MS-EFSR Detections:
- MS-EFSR Defenses:

## Microsoft’s Print Spooler (MS-RPRN)

- MS-RPRN Configurations:
- MS-RPRN Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn
- MS-RPRN Detections:
- MS-RPRN Defenses:

## Microsoft's File Server Remote VSS (MS-FSRVP)

- MS-FSRVP Configurations:
- MS-FSRVP Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp
- MS-FSRVP Detections:
- MS-FSRVP Defenses:

## Microsoft's Distributed File System Namespace Management (MS-DFSNM)

- MS-DFSNM Configurations:
- MS-DFSNM Attacks:
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-dfsnm
- MS-DFSNM Detections:
- MS-DFSNM Defenses:

# Active Directory Certificate Services

Active Directory Certificate Services documentations:
- https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview

AD CS Labs:
- https://github.com/arth0sz/Practice-AD-CS-Domain-Escalation

AD CS Blog:
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
- https://redfoxsec.com/blog/exploiting-active-directory-certificate-services-ad-cs/
- https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/

CA PKI Tiers:
- https://www.keytos.io/blog/pki/what-is-a-ca-hierarchy-and-which-ca-hierarchy-should-i-use.html

CA Two Tier:
- https://www.informaticar.net/implementing-two-tier-pki-on-windows-server-2022-part-1/

## ESC1

- ESC1 Configurations:
- ESC1 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc1
    - https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/
- ESC1 Detections:
- ESC1 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-prevent-users-request-certificate

## ESC2

- ESC2 Configurations:
- ESC2 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc2
- ESC2 Detections:
- ESC2 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-overly-permissive-template

## ESC3

- ESC3 Configurations:
- ESC3 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc3
- ESC3 Detections:
- ESC3 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-misconfigured-enrollment-agent

## ESC4

- ESC4 Configurations:
- ESC4 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc4
- ESC4 Detections:
- ESC4 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-misconfigured-owner

## ESC5

- ESC5 Configurations:
- ESC5 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc5
- ESC5 Detections:
- ESC5 Defenses:

## ESC6

- ESC6 Configurations:
- ESC6 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc6
- ESC6 Detections:
- ESC6 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting

## ESC7

- ESC7 Configurations:
- ESC7 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc7
- ESC7 Detections:
- ESC7 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-misconfigured-ca-acl

## ESC8

- ESC8 Configurations:
- ESC8 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc8
- ESC8 Detections:
- ESC8 Defenses:
    - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-enforce-encryption-rpc

## ESC9

- ESC9 Configurations:
- ESC9 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc9
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate
- ESC9 Detections:
- ESC9 Defenses:

## ESC10

- ESC10 Configurations:
- ESC10 Attacks:
    - https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc10
- ESC10 Detections:
- ESC10 Defenses:

## ESC11

- ESC11 Configurations:
- ESC11 Attacks:
    - https://heartburn.dev/exploiting-active-directory-certificate-services-esc11-walkthrough/
    - https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/
- ESC11 Detections:
- ESC11 Defenses:

## ESC13

ESC13:
- https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53

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
- Extra SID Detections:
    - https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/
- Extra SID Defenses:

### MSSQL Trusted Links

- MSSQL Trusted Links Attacks:
    - https://www.offsec-journey.com/post/attacking-ms-sql-servers
    - https://redfoxsec.com/blog/exploiting-ms-sql-servers/
    - https://www.adversify.co.uk/escalating-privileges-via-linked-database-servers/
    - https://github.com/carlospolop/hacktricks/tree/master/network-services-pentesting/pentesting-mssql-microsoft-sql-server
- MSSQL Trusted Links Detections:
- MSSQL Trusted Links Defenses:

## Child Domain to Forest

### Extra SIDs Parent/Child

- Extra SID Parent/Child Attacks:
    - https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/attack-trusts
    - https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d
- Extra SID Parent/Child Detections:
- Extra SID Parent/Child Defenses:

### Extra SIDs Child/Parent

- Extra SID Child/Parent Attacks:
- Extra SID Child/Parent Detections:
- Extra SID Child/Parent Defenses:

# Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs)

Discretionary Access Control Lists (DACLs) and Access Control Entries (ACEs) documentations:
- https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
- https://learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces

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

## Users

- Users DACL:
- Users DACL Attacks:
- Users DACL Detections:
- Users DACL Defenses:

## Groups

- Groups DACL:
- Groups DACL Attacks:
- Groups DACL Detections:
- Groups DACL Defenses:

## Services

- Services DACL:
- Services DACL Attacks:
- Services DACL Detections:
- Services DACL Defenses:

## Computers

- Computers DACL:
- Computers DACL Attacks:
- Computers DACL Detections:
- Computers DACL Defenses:

## Directories

- Directories DACL:
- Directories DACL Attacks:
- Directories DACL Detections:
- Directories DACL Defenses:

## Files

- Files DACL:
- Files DACL Attacks:
- Files DACL Detections:
- Files DACL Defenses:

## Group Policy

- Group Policy DACL:
- Group Policy DACL Attacks:
- Group Policy DACL Detections:
- Group Policy DACL Defenses:

# Group Policy Object (GPO)

Group Policy Objects (GPOs) documentation:
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/linking-gpos-to-active-directory-containers
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-hierarchy
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/policy-processing

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

DCOM Attacks:
    - DCOM:
        - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/internal-dcom/
    - DCOM via MMC Application Class
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-mmc-application-class
    - DCOM via Excel
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-office
    - DCOM via ShellExecute
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-shellexecute
    - DCOM via ShellBrowserWindow
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dcom-via-shellbrowserwindow

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
- Group Managed Service Accounts (gMSA) Attacks:
    - https://www.semperis.com/blog/golden-gmsa-attack/
    - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-gmsa/
- Group Managed Service Accounts (gMSA) Detections:
- Group Managed Service Accounts (gMSA) Defenses:

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
- Active Directory Recycle Bin Detections:
- Active Directory Recycle Bin Defenses:

# Windows Subsystem for Linux

The Windows Subsystem for Linux is a Microsoft feature that enables a system to run a Linux subsystem operating system.

- Windows Subsystem for Linux:
- Windows Subsystem for Linux Attacks:
      https://blog.lumen.com/windows-subsystem-for-linux-wsl-threats/
- Windows Subsystem for Linux Detections:
- Windows Subsystem for Linux Defenses:
    - https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1

# Drivers

There are two types of drivers:
- User space drivers run in user space
- Kernel drivers run in kernel space

- Drivers Attacks:
    - https://www.loldrivers.io/
    - https://github.com/magicsword-io/LOLDrivers
- Drivers Detections:
- Drivers Defenses:

# Unquoted Paths

Unquoted Paths aren't enclosed with quotation marks (") and therefore it's interpreted by spaces.

- Unquoted Paths Attacks:
    - https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop---unquoted-service-paths
    - https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths
    - https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
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
- DPAPI Defenses:

## LSASS

- LSASS Attacks:
    - https://notes.justin-p.me/notes/methodology/internal/active-directory/credential-access/
    - https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass
- LSASS Detections:
- LSASS Defenses:

## SAM

- SAM Attacks:
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credential-dumping/security-account-manager-sam
- SAM Detections:
- SAM Defenses:

## NTDS

- NTDS Attacks:
    - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-ntds-dumping/
    - https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds
    - https://attack.mitre.org/techniques/T1003/003/
- NTDS Detections:
- NTDS Defenses:

## Windows Credential Manager

- Windows Credential Manager Attacks:
    - https://systemweakness.com/windows-credential-manager-for-hackers-e67aad9c2a75
    - https://attack.mitre.org/techniques/T1555/004/
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credentials-from-password-stores/windows-credential-manager
- Windows Credential Manager Detections:
- Windows Credential Manager Defenses:
    - https://wazuh.com/blog/hunting-for-windows-credential-access-attacks/
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

- LSA Attacks:
    - https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credential-dumping/lsa-secrets
    - https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets
- LSA Detections:
- LSA Defenses:
    - https://blog.netwrix.com/2022/01/11/understanding-lsa-protection/
    - https://learn.microsoft.com/en-us/answers/questions/1422926/lsa-protection-and-attack-surface-rules

## RunAs Saved Credentials

- RunAs Attacks:
    - https://systemweakness.com/runas-for-hackers-6b2243633091
    - https://medium.com/falconforce/falconfriday-e4554e9e6665
- RunAs Detections:
- RunAs Defenses:

## Registry Hive Credentials

- Registry Hive Attacks:
    - https://redcanary.com/blog/windows-registry-attacks-threat-detection/
    - https://www.darkreading.com/cyberattacks-data-breaches/detecting-the-undetectable-windows-registry-attacks
- Registry Hive Detections:
- Registry Hive Defenses:

## PowerShell History Credentials

- PowerShell History Attacks:
    - https://securityintelligence.com/articles/all-about-powershell-attacks/
    - https://michaelkoczwara.medium.com/windows-privilege-escalation-dbb908cce8d4
- PowerShell History Detections:
- PowerShell History Defenses:
- Disable PowerShell History:

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
- DCShadow Detections:
- DCShadow Defenses:

## DCSync

- DCSync Attacks:
    - https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/dcsync.md
- DCSync Detections:
- DCSync Defenses:

# MiTM

MiTM Attacks:
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/internal-mitm-relay/
- https://github.com/frostbits-security/MITM-cheatsheet

# Classic Vulnerabilities

Certifried CVE-2022-26923: 
- MSRC: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923
- Microsoft Documentation: https://support.microsoft.com/en-us/topic/april-11-2023-kb5025230-os-build-20348-1668-28a5446e-6389-4a5b-ae3f-e942a604f2d3

EternalBlue MS17-010:
- Microsoft Documentation: https://support.microsoft.com/en-us/topic/ms17-010-security-update-for-windows-smb-server-march-14-2017-435c22fb-5f9b-f0b3-3c4b-b605f4e6a655

HiveNightmare CVE-2021-36934:
- MSRC: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
- Article: https://news.sophos.com/en-us/2021/07/22/hivenightmare-aka-serioussam-vulnerability-what-to-do/

Log4Shell CVE-2021-44228:
- Microsoft Defender for Endpoint mitigation: https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-manage-log4shell-guidance?view=o365-worldwide

Kerberos Could Allow Elevation of Privilege MS14-068 / CVE-2014-6324:
- Microsoft documentation: https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-068

SamAccountName CVE-2021-42287 / NoPAC CVE-2021-42278:
- MSRC: https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-42278

PrintNightmare CVE-2021-1675 / CVE 2021-42278:
- MSRC: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527

PrivExchange CVE-2019-0724 / CVE 2019-0686:
- Tool: https://github.com/dirkjanm/PrivExchange
- Article: https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/
- Patch: https://techcommunity.microsoft.com/t5/exchange-team-blog/released-february-2019-quarterly-exchange-updates/ba-p/609061

ProxyLogon CVE-2021-26855:
- CISA Advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a
- Blog Post: https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
- Patch: https://msrc.microsoft.com/blog/2021/03/multiple-security-updates-released-for-exchange-server/

ProxyShell CVE-2021-31207 / CVE-2021-34473 / CVE-2021-34523:
- Blog Post: https://techcommunity.microsoft.com/t5/exchange-team-blog/proxyshell-vulnerabilities-and-your-exchange-server/ba-p/2684705
- Workarounds: 
    - https://news.sophos.com/en-us/2021/08/23/proxyshell-vulnerabilities-in-microsoft-exchange-what-to-do/
    - https://www.mandiant.com/resources/blog/pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers

SMBGhost CVE-2020-0796:
- Patch: https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-0796

SYSVOL GPP MS14-025:
- Article: https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30
- Security Bulletin: https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025?redirectedfrom=MSDN

ZeroLogon CVE-2020-1472:
- Article: https://www.tenable.com/blog/cve-2020-1472-microsoft-finalizes-patch-for-zerologon-to-enable-enforcement-mode-by-default
- Patch: https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-1472