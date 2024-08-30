# -So-You-ve-Got-MFA-Defending-and-Responding-Against-MFA-Bypass-Techniques-in-Entra

This talk was given as part of https://www.meetup.com/m365sandcug/events/302644214 and serves as a much needed update to my [earlier article](https://www.linkedin.com/posts/jay-kerai-cyber_devfender-entra-token-activity-7122902992873287681-P03M?utm_source=share)

My intention is create a more formal writeup based on the content presented.

The videos have been stripped out for file size and replaced with public referenced videos instead.

Shoutout to anyone who's content I have referenced/featured! They were really helpful for confirming my knowledge or teaching me new things :D


# References 

Slide 3: How to bypass MFA? 

https://github.com/kgretzky/evilginx2
https://github.com/drk1wi/Modlishka

Smartscreen/Exploit Guard KQL:
```
DeviceEvents
| where ActionType == "SmartScreenUrlWarning" or ActionType == "ExploitGuardNetworkProtectionBlocked"
```
Browser history/Artificats: https://www.linkedin.com/pulse/stealing-passwords-defender-endpoint-jay-kerai

Slide 4:
Merill Fernado Demo: https://www.youtube.com/watch?v=tI1bdVohOK8

Slide 6: Simplyfing the attack

https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/

Slide 8:

host locally: https://janbakker.tech/running-evilginx-3-0-on-windows/

Slide 12: Conditional Access: Sign-in Risk (Identity Protection)

Microsoft Entra ID Protection risk-based access policies - Microsoft Entra ID Protection | Microsoft Learn


Slide 13: On the same note…Idle Session Time Out

https://learn.microsoft.com/en-us/microsoft-365/admin/manage/idle-session-timeout-web-apps?view=o365-worldwide#details-about-idle-session-timeout

Slide 15: Conditional Access: Block Certain Device Platforms/User agents

Queries:
Below is from https://www.kqlsearch.com/
```
let OfficeHomeSessionIds = 
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where ApplicationId == "4765445b-32c6-49b0-83e6-1d93765276ca" //OfficeHome application 
| where ClientAppUsed == "Browser" 
| where LogonType has "interactiveUser" 
| summarize arg_min(Timestamp, Country) by SessionId;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ApplicationId != "4765445b-32c6-49b0-83e6-1d93765276ca"
| where ClientAppUsed == "Browser" 
| project OtherTimestamp = Timestamp, Application, ApplicationId, AccountObjectId, AccountDisplayName, OtherCountry = Country, SessionId
| join OfficeHomeSessionIds on SessionId
| where OtherTimestamp > Timestamp and OtherCountry != Country
```
```
union SigninLogs , AADNonInteractiveUserSignInLogs
| where isnotempty(UserAgent)//| extend UserAgent = replace_string(UserAgent,";","")| where ResultType == "0"| extend UserAgentDetail = todynamic(parse_user_agent(UserAgent, dynamic(["browser","os","device"])))| extend OS = strcat(parse_json(tostring(UserAgentDetail.OperatingSystem)).Family," ",parse_json(tostring(UserAgentDetail.OperatingSystem)).MajorVersion,parse_json(tostring(UserAgentDetail. OperatingSystem)).MinorVersion)| extend UserAgentDetail = todynamic(parse_user_agent(UserAgent, "browser"))| extend UserAgentFamily = tostring(parse_json(tostring(UserAgentDetail.Browser)).Family)| extend UserAgentMajorVersion = toint(parse_json(tostring(UserAgentDetail.Browser)).MajorVersion)| extend UserAgentMinorVersion = toint(parse_json(tostring(UserAgentDetail.Browser)).MinorVersion)| where isnotempty(UserAgentMajorVersion)| extend UserAgentMinorVersion == iff(isempty(UserAgentMinorVersion),0,UserAgentMinorVersion)| summarize Count=count() by UserAgentFamily, UserAgentMajorVersion, UserAgentMinorVersion, OS| sort by Count
```
Slide 18: CAE

https://cloudbrothers.info/en/continuous-access-evaluation/

https://openid.net/specs/openid-sse-framework-1_0-01.html

Slide 19: Banned passwords

Tools
https://github.com/jkerai1/AzurePasswordProtectionCalculator
https://github.com/jkerai1/GeneratePasswordListFromWebsite


Sites:
https://exposed.lol/ (free)
https://leakpeek.com/
intelx.io
https://www.hudsonrock.com/
https://leakcheck.io/


Slide 20: PIM

https://jeffreyappel.nl/protect-against-aitm-mfa-phishing-attacks-using-microsoft-technology/
https://www.linkedin.com/posts/jay-kerai-cyber_entra-aitm-token-activity-7233084655942410240-e5zO

Slide 23: Attacker Controls the Proxy

https://github.com/nicolonsky/AzureAiTMFunction 

Slide 24-28: Canary Token

https://didsomeoneclone.me/
https://www.linkedin.com/pulse/punishing-aitms-using-css-flask-jay-kerai-ffrhe/


Slide 31: FIDO

https://www.w3.org/TR/webauthn/#dictdef-tokenbinding
https://www.rfc-editor.org/rfc/rfc8471
https://www.silverfort.com/blog/using-mitm-to-bypass-fido2/

Slide 32-33: FIDO quirks
https://www.linkedin.com/pulse/passwordlessphishing-resistant-considerations-entra-jay-kerai-zh6nc
https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/update-mgpolicyauthorizationpolicy?view=graph-powershell-1.0#-allowedtousesspr

Slide 34: PRT
https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token

Slide 35: TPM/PRT

TPM Attest: https://youtu.be/j0D3So1q-IA?t=554
https://call4cloud.nl/2024/07/istpmattested-enrollment-attestation/
https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/ 


Slide 37: CAE Demo

https://learn.microsoft.com/en-us/microsoft-365/enterprise/o365-data-locations?view=o365-worldwide

Slide 38: Conditional Access: Lock Down MFA registration/ Device Enrolment

https://timmyit.com/2022/11/08/block-linux-enrollment-into-microsoft-intune-with-conditional-access/

Can Restrict Fido keys with AAGUIDs. Use passkey explorer https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/?combined 

https://github.com/RedByte1337/GraphSpy - GraphSpy is popular tool for attackers to add MFA  


Slide 41: TLD Blocking

https://github.com/jkerai1/TLD-TABL-Block 
https://jeffreyappel.nl/block-gtld-zip-fqdn-domains-with-windows-firewall-and-defender-for-endpoint/#:~:text=With%20the%20use%20of%20Defender  

Slide 42: Typosquat

https://github.com/jkerai1/DNSTwistToMDEIOC  

KQL:
```
DeviceEvents
| where (ActionType == "SmartScreenUrlWarning" and AdditionalFields.Experience == "CustomBlockList") or (AdditionalFields.ResponseCategory == "CustomBlockList" and ActionType == "ExploitGuardNetworkProtectionBlocked")
| join kind=leftouter DeviceFileCertificateInfo on SHA1
| join kind=leftouter IdentityInfo on $left.InitiatingProcessAccountUpn == $right.AccountUPN
| summarize by FileName, RemoteUrl,DeviceName, Signer, InitiatingProcessAccountUpn, InitiatingProcessFileName, SHA1,TimeGenerated, InitiatingProcessVersionInfoProductName, JobTitle
```
Slide 43: DNS OSINT

https://aadinternals.com/osint/  


Slide 44: onmicrosoft  
https://c7solutions.com/2024/04/blocking-onmicrosoft-com-emails-in-exchange-online-protection  

Slide 45: Teams

https://labs.jumpsec.com/advisory-idor-in-microsoft-teams-allows-for-external-tenants-to-introduce-malware/  
Novel take on Webhook phishing: https://www.blackhillsinfosec.com/wishing-webhook-phishing-in-teams) 

Slide 46: MFA Boundary
https://github.com/jkerai1/SoftwareCertificates

Slide 47: Misc

browser passwords: https://www.linkedin.com/pulse/stealing-passwords-defender-endpoint-jay-kerai/
Netskope query:
```
let NetskopeCloudflareWorkers = externaldata(Url: string)[@"https://raw.githubusercontent.com/netskopeoss/NetskopeThreatLabsIOCs/main/Phishing/CloudflareWorkers/IOCs/README.md"] with (format="csv", ignoreFirstRecord=True);let CloudFlareWorkers = NetskopeCloudflareWorkers| where Url startswith "hxxp"| extend domain = split(Url,'/')| extend RemoteUrl = replace_string(strcat(domain[1],domain[2]),'[.]','.') //remove defang from externaldata| distinct RemoteUrl; //calling RemoteUrl makes doing joins easier 😉 DeviceNetworkEvents| where RemoteUrl in (CloudFlareWorkers) //example, use as you please
```

Block Cloudflare domain post: https://www.linkedin.com/posts/jay-kerai-cyber_aitm-cloudflare-workers-activity-7225926416226263040-wCWW

link shorteners (biolinky[.]co, bit[.]ly, drp[.]li)

Slide 48: Responding to AITM

https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Azure%20Active%20Directory/PotentialAiTMPhishing.md

Slide 49: Responding (2)

https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/non-interactive-logins-minimizing-the-blind-spot/ba-p/2287932

PS command:

Get-CASMailbox | Set-CASMailbox -OWAEnabled $false

