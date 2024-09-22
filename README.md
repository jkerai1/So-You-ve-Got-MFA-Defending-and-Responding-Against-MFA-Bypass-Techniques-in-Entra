# So-You-ve-Got-MFA-Defending-and-Responding-Against-MFA-Bypass-Techniques-in-Entra

This talk was given as part of https://www.meetup.com/m365sandcug/events/302644214 and serves as a much needed update to my [earlier article](https://www.linkedin.com/posts/jay-kerai-cyber_devfender-entra-token-activity-7122902992873287681-P03M?utm_source=share)

My intention is create a more formal writeup based on the content presented.

The videos have been stripped out for file size and replaced with public referenced videos instead.

Shoutout to anyone who's content I have referenced/featured! They were really helpful for confirming my knowledge or teaching me new things :D


# References 

__Slide 3: How to bypass MFA?__

https://github.com/kgretzky/evilginx2  
https://github.com/drk1wi/Modlishka

Smartscreen/Exploit Guard KQL:
```
DeviceEvents
| where ActionType == "SmartScreenUrlWarning" or ActionType == "ExploitGuardNetworkProtectionBlocked"
```
Browser history/artifacts: https://www.linkedin.com/pulse/stealing-passwords-defender-endpoint-jay-kerai  

Attacker can Block outlook protection IPs in evilginx to prevent MDO detonation  

__Slide 4:__
Merill Fernado Demo: https://www.youtube.com/watch?v=tI1bdVohOK8

__Slide 6: Simplyfing the attack__    

https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/

__Slide 8:__  

host locally: https://janbakker.tech/running-evilginx-3-0-on-windows/

__Slide 12: Conditional Access: Sign-in Risk (Identity Protection)__  

https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions#sign-in-risk  

__Slide 13: On the same note…Idle Session Time Out__  

https://learn.microsoft.com/en-us/microsoft-365/admin/manage/idle-session-timeout-web-apps?view=o365-worldwide#details-about-idle-session-timeout

__Slide 15: Conditional Access: Block Certain Device Platforms/User agents__  

Queries:

Browser Parser - useful for adding to hunting queries:
```
union SigninLogs , AADNonInteractiveUserSignInLogs
| where isnotempty(UserAgent)
//| extend UserAgent = replace_string(UserAgent,";","")
|where ResultType == "0"| extend UserAgentDetail = todynamic(parse_user_agent(UserAgent, dynamic(["browser","os","device"])))
| extend OS = strcat(parse_json(tostring(UserAgentDetail.OperatingSystem)).Family," ",parse_json(tostring(UserAgentDetail.OperatingSystem)).MajorVersion,parse_json(tostring(UserAgentDetail. OperatingSystem)).MinorVersion)
| extend UserAgentFamily = tostring(parse_json(tostring(UserAgentDetail.Browser)).Family)
| extend UserAgentMajorVersion = toint(parse_json(tostring(UserAgentDetail.Browser)).MajorVersion)
| extend UserAgentMinorVersion = toint(parse_json(tostring(UserAgentDetail.Browser)).MinorVersion)
| where isnotempty(UserAgentMajorVersion)
| extend UserAgentMinorVersion == iff(isempty(UserAgentMinorVersion),0,UserAgentMinorVersion)
| summarize Count=count() by UserAgentFamily, UserAgentMajorVersion, UserAgentMinorVersion, OS
| sort by Count
```

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

__Slide 18: CAE__  

https://cloudbrothers.info/en/continuous-access-evaluation/

https://openid.net/specs/openid-sse-framework-1_0-01.html

__Slide 19: Banned passwords__  

Tools
https://github.com/jkerai1/AzurePasswordProtectionCalculator
https://github.com/jkerai1/GeneratePasswordListFromWebsite


Sites:  
[https://exposed.lol/](https://exposed.lol/) (free)  
[https://leakpeek.com/  ](https://leakpeek.com/)
[intelx.io  ](https://intelx.io/)  
[https://www.hudsonrock.com/  ](https://www.hudsonrock.com/)  
[https://leakcheck.io/  ](https://leakcheck.io/)


__Slide 20: PIM__  

https://jeffreyappel.nl/protect-against-aitm-mfa-phishing-attacks-using-microsoft-technology/  
https://www.linkedin.com/posts/jay-kerai-cyber_entra-aitm-token-activity-7233084655942410240-e5zO

__Slide 23: Attacker Controls the Proxy__  

https://github.com/nicolonsky/AzureAiTMFunction 

__Slide 24-28: Canary Token__  

https://didsomeoneclone.me/  
https://www.linkedin.com/pulse/punishing-aitms-using-css-flask-jay-kerai-ffrhe/


__Slide 31: FIDO__  

https://www.w3.org/TR/webauthn/#dictdef-tokenbinding  
https://www.rfc-editor.org/rfc/rfc8471  
https://www.silverfort.com/blog/using-mitm-to-bypass-fido2/  

__Slide 32-33: FIDO quirks__  
https://www.linkedin.com/pulse/passwordlessphishing-resistant-considerations-entra-jay-kerai-zh6nc  
https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/update-mgpolicyauthorizationpolicy?view=graph-powershell-1.0#-allowedtousesspr  

__Slide 34: PRT__  
https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token  

__Slide 35: TPM/PRT__  

TPM Attest: https://youtu.be/j0D3So1q-IA?t=554  
https://call4cloud.nl/2024/07/istpmattested-enrollment-attestation/  
https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/   


__Slide 37: CAE Demo__  

https://learn.microsoft.com/en-us/microsoft-365/enterprise/o365-data-locations?view=o365-worldwide  

__Slide 38: Conditional Access: Lock Down MFA registration/ Device Enrolment__  

https://timmyit.com/2022/11/08/block-linux-enrollment-into-microsoft-intune-with-conditional-access/  

Can Restrict Fido keys with AAGUIDs. Use passkey explorer https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/?combined  

https://github.com/RedByte1337/GraphSpy - GraphSpy is popular tool for attackers to add MFA  


__Slide 41: TLD Blocking__  

https://github.com/jkerai1/TLD-TABL-Block  
https://jeffreyappel.nl/block-gtld-zip-fqdn-domains-with-windows-firewall-and-defender-for-endpoint/#:~:text=With%20the%20use%20of%20Defender  

__Slide 42: Typosquat__  

https://github.com/jkerai1/DNSTwistToMDEIOC  

KQL:
```
DeviceEvents
| where (ActionType == "SmartScreenUrlWarning" and AdditionalFields.Experience == "CustomBlockList") or (AdditionalFields.ResponseCategory == "CustomBlockList" and ActionType == "ExploitGuardNetworkProtectionBlocked")
| join kind=leftouter DeviceFileCertificateInfo on SHA1
| join kind=leftouter IdentityInfo on $left.InitiatingProcessAccountUpn == $right.AccountUPN
| summarize by FileName, RemoteUrl,DeviceName, Signer, InitiatingProcessAccountUpn, InitiatingProcessFileName, SHA1,TimeGenerated, InitiatingProcessVersionInfoProductName, JobTitle
```
__Slide 43: DNS OSINT__  

https://aadinternals.com/osint/  


__Slide 44: onmicrosoft__    
https://c7solutions.com/2024/04/blocking-onmicrosoft-com-emails-in-exchange-online-protection  

__Slide 45: Teams__  

https://labs.jumpsec.com/advisory-idor-in-microsoft-teams-allows-for-external-tenants-to-introduce-malware/  
Novel take on Webhook phishing: https://www.blackhillsinfosec.com/wishing-webhook-phishing-in-teams   

Ideally keep all webhooks required in backend  

__Slide 46: MFA Boundary__  
https://github.com/jkerai1/SoftwareCertificates

__Slide 47: Misc__  

browser passwords: https://www.linkedin.com/pulse/stealing-passwords-defender-endpoint-jay-kerai/  
Netskope query:
```
let NetskopeCloudflareWorkers = externaldata(Url: string)[@"https://raw.githubusercontent.com/netskopeoss/NetskopeThreatLabsIOCs/main/Phishing/CloudflareWorkers/IOCs/README.md"] with (format="csv", ignoreFirstRecord=True);
let CloudFlareWorkers = NetskopeCloudflareWorkers
| where Url startswith "hxxp"
| extend domain = split(Url,'/')
| extend RemoteUrl = replace_string(strcat(domain[1],domain[2]),'[.]','.') //remove defang from externaldata| distinct RemoteUrl; //calling RemoteUrl makes doing joins easier
DeviceNetworkEvents
| where RemoteUrl in (CloudFlareWorkers) //example, use as you please
```

Block Cloudflare domain post: https://www.linkedin.com/posts/jay-kerai-cyber_aitm-cloudflare-workers-activity-7225926416226263040-wCWW

link shorteners (biolinky[.]co, bit[.]ly, drp[.]li) 
https://hackingblogs.com/hackers-use-url-shortner-to-hide-malicious-links-and-redirect-victims-to-phishing-pages/  

__Slide 48: Responding to AITM__  

https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Azure%20Active%20Directory/PotentialAiTMPhishing.md  

__Slide 49: Responding (2)__  

https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/non-interactive-logins-minimizing-the-blind-spot/ba-p/2287932  
https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/  

PS command for disabling OWA: Get-CASMailbox | Set-CASMailbox -OWAEnabled $false

__Misc__:  

__FOCI query Checking:__    
```
let FOCI = externaldata(ClientID: string, Application: string)[@"https://raw.githubusercontent.com/secureworks/family-of-client-ids-research/main/known-foci-clients.csv"] with (format="csv", ignoreFirstRecord=true);
union SigninLogs,AADNonInteractiveUserSignInLogs
| join kind=leftouter FOCI on $left.AppId == $right.ClientID //Everything from left and only matching from right
| extend isFOCI = iff(isnotempty(ClientID), bool(1), bool(0)) //yield true if a join was possible between records of the two tables
| project-away ClientID
```

This Came out after my talk was delivered but is a comprehensive resource on AiTMs  

https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/Adversary-in-the-Middle.md


__Look for Subdomains impersonating Microsoft__  

```
let MSFT_Domains = externaldata(Url:string)[@"https://raw.githubusercontent.com/HotCakeX/MicrosoftDomains/main/Microsoft%20Domains.txt"] with (format="csv");
DeviceNetworkEvents 
| where isnotempty(RemoteUrl) //Below is Clean Up - alternatively use a function 
| extend Url = replace_string(RemoteUrl,'http://','')
| extend Url = split(replace_string(Url,'https://',''),'/')[0]
| extend Url = split(Url,':')[0] //remove Ports
| extend Domain_split= split(Url,'.') //Split Out
| where Domain_split[-1] != "microsoft" //Microsoft TLD is not of interest here
| where strcat(Domain_split[-2],'.',Domain_split[-1]) !in (MSFT_Domains) //Microsoft domains, decent way to cut noise but not perfect will not catch function apps/sharepoints being abused
| where Url has "microsoft"
| summarize by tostring(Domain_split),tostring(Url), RemoteUrl

```

__Evilginx Pro Showcase__ https://www.youtube.com/watch?v=eBKq1_L_tFE  
__MDA Session Hand-over Damage control__ https://www.linkedin.com/posts/jay-kerai-cyber_aitms-entra-byod-activity-7243574769369976832-Zpeb  
