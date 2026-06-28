$r = $PSScriptRoot
$d = "C:\Users\Public\Downloads"
$l = "$d\powerMyCalc.lnk"
$z = "$d\powerMyCalc.zip"
$p = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

@($l, $z) | % { if (Test-Path $_) {
	rm $_ -Force
}}

Start-Process "$r\..\iEDR.exe" -Args "-a $l"
Sleep -Milliseconds 100 # no race cond, not doing a global mutex in iEDR
Start-Process "$r\..\iEDR.exe" -Args "-a $z"
Sleep -Milliseconds 100 # no race cond, not doing a global mutex in iEDR
Start-Process "$r\..\iEDR.exe" -Args "-a $p"

$_= Read-Host "Wait for iEDR startup..."

Invoke-RestMethod "https://github.com/evilele/iEDR/raw/af234474f67c2869bd9989cbc5672fd203c82254/demo/powerMyCalc.zip" -OutFile $z
Write-Host "Downloaded $z"
Read-Host "Press ENTER to unzip"

Expand-Archive -Path $z -DestinationPath "$d\" # DestinationPath is the folder to extract the contained files to

Read-Host "Press ENTER to start $l"
Invoke-Item $l
