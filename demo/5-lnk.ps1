$r = $PSScriptRoot
$s = "$PSScriptRoot\powerMyCalc.lnk"
$l = "C:\Users\Public\Downloads\powerMyCalc.lnk"
$p = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

if (Test-Path $l) {
	rm $l -Force
}

Start-Process "$r\..\iEDR.exe" -Args "-a $l"
Sleep -Milliseconds 100 # no race cond, not doing a global mutex in iEDR
Start-Process "$r\..\iEDR.exe" -Args "-a $p"

$_= Read-Host "Wait for iEDR startup..."

cp $s $l
Write-Host "Written to $l"
Read-Host "Press ENTER to start $l"
Invoke-Item $l
