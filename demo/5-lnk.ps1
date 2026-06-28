$r = $PSScriptRoot
$s = "$PSScriptRoot\powerMyCalc.lnk"
$p = "C:\Users\Public\Downloads\powerMyCalc.lnk"

if (Test-Path $p) {
	rm $p -Force
}

Start-Process "$r\..\iEDR.exe" -Args "-a $p"

$_= Read-Host "Wait for iEDR startup..."

cp $s $p
Write-Host "Written to $p"
Read-Host "Press ENTER to start $p"
Invoke-Item $p
