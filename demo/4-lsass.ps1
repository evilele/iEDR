$r = $PSScriptRoot
$s = "$PSScriptRoot\LsassRead\LsassRead.exe"
$p = "C:\Users\Public\Downloads\LsassRead.exe"

if (Test-Path $p) {
	rm $p -Force
}

Start-Process "$r\..\iEDR.exe" -Args "-a $p"

$_= Read-Host "Wait for iEDR startup..."

cp $s $p
Write-Host "Copied $s to $p"
Read-Host "Press ENTER to start $p"
Start-Process $p -NoNewWindow -Wait