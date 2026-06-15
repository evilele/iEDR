$r = $PSScriptRoot
$s = "$PSScriptRoot\mimikatz.b64"
$p = "C:\Users\Public\Downloads\mimikatz.exe"

if (Test-Path $p) {
	rm $p -Force
}

Start-Process "$r\..\iEDR.exe" -Args "-a $p"

$_= Read-Host "Wait for iEDR startup..."

[IO.File]::WriteAllBytes($p, [Convert]::FromBase64String((Get-Content $s -Raw)))
Write-Host "Written to $p"
Read-Host "Press ENTER to start $p"
Start-Process $p -NoNewWindow -Wait
