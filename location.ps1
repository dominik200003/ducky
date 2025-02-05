# Logs to extract from server
$logArray = Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 } | Select-Object -ExpandProperty LogName

# Grabs the server name to append to the log file extraction
$servername = $env:computername

# Provide the path with ending "\" to store the log file extraction.
$destinationpath = "C:\tmp\WindowsEventLogs\events"
$compressdestpath = "C:\tmp\WindowsEventLogs\"

# Checks the last character of the destination path.  If it does not end in '\' it adds one.
if ($destinationpath -notmatch '.+?\\$') {
    $destinationpath += '\'
}

# If the destination path does not exist it will create it
if (!(Test-Path -Path $destinationpath)) {
    New-Item -ItemType directory -Path $destinationpath
}

# Get the current date in YearMonthDay format
$logdate = Get-Date -format yyyyMMddHHmm

# Define log info file
$logInfoFile = $destinationpath + $servername + "-LogInfo-" + $logdate + ".txt"

# Start Process Timer
$StopWatch = [system.diagnostics.stopwatch]::startNew()

# Start Code
Clear-Host

"Server Name: $servername" | Out-File -FilePath $logInfoFile -Append
"Extraction Time: $(Get-Date)" | Out-File -FilePath $logInfoFile -Append
"----------------------------------------" | Out-File -FilePath $logInfoFile -Append

Foreach($log in $logArray) {
    # Biztonságos fájlnév generálása
    $safeLogName = $log -replace '[\/]', '_'
    $destination = $destinationpath + $servername + "-" + $safeLogName + "-" + $logdate + ".evtx"

    Write-Host "Extracting the $log file now."

    # Extract each log file listed in $logArray from the local server.
    wevtutil epl $log $destination

    # Get log file size
    $logSize = (Get-Item $destination).Length / 1KB
    $logSize = "{0:N2}" -f $logSize + " KB"

    # Get the oldest event timestamp
    $oldestEvent = Get-WinEvent -LogName $log -MaxEvents 1 | Select-Object -ExpandProperty TimeCreated

    # Get maximum log file size before rotation
    $logMaxSize = (Get-WinEvent -ListLog $log).MaximumSizeInBytes / 1KB
    $logMaxSize = "{0:N2}" -f $logMaxSize + " KB"

    # Get total number of entries
    $logEntries = (Get-WinEvent -ListLog $log).RecordCount

    # Write log info to file
    "Log Name: $log" | Out-File -FilePath $logInfoFile -Append
    "Size: $logSize" | Out-File -FilePath $logInfoFile -Append
    "Oldest Entry: $oldestEvent" | Out-File -FilePath $logInfoFile -Append
    "Max Log Size Before Rotation: $logMaxSize" | Out-File -FilePath $logInfoFile -Append
    "Total Entries: $logEntries" | Out-File -FilePath $logInfoFile -Append
    "----------------------------------------" | Out-File -FilePath $logInfoFile -Append
}

# Ellenőrizd, hogy a célmappa létezik, ha nem, hozd létre a tömörítéshez
if (!(Test-Path -Path $compressdestpath)) {
    New-Item -ItemType directory -Path $compressdestpath
}

# Tömörítés a fájlokba
$zipFilePath = Join-Path -Path $compressdestpath -ChildPath ($servername + "-LogInfo-" + $logdate + ".zip")
Compress-Archive -Path $destinationpath\* -CompressionLevel Fastest -DestinationPath $zipFilePath

# Define variables
$seafileUrl = "https://drive.itsecarea.eu"
$username = "it@auto.hu"
$folderId = "ce6d40ba-2f52-4a3e-91c4-82aeb7d3f726"
$filePath = "C:\tmp\WindowsEventLogs\*.zip"

# Embedded encryption key (32-byte key for AES encryption)
$key = "190 150 175 255 214 208 21 145 151 12 25 215 191 142 88 214 198 6 235 201 237 195 188 102 143 160 78 206 105 206 178 47"
$keyBytes = $key -split ' ' | ForEach-Object { [byte]$_ }

# Hashed password (replace with your generated hashed password)
$hashedPassword = "76492d1116743f0423413b16050a5345MgB8AGcAcwBiAHkAOABUAGIAZgB4ADAAWgBJAHEAQgB2AGQALwBlADUAcQBPAFEAPQA9AHwAYQA1ADQAYgA4AGYAYwBjAGQANQA5ADkANwA3ADkANwA4A
GEAMwBiADEAZQAzAGMANwAwAGYAYQBiADMANwA0ADcAMgA3ADIANAAxAGEANgBhAGEANgBmADYANgAwAGMANABjAGMAOAA3ADIAMwAwAGMANQA3ADcAOABhAGYAZAAwAGEAYwBkADEANQBkADMAZQ
A2AGUANQAyADAAOQAyAGYAZAAxAGEAMgBlADMAZgBiAGEAOQBlADQAZgAzAGUAZABkADkAYQBhAGUAMAAzAGIANwBiAGUAZQAzAGIAZAA3ADAANQA4ADYAMgAzADcANABlADUAYQAxADEANQBjAA=
="

# Function to sanitize file name (not path)
function Sanitize-FileName {
    param (
        [string]$fileName
    )
    # Replace illegal characters with an underscore (_)
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $sanitizedFileName = $fileName -replace "[$invalidChars]", "_"
    return $sanitizedFileName
}

# Step 1: Convert the hashed password to a secure string and retrieve the plain-text password
try {
    $securePassword = ConvertTo-SecureString -String $hashedPassword -Key $keyBytes
    $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
    $password = $credential.GetNetworkCredential().Password
} catch {
    Write-Error "Failed to decrypt the hashed password: $_"
    exit
}

# Step 2: Get the authentication token
$authUrl = "$seafileUrl/api2/auth-token/"
$authBody = @{
    username = $username
    password = $password
} | ConvertTo-Json

try {
    $authResponse = Invoke-RestMethod -Uri $authUrl -Method Post -Body $authBody -ContentType "application/json"
    $token = $authResponse.token

    if (-not $token) {
        Write-Error "Failed to retrieve authentication token."
        exit
    }
} catch {
    Write-Error "Failed to authenticate with Seafile API: $_"
    exit
}

# Step 3: Get the upload link
$uploadUrl = "$seafileUrl/api2/repos/$folderId/upload-link/"
$headers = @{
    Authorization = "Token $token"
}

try {
    $uploadLinkResponse = Invoke-RestMethod -Uri $uploadUrl -Method Get -Headers $headers
    $uploadLink = $uploadLinkResponse

    if (-not $uploadLink) {
        Write-Error "Failed to retrieve upload link."
        exit
    }
} catch {
    Write-Error "Failed to retrieve upload link: $_"
    exit
}

# Step 4: Upload all .zip files in the specified directory
$files = Get-ChildItem -Path $filePath

if ($files.Count -eq 0) {
    Write-Output "No .zip files found in the specified directory."
    exit
}

foreach ($file in $files) {
    $fileFullPath = $file.FullName
    $fileName = $file.Name

    # Sanitize the file name (not the path)
    $sanitizedFileName = Sanitize-FileName -fileName $fileName

    # Check if the file is accessible
    if (-not (Test-Path -Path $fileFullPath)) {
        Write-Error "File not found or inaccessible: $fileFullPath"
        continue
    }

    # Check file size (optional: ensure it's within Seafile's limits)
    $fileSize = (Get-Item -Path $fileFullPath).Length / 1MB  # Size in MB
    if ($fileSize -gt 100) {  # Example: Limit of 100 MB
        Write-Error "File size exceeds limit (100 MB): $fileFullPath"
        continue
    }

    # Prepare the multipart form data
    $boundary = [System.Guid]::NewGuid().ToString()
    $headers["Content-Type"] = "multipart/form-data; boundary=$boundary"

    $bodyLines = @(
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$sanitizedFileName`"",
        "Content-Type: application/octet-stream",
        "",
        [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($fileFullPath)),
        "--$boundary",
        "Content-Disposition: form-data; name=`"parent_dir`"",
        "",
        "/",  # Specify the parent directory in the Seafile repository
        "--$boundary",
        "Content-Disposition: form-data; name=`"replace`"",
        "",
        "1",  # Replace existing files
        "--$boundary--"
    )
    $body = $bodyLines -join "`r`n"

    # Upload the file
    try {
        $uploadResponse = Invoke-RestMethod -Uri $uploadLink -Method Post -Headers $headers -Body $body
        Write-Output "File uploaded successfully: $sanitizedFileName"
    } catch {
        Write-Error "Failed to upload file: $sanitizedFileName. Error: $_"
    }
}
