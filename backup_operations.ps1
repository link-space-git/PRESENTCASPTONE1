param(
    [string]$ParametersFile
)

# Read parameters from JSON file
$params = Get-Content $ParametersFile | ConvertFrom-Json

function Generate-Checksum {
    param(
        [string]$filePath
    )
    
    try {
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($filePath)
        
        $hash = $hasher.ComputeHash($stream)
        $stream.Close()
        
        return [System.BitConverter]::ToString($hash).Replace("-", "").ToLower()
    }
    catch {
        Write-Output "Warning: Could not generate checksum for $filePath"
        return $null
    }
}

function Compare-Folders {
    param(
        [string]$folder1,
        [string]$folder2
    )
    
    # Get all files from both folders
    $files1 = Get-ChildItem -Recurse -File $folder1
    $files2 = Get-ChildItem -Recurse -File $folder2
    
    # Create hashtables for quick lookup
    $fileTable1 = @{}
    $fileTable2 = @{}
    
    $files1 | ForEach-Object {
        $relativePath = $_.FullName.Substring($folder1.Length + 1)
        $fileTable1[$relativePath] = $_
    }
    
    $files2 | ForEach-Object {
        $relativePath = $_.FullName.Substring($folder2.Length + 1)
        $fileTable2[$relativePath] = $_
    }
    
    $allFiles = $fileTable1.Keys + $fileTable2.Keys | Select-Object -Unique
    $differences = 0
    
    foreach ($relativePath in $allFiles) {
        $file1 = $fileTable1[$relativePath]
        $file2 = $fileTable2[$relativePath]
        
        if ($null -eq $file1) {
            Write-Output "File missing in System: $relativePath"
            $differences++
            continue
        }
        
        if ($null -eq $file2) {
            Write-Output "File missing in Backup: $relativePath"
            $differences++
            continue
        }
        
        # Compare file sizes
        if ($file1.Length -ne $file2.Length) {
            Write-Output "DATABREACH DETECTED!!! Size mismatch: $relativePath ($($file1.Length) vs $($file2.Length) bytes)"
            $differences++
            continue
        }
        
        # Compare last write times (with 2 second tolerance)
        $timeDiff = [math]::Abs(($file1.LastWriteTime - $file2.LastWriteTime).TotalSeconds)
        if ($timeDiff -gt 2) {
            Write-Output "Warning: Modification time difference: $relativePath ($($file1.LastWriteTime) vs $($file2.LastWriteTime))"
        }
        
        # Compare file contents (checksum)
        $checksum1 = Generate-Checksum $file1.FullName
        $checksum2 = Generate-Checksum $file2.FullName
        
        if ($null -ne $checksum1 -and $null -ne $checksum2 -and $checksum1 -ne $checksum2) {
            Write-Output "DATABREACH DETECTED!!! Content mismatch: $relativePath"
            $differences++
        }
    }
    
    return $differences
}

try {
    switch ($params.operation) {
        "backup" {
            if (-not (Test-Path $params.source_dir)) {
                throw "Source directory does not exist: $($params.source_dir)"
            }
            
            if (Test-Path $params.destination_dir) {
                Remove-Item $params.destination_dir -Recurse -Force
            }
            
            Write-Output "Starting backup from $($params.source_dir) to $($params.destination_dir)"
            Copy-Item $params.source_dir $params.destination_dir -Recurse -Force
            Write-Output "Backup created successfully at $($params.destination_dir)"
        }
        
        "scan" {
            if (-not (Test-Path $params.system_dir)) {
                throw "System directory does not exist: $($params.system_dir)"
            }
            
            if (-not (Test-Path $params.backup_dir)) {
                throw "Backup directory does not exist: $($params.backup_dir)"
            }
            
            Write-Output "Starting scan between:"
            Write-Output "System: $($params.system_dir)"
            Write-Output "Backup: $($params.backup_dir)"
            Write-Output ""
            
            $diffCount = Compare-Folders $params.system_dir $params.backup_dir
            
            Write-Output ""
            if ($diffCount -eq 0) {
                Write-Output "Scan complete. No differences found between the directories."
            }
            else {
                Write-Output "DATABREACH DETECTED!!! Scan complete. Found $diffCount differences between the directories."
            }
        }
        
        "restore" {
            if (-not (Test-Path $params.backup_dir)) {
                throw "Backup directory does not exist: $($params.backup_dir)"
            }
            
            if (Test-Path $params.system_dir) {
                Write-Output "Removing existing system directory..."
                Remove-Item $params.system_dir -Recurse -Force -ErrorAction Stop
            }
            
            Write-Output "Restoring from backup..."
            Copy-Item $params.backup_dir $params.system_dir -Recurse -Force
            Write-Output "Restore successful! System restored from $($params.backup_dir)"
        }
        
        default {
            throw "Invalid operation specified: $($params.operation)"
        }
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}