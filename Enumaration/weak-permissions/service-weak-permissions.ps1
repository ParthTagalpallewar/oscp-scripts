$DangerousServiceRights = @('ChangeConfig','WriteDac','WriteOwner','GenericWrite','GenericAll','AllAccess')
$DangerousFileRights = @('FullControl','Modify','Write','WriteData','CreateFiles','AppendData','WriteExtendedAttributes','WriteAttributes','TakeOwnership','ChangePermissions')
$DangerousRegistryRights = @('FullControl','SetValue','CreateSubKey','WriteKey','TakeOwnership','ChangePermissions')

function Get-CurrentUserIdentities {
    $identities = @()
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $identities += $currentUser.Name.ToLower()
    foreach ($group in $currentUser.Groups) {
        try { $identities += $group.Translate([System.Security.Principal.NTAccount]).Value.ToLower() } catch {}
    }
    return $identities | Sort-Object -Unique
}

function Test-AceMatchesUser {
    param([string]$AceIdentity, [string[]]$UserIdentities)
    $normalized = $AceIdentity.ToLower()
    foreach ($id in $UserIdentities) {
        if ($normalized -eq $id -or $normalized -like "*\$($id.Split('\')[-1])") { return $true }
    }
    return $false
}

function Check-ServiceObjectPermissions {
    param([string[]]$UserIdentities)
    $results = @()
    $services = Get-Service | Select-Object -ExpandProperty Name
    foreach ($svcName in $services) {
        try {
            $sddlOutput = & sc.exe sdshow $svcName 2>$null
            if (-not $sddlOutput) { continue }
            $sddlString = ($sddlOutput | Where-Object { $_ -match 'D:' }) -join ''
            if (-not $sddlString) { continue }
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddlString)
            foreach ($ace in $sd.DiscretionaryAcl) {
                try { $account = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $account = $ace.SecurityIdentifier.Value }
                if (-not (Test-AceMatchesUser -AceIdentity $account -UserIdentities $UserIdentities)) { continue }
                $mask = $ace.AccessMask
                $perms = @()
                if ($mask -band 0x000F01FF) { $perms += 'QueryConfig' }
                if ($mask -band 0x00000002) { $perms += 'ChangeConfig' }
                if ($mask -band 0x00000004) { $perms += 'QueryStatus' }
                if ($mask -band 0x00000008) { $perms += 'EnumerateDependents' }
                if ($mask -band 0x00000010) { $perms += 'Start' }
                if ($mask -band 0x00000020) { $perms += 'Stop' }
                if ($mask -band 0x00000040) { $perms += 'PauseContinue' }
                if ($mask -band 0x00000080) { $perms += 'Interrogate' }
                if ($mask -band 0x00000100) { $perms += 'UserDefinedControl' }
                if ($mask -band 0x00010000) { $perms += 'Delete' }
                if ($mask -band 0x00020000) { $perms += 'ReadControl' }
                if ($mask -band 0x00040000) { $perms += 'WriteDac' }
                if ($mask -band 0x00080000) { $perms += 'WriteOwner' }
                if ($mask -band 0x10000000) { $perms += 'GenericAll' }
                if ($mask -band 0x40000000) { $perms += 'GenericWrite' }
                if ($mask -band 0x02000000) { $perms += 'AllAccess' }
                $dangerous = $perms | Where-Object { $DangerousServiceRights -contains $_ }
                if ($dangerous) {
                    $results += [PSCustomObject]@{ ServiceName=$svcName; CheckType='Service Object ACL'; Identity=$account; Permissions=($dangerous -join ', '); AllPerms=($perms -join ', '); Detail="Dangerous rights on service object itself" }
                }
            }
        } catch {}
    }
    return $results
}

function Check-ServiceBinaryPermissions {
    param([string[]]$UserIdentities)
    $results = @()
    $services = Get-WmiObject Win32_Service | Select-Object Name, PathName, DisplayName
    foreach ($svc in $services) {
        if (-not $svc.PathName) { continue }
        $rawPath = $svc.PathName.Trim()
        if ($rawPath -match '^"([^"]+)"') { $exePath = $Matches[1] }
        elseif ($rawPath -match '^([^\s]+\.exe)') { $exePath = $Matches[1] }
        else { $exePath = $rawPath.Split(' ')[0] }
        if (-not (Test-Path $exePath -ErrorAction SilentlyContinue)) { continue }
        try {
            $acl = Get-Acl -Path $exePath -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                if (-not (Test-AceMatchesUser -AceIdentity $identity -UserIdentities $UserIdentities)) { continue }
                $rights = $ace.FileSystemRights.ToString()
                $dangerous = $DangerousFileRights | Where-Object { $rights -match $_ }
                if ($dangerous) {
                    $results += [PSCustomObject]@{ ServiceName=$svc.Name; CheckType='Service Binary ACL'; Identity=$identity; Permissions=($dangerous -join ', '); AllPerms=$rights; Detail="Weak permissions on binary: $exePath" }
                }
            }
        } catch {}
    }
    return $results
}

function Check-UnquotedServicePaths {
    param([string[]]$UserIdentities)
    $results = @()
    $services = Get-WmiObject Win32_Service | Select-Object Name, PathName, StartMode
    foreach ($svc in $services) {
        if (-not $svc.PathName) { continue }
        $path = $svc.PathName.Trim()

        # Skip already-quoted paths
        if ($path.StartsWith('"')) { continue }

        # FILTER 1: Skip paths that live under C:\Windows\System32 (trusted system location)
        if ($path -match '^[a-zA-Z]:\\[Ww][Ii][Nn][Dd][Oo][Ww][Ss]\\[Ss][Yy][Ss][Tt][Ee][Mm]32\\') { continue }

        # FILTER 2: Path must contain a space BEFORE the .exe (i.e. inside the directory/file name)
        # e.g. "C:\Program Files\app\svc.exe"  -> has space before .exe  -> INCLUDE
        # e.g. "C:\Windows\svc.exe -arg value" -> space is only in args  -> EXCLUDE
        $exePart = if ($path -match '^(.+\.exe)') { $Matches[1] } else { $path.Split(' ')[0] }
        if ($exePart -notmatch ' ') { continue }
        $parts = $exePart.Split('\')
        $exploitablePaths = @()
        for ($i = 1; $i -lt $parts.Count - 1; $i++) {
            $partialPath = ($parts[0..$i] -join '\')
            $parentDir = Split-Path $partialPath -Parent
            if (-not $parentDir -or -not (Test-Path $parentDir -ErrorAction SilentlyContinue)) { continue }
            try {
                $acl = Get-Acl -Path $parentDir -ErrorAction Stop
                foreach ($ace in $acl.Access) {
                    $identity = $ace.IdentityReference.Value
                    if (-not (Test-AceMatchesUser -AceIdentity $identity -UserIdentities $UserIdentities)) { continue }
                    $rights = $ace.FileSystemRights.ToString()
                    $dangerous = $DangerousFileRights | Where-Object { $rights -match $_ }
                    if ($dangerous) { $exploitablePaths += "$parentDir [$identity : $($dangerous -join ',')]" }
                }
            } catch {}
        }
        if ($exploitablePaths) {
            $results += [PSCustomObject]@{ ServiceName=$svc.Name; CheckType='Unquoted Service Path'; Identity=(($exploitablePaths | ForEach-Object { ($_ -split '\[')[1].TrimEnd(']') }) -join ' | '); Permissions='Write/Modify on parent dir'; AllPerms=$path; Detail="Unquoted path. Writable dirs: $($exploitablePaths -join ' | ')" }
        } else {
            $results += [PSCustomObject]@{ ServiceName=$svc.Name; CheckType='Unquoted Service Path (Info)'; Identity='N/A'; Permissions='None detected for current user'; AllPerms=$path; Detail="Unquoted path but no writable dir found for current user" }
        }
    }
    return $results
}

function Check-ServiceRegistryPermissions {
    param([string[]]$UserIdentities)
    $results = @()
    $baseKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $serviceKeys = Get-ChildItem -Path $baseKey -ErrorAction SilentlyContinue
    foreach ($key in $serviceKeys) {
        try {
            $acl = Get-Acl -Path $key.PSPath -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                if (-not (Test-AceMatchesUser -AceIdentity $identity -UserIdentities $UserIdentities)) { continue }
                $rights = $ace.RegistryRights.ToString()
                $dangerous = $DangerousRegistryRights | Where-Object { $rights -match $_ }
                if ($dangerous) {
                    $results += [PSCustomObject]@{ ServiceName=$key.PSChildName; CheckType='Registry Key ACL'; Identity=$identity; Permissions=($dangerous -join ', '); AllPerms=$rights; Detail="Weak registry permissions on: $($key.PSPath)" }
                }
            }
        } catch {}
    }
    return $results
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "   Windows Service Weak Permission Checker" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$userIdentities = Get-CurrentUserIdentities

Write-Host "`n[*] Current User : " -NoNewline -ForegroundColor Yellow
Write-Host ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -ForegroundColor White
Write-Host "[*] Checking as  : " -NoNewline -ForegroundColor Yellow
Write-Host ($userIdentities -join ', ') -ForegroundColor Gray
Write-Host "`n[*] Running checks...`n" -ForegroundColor Yellow

$allResults = @()
Write-Host "[1/4] Checking Service Object ACLs..." -ForegroundColor DarkCyan
$allResults += Check-ServiceObjectPermissions -UserIdentities $userIdentities
Write-Host "[2/4] Checking Service Binary Permissions..." -ForegroundColor DarkCyan
$allResults += Check-ServiceBinaryPermissions -UserIdentities $userIdentities
Write-Host "[3/4] Checking Unquoted Service Paths..." -ForegroundColor DarkCyan
$allResults += Check-UnquotedServicePaths -UserIdentities $userIdentities
Write-Host "[4/4] Checking Service Registry Key Permissions..." -ForegroundColor DarkCyan
$allResults += Check-ServiceRegistryPermissions -UserIdentities $userIdentities

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "   RESULTS" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

if ($allResults.Count -eq 0) {
    Write-Host "[+] No weak permissions found for the current user." -ForegroundColor Green
} else {
    $dangerous = $allResults | Where-Object { $_.CheckType -notmatch '\(Info\)' }
    $info      = $allResults | Where-Object { $_.CheckType -match '\(Info\)' }

    if ($dangerous) {
        Write-Host "[ DANGEROUS FINDINGS ]" -ForegroundColor Red
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkRed
        foreach ($r in $dangerous) {
            Write-Host "`nService    : " -NoNewline -ForegroundColor White; Write-Host $r.ServiceName -ForegroundColor Yellow
            Write-Host "Check      : " -NoNewline -ForegroundColor White; Write-Host $r.CheckType -ForegroundColor Red
            Write-Host "Identity   : " -NoNewline -ForegroundColor White; Write-Host $r.Identity -ForegroundColor Cyan
            Write-Host "Dangerous  : " -NoNewline -ForegroundColor White; Write-Host $r.Permissions -ForegroundColor Red
            Write-Host "All Perms  : " -NoNewline -ForegroundColor White; Write-Host $r.AllPerms -ForegroundColor Gray
            Write-Host "Detail     : " -NoNewline -ForegroundColor White; Write-Host $r.Detail -ForegroundColor DarkYellow
        }
    }

    if ($info) {
        Write-Host "`n[ INFORMATIONAL - Unquoted Paths (no writable dir for current user) ]" -ForegroundColor DarkYellow
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkYellow
        foreach ($r in $info) {
            Write-Host "`nService    : " -NoNewline -ForegroundColor White; Write-Host $r.ServiceName -ForegroundColor Yellow
            Write-Host "Detail     : " -NoNewline -ForegroundColor White; Write-Host $r.Detail -ForegroundColor Gray
        }
    }

    Write-Host "`n`n============================================================" -ForegroundColor Cyan
    Write-Host "   SUMMARY TABLE (Dangerous Only)" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
    $dangerous | Select-Object ServiceName, CheckType, Identity, Permissions, Detail | Format-Table -AutoSize -Wrap

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csvPath = "$env:TEMP\ServiceWeakPerms_$timestamp.csv"
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Full results exported to: $csvPath" -ForegroundColor Green
}

Write-Host "`n[*] Scan complete.`n" -ForegroundColor Cyan