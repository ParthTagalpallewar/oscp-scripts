# ACEs for files in NFSC volumes, in Master File Table.. 
# DACL can be query using Get-ACL

#output list of service which binaries, current user can change also output what permission current 
# user can have on same service. 

#example: service permission 
    #1. change config -> you can directly change path of binary which service can run.
    #2. Modify DACL -> modify permission.

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentGroups = $currentUser.Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }
$allIdentities = @($currentUser.Name) + $currentGroups

Get-WmiObject Win32_Service | ForEach-Object {
    $svcName = $_.Name
    $svcPath = $_.PathName
    $svcDisplayName = $_.DisplayName

    $cleanPath = $svcPath -replace '"', ''
    $cleanPath = ($cleanPath -split '\.exe')[0] + '.exe'
    $cleanPath = $cleanPath.Trim()

    if (Test-Path $cleanPath -ErrorAction SilentlyContinue) {
        $acl = Get-Acl $cleanPath -ErrorAction SilentlyContinue
        if ($acl) {
            $matchingAces = $acl.Access | Where-Object {
                $_.AccessControlType -eq "Allow" -and
                $_.FileSystemRights -match "Write|FullControl|Modify" -and
                ($allIdentities -contains $_.IdentityReference.Value)
            }

            if ($matchingAces) {

                Write-Host "======================================" -ForegroundColor Cyan
                Write-Host "ServiceName : $svcName"
                Write-Host "DisplayName : $svcDisplayName"
                Write-Host "BinaryPath  : $cleanPath"

                # --- Binary ACL ---
                Write-Host "  [BinaryACL]" -ForegroundColor Red
                $matchingAces | ForEach-Object {
                    Write-Host "    Identity : $($_.IdentityReference.Value)"
                    Write-Host "    Rights   : $($_.FileSystemRights)"
                    Write-Host ""
                }

                # --- Service Object ACL ---
                try {
                    $sddl = (sc.exe sdshow $svcName 2>$null) -join ""
                    if ($sddl -match "^D:") {
                        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
                        $matched = $sd.DiscretionaryAcl | Where-Object { $_.AceType -eq "AccessAllowed" } | ForEach-Object {
                            try { $identity = $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value }
                            catch { $identity = $_.SecurityIdentifier.Value }

                            if ($allIdentities -contains $identity) {
                                $mask = $_.AccessMask
                                $perms = @()
                                if ($mask -band 0x0001) { $perms += "QueryConfig" }
                                if ($mask -band 0x0002) { $perms += "ChangeConfig" }
                                if ($mask -band 0x0004) { $perms += "QueryStatus" }
                                if ($mask -band 0x0008) { $perms += "EnumDependents" }
                                if ($mask -band 0x0010) { $perms += "Start" }
                                if ($mask -band 0x0020) { $perms += "Stop" }
                                if ($mask -band 0x0040) { $perms += "PauseContinue" }
                                if ($mask -band 0x0080) { $perms += "Interrogate" }
                                if ($mask -band 0x0100) { $perms += "UserDefinedControl" }
                                if ($mask -band 0x00010000) { $perms += "Delete" }
                                if ($mask -band 0x00020000) { $perms += "ReadControl" }
                                if ($mask -band 0x00040000) { $perms += "WriteDACL" }
                                if ($mask -band 0x00080000) { $perms += "WriteOwner" }

                                [PSCustomObject]@{ Identity = $identity; Perms = $perms -join ", " }
                            }
                        }

                        if ($matched) {
                            Write-Host "  [ServiceACL]" -ForegroundColor Magenta
                            $matched | ForEach-Object {
                                Write-Host "    Identity : $($_.Identity)"
                                Write-Host "    Rights   : $($_.Perms)"
                                Write-Host ""
                            }
                        }
                    }
                } catch {}
            }
        }
    }
}
