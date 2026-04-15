Import-Module ActiveDirectory

function isNotSkippable {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [string]$id
  )
    # Principals to skip (built-in noise)
    $skipPrincipals = @(
        "S-1-5-32-548", # account operators
        "S-1-5-32-554", # pre-windows 2000 compatible access
        "S-1-5-32-561", # distributed COM users
        "ADND\Domain Admins",
        "ADND\Enterprise Admins",
        "ADND\Key Admins",
        "ADND\Enterprise Key Admins",
        "ADND\Enterprise Read-only Domain Controllers",
        "NT AUTHORITY\SELF",
        "NT AUTHORITY\SYSTEM",
        "NT AUTHORITY\Authenticated Users",
        "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS",
        "NT AUTHORITY\NETWORK SERVICE",
        "NT AUTHORITY\LOCAL SERVICE",
        "BUILTIN\Administrators",
        "BUILTIN\Account Operators",
        "BUILTIN\Server Operators",
        "BUILTIN\Print Operators",
        "BUILTIN\Backup Operators",
        "BUILTIN\Users",
        "BUILTIN\Pre-Windows 2000 Compatible Access",
        "Everyone",
        "CREATOR OWNER"
    )

    # Filter out built-in and noise principals from ACE inventory
    $BuiltInSidPrefixes = @(
        'S-1-5-32-',   # BUILTIN\* local groups (Account Operators, Server Operators, etc.)
        'S-1-5-18',    # Local System
        'S-1-5-19',    # Local Service
        'S-1-5-20',    # Network Service
        'S-1-5-11',    # Authenticated Users
        'S-1-5-10',    # Principal Self
        'S-1-5-4',     # Interactive
        'S-1-5-6',     # Service
        'S-1-5-7',     # Anonymous
        'S-1-5-9',     # Enterprise Domain Controllers
        'S-1-5-12',    # Restricted Code
        'S-1-5-15'     # This Organization
    )

    $BuiltInAccountNames = @(
        'NT AUTHORITY\*',
        'BUILTIN\*'
    )

    # Exclude if id starts with any built-in prefix
    if ($BuiltInSidPrefixes | Where-Object { $id -like "$_*" }) {
        return $false
    }

    # Exclude if id is NT AUTHORITY or BUILTIN
    if ($BuiltInAccountNames | Where-Object { $sid -like $_ }) {
        return $false
    }

    # Exclude some principals
    if ($skipPrincipals -contains $id) {
        return $false
    }

    # Otherwise keep it
    return $true
}

function Get-AdGuidMap {
    [CmdletBinding()]
    param()

    $root = Get-ADRootDSE
    $schemaNC = $root.schemaNamingContext
    $configNC = $root.configurationNamingContext

    # Final map: GUID → name
    $map = @{}

    # --- 1. Schema classes + attributes (schemaIDGUID) ---
    $schemaObjects = Get-ADObject -SearchBase $schemaNC `
                                  -LDAPFilter "(schemaIDGUID=*)" `
                                  -Properties lDAPDisplayName, schemaIDGUID

    foreach ($obj in $schemaObjects) {
        $guid = New-Object Guid (,$obj.schemaIDGUID)
        $map[$guid] = $obj.lDAPDisplayName
    }

    # --- 2. Extended rights + property sets (rightsGuid) ---
    $extendedRights = Get-ADObject -SearchBase "CN=Extended-Rights,$configNC" `
                                   -LDAPFilter "(rightsGuid=*)" `
                                   -Properties displayName, rightsGuid

    foreach ($obj in $extendedRights) {
        $guid = New-Object Guid (,$obj.rightsGuid)
        $map[$guid] = $obj.displayName
    }

    return $map
}

$guidMap = Get-AdGuidMap

foreach ($obj in $schemaObjects) {
    # Convert raw byte[] to System.Guid
    $guid = New-Object System.Guid (,$obj.schemaIDGUID)
    $guidMap[$guid] = $obj.lDAPDisplayName
}

# Add sentinel for zero GUID
$guidMap[[Guid]"00000000-0000-0000-0000-000000000000"] = "None"

$counter = 0

# Collect explicit ACEs from all OUs
$AllOUs = Get-ADOrganizationalUnit -Filter *
$results = foreach ($ou in $AllOUs) {
    $counter++
    $percent = ($counter / $AllOus.Count) * 100
    Write-Progress -Activity 'Gathering OU ACLs' -Status "$($counter) of $($AllOUs.Count)" -PercentComplete $percent

    # I found the Get-Acl problematic on OUs that had commas and such in the name.
    # So, I switched to the System.DirectoryServices.DirectoryEntry instead
    #$acl = Get-Acl ("AD:\" + $ou.DistinguishedName) -ErrorAction SilentlyContinue
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($ou.DistinguishedName)")
    if (-not $entry) {
        Write-Host $ou.DistinguishedName
        continue
    }
    $acl = $entry.ObjectSecurity
    if (-not $acl) {
        Write-Host $ou.DistinguishedName
        continue
    }

    foreach ($ace in $acl.Access) {

        if (-not $ace.IsInherited -and ( isNotSkippable -id $ace.IdentityReference.Value )) {
            # Resolve ObjectType and InheritedObjectType
            $objTypeName = $guidMap[$ace.ObjectType] 
            if (-not $objTypeName) { $objTypeName = "Unknown-$($ace.ObjectType)" }

            $inhTypeName = $guidMap[$ace.InheritedObjectType]
            if (-not $inhTypeName) { $inhTypeName = "Unknown-$($ace.InheritedObjectType)" }

            [PSCustomObject]@{
                OU                   = $ou.DistinguishedName
                Identity             = $ace.IdentityReference
                Rights               = $ace.ActiveDirectoryRights
                AccessType           = $ace.AccessControlType
                ObjectType           = $objTypeName
                ObjectTypeGuid       = $ace.ObjectType
                InheritedObjectType  = $inhTypeName
                InheritedObjectGuid  = $ace.InheritedObjectType
                InheritanceType      = $ace.InheritanceType
                InheritanceFlags     = $ace.InheritanceFlags
                PropagationFlags     = $ace.PropagationFlags
                IsInherited          = $ace.IsInherited
            }
        }
    }
}

Write-Progress -Activity 'Gathering OU ACLs' -Completed

# Export to CSV
$results | Export-Csv -NoTypeInformation -Path .\OU-Explicit-ACEs.csv -Force
$guidMapRows = foreach ($kvp in $guidMap.GetEnumerator()) {
    [pscustomobject]@{
        Guid = $kvp.Key
        Name = $kvp.Value
    }
}
$guidMapRows | Export-Csv -NoTypeInformation -Path .\guid-map.csv -Force
Write-Host "Created CSV files: 'OU-Explicit-ACEs.csv', 'guid-map.csv'"
