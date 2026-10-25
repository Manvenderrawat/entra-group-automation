<#
.SYNOPSIS
    Assigns an Entra security group to an Enterprise Application with an app role.

.DESCRIPTION
    Called by Azure DevOps after ServiceNow submits an approved request.
    ServiceNow supplies the application identifiers from its application database.
    The script validates the supplied identifiers against Microsoft Graph, resolves
    the group by exact display name or object ID, validates/selects an app role,
    and creates the appRoleAssignment if it does not already exist.

.EXIT CODES
    0 = Assignment created
    1 = Group not found, ambiguous, or not security-enabled
    2 = Assignment already exists
    3 = Application or role not found/invalid
    4 = Other failure

.REQUIREMENTS
    Environment variables:
      ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET

    Optional notification:
      MAIL_ENABLED, MAIL_SENDER_USER_ID
      Optional separate sender credentials:
      MAIL_SENDER_TENANT_ID, MAIL_SENDER_CLIENT_ID, MAIL_SENDER_CLIENT_SECRET

    Optional ServiceNow update:
      SNOW_ENABLED, SNOW_INSTANCE_URL, SNOW_USERNAME, SNOW_PASSWORD
      Optional SNOW_RITM_TABLE (defaults to sc_req_item)

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7.
    Uses Microsoft Graph REST APIs; no Graph PowerShell module required.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^(?:|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')]
    [string]$AppId = '',

    [Parameter()]
    [ValidatePattern('^(?:|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')]
    [string]$AppObjectId = '',

    [Parameter()]
    [ValidatePattern('^(?:|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')]
    [string]$ServicePrincipalObjectId = '',

    [Parameter()]
    [ValidatePattern('^(?:|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')]
    [string]$TenantId = '',

    [Parameter()]
    [string]$AppDisplayName = '',

    [Parameter()]
    [string]$GroupName = '',

    [Parameter()]
    [ValidatePattern('^(?:|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')]
    [string]$GroupObjectId = '',

    [Parameter()]
    [string]$RoleName = '',

    [Parameter()]
    [string]$RequesterEmail = '',

    [Parameter()]
    [string]$RITMNumber = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:GraphBase = 'https://graph.microsoft.com/v1.0'
$script:GraphToken = $null
$script:Outcome = 'Failure'
$script:ExitCode = 4
$script:AppNameResolved = if ($AppDisplayName) { $AppDisplayName } else { $AppId }
$script:GroupNameResolved = if ($GroupName) { $GroupName } else { $GroupObjectId }
$script:RoleResolved = ''
$script:OutcomeDetail = ''

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Output "$stamp [$Level] $Message"
}

function Get-RequiredEnv {
    param([Parameter(Mandatory)][string]$Name)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) { throw "Required environment variable '$Name' is missing." }
    return $v
}

function Get-GraphToken {
    param(
        [Parameter(Mandatory)][string]$TokenTenantId,
        [Parameter(Mandatory)][string]$Client,
        [Parameter(Mandatory)][string]$Secret
    )
    $tokenUri = "https://login.microsoftonline.com/$TokenTenantId/oauth2/v2.0/token"
    $body = @{
        client_id = $Client
        client_secret = $Secret
        scope = 'https://graph.microsoft.com/.default'
        grant_type = 'client_credentials'
    }
    $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUri `
        -ContentType 'application/x-www-form-urlencoded' -Body $body
    if ([string]::IsNullOrWhiteSpace([string]$tokenResponse.access_token)) {
        throw 'Microsoft identity platform returned an empty access token.'
    }
    return [string]$tokenResponse.access_token
}

function Get-HttpStatusCode {
    param([object]$ErrorRecord)
    try {
        if ($ErrorRecord.Exception.Response.StatusCode) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    } catch {}
    try {
        if ($ErrorRecord.Exception.Response.StatusCode.value__) {
            return [int]$ErrorRecord.Exception.Response.StatusCode.value__
        }
    } catch {}
    return 0
}

function Invoke-Graph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body,
        [string]$AccessToken = $script:GraphToken,
        [int]$MaxRetries = 6
    )

    $headers = @{ Authorization = "Bearer $AccessToken"; Accept = 'application/json' }
    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        try {
            if ($null -ne $Body) {
                $json = ConvertTo-Json -InputObject $Body -Depth 20
                return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers `
                    -ContentType 'application/json' -Body $json
            }
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        }
        catch {
            $status = Get-HttpStatusCode $_
            $retryAfter = 0
            try {
                $h = $_.Exception.Response.Headers
                if ($h['Retry-After']) { [void][int]::TryParse([string]$h['Retry-After'], [ref]$retryAfter) }
            } catch {}
            $transient = ($status -eq 429 -or $status -eq 408 -or ($status -ge 500 -and $status -le 599))
            if (-not $transient -or $attempt -ge $MaxRetries) { throw }
            $delay = if ($retryAfter -gt 0) { $retryAfter } else { [Math]::Min(60, [Math]::Pow(2, $attempt)) }
            Write-Log "Graph HTTP $status. Retry $($attempt + 1)/$MaxRetries after $delay second(s)." 'WARN'
            Start-Sleep -Seconds ([int]$delay)
        }
    }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while (-not [string]::IsNullOrWhiteSpace([string]$next)) {
        $page = Invoke-Graph -Method GET -Uri $next
        foreach ($item in @($page.value)) {
            if ($null -ne $item) { $items.Add($item) }
        }
        $next = $page.'@odata.nextLink'
    }
    return $items.ToArray()
}

function Escape-OData {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Replace("'", "''")
}

function Get-TargetServicePrincipal {
    # Prefer the SP object ID if ServiceNow has it; validate all supplied identifiers.
    if ($ServicePrincipalObjectId) {
        try {
            $sp = Invoke-Graph -Method GET -Uri (
                "$script:GraphBase/servicePrincipals/$ServicePrincipalObjectId" +
                '?$select=id,appId,displayName,appRoles,appOwnerOrganizationId'
            )
        } catch {
            if ((Get-HttpStatusCode $_) -eq 404) { throw 'APP_NOT_FOUND: Service principal object ID was not found in the supplied tenant.' }
            throw
        }
        if ($AppId -and $sp.appId -ine $AppId) {
            throw 'APP_NOT_FOUND: Supplied AppId does not match the service principal object ID.'
        }
        if ($TenantId -and $sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId -ine $TenantId) {
            # appOwnerOrganizationId is not the same as the resource tenant for multi-tenant apps.
            # Do not use it as the tenant validation mechanism.
            Write-Verbose 'Application owner tenant differs; this can be valid for a multi-tenant app.'
        }
        return $sp
    }

    if ($AppId) {
        $v = Escape-OData $AppId
        $results = @(Get-GraphCollection -Uri (
            "$script:GraphBase/servicePrincipals?`$filter=appId eq '$v'&" +
            '$select=id,appId,displayName,appRoles,appOwnerOrganizationId'
        ))
        if ($results.Count -eq 0) { throw "APP_NOT_FOUND: No Enterprise Application service principal found for AppId '$AppId' in the authenticated tenant." }
        if ($results.Count -gt 1) { throw "APP_NOT_FOUND: Multiple service principals matched AppId '$AppId'; provide ServicePrincipalObjectId." }
        if ($AppObjectId) {
            $appObject = Invoke-Graph -Method GET -Uri (
                "$script:GraphBase/applications/$AppObjectId" +
                '?$select=id,appId,displayName'
            )
            if ($appObject.appId -ine $results[0].appId) {
                throw 'APP_NOT_FOUND: Application Object ID does not match the supplied AppId.'
            }
        }
        return $results[0]
    }

    if ($AppObjectId) {
        $appObject = Invoke-Graph -Method GET -Uri (
            "$script:GraphBase/applications/$AppObjectId" +
            '?$select=id,appId,displayName'
        )
        $v = Escape-OData ([string]$appObject.appId)
        $results = @(Get-GraphCollection -Uri (
            "$script:GraphBase/servicePrincipals?`$filter=appId eq '$v'&" +
            '$select=id,appId,displayName,appRoles,appOwnerOrganizationId'
        ))
        if ($results.Count -ne 1) { throw "APP_NOT_FOUND: Expected one service principal for application object '$AppObjectId'; found $($results.Count)." }
        return $results[0]
    }

    if ($AppDisplayName) {
        $v = Escape-OData $AppDisplayName
        $results = @(Get-GraphCollection -Uri (
            "$script:GraphBase/servicePrincipals?`$filter=displayName eq '$v'&" +
            '$select=id,appId,displayName,appRoles,appOwnerOrganizationId'
        ))
        if ($results.Count -ne 1) { throw "APP_NOT_FOUND: Expected one service principal for app name '$AppDisplayName'; found $($results.Count). Supply AppId." }
        return $results[0]
    }

    throw 'APP_NOT_FOUND: Supply AppId, AppObjectId, ServicePrincipalObjectId, or AppDisplayName.'
}

function Get-TargetGroup {
    if ($GroupObjectId) {
        try {
            $g = Invoke-Graph -Method GET -Uri (
                "$script:GraphBase/groups/$GroupObjectId" +
                '?$select=id,displayName,securityEnabled,mailEnabled,groupTypes'
            )
        } catch {
            if ((Get-HttpStatusCode $_) -eq 404) { throw 'GROUP_NOT_FOUND: Group object ID was not found.' }
            throw
        }
        if ($g.securityEnabled -ne $true) { throw "GROUP_NOT_FOUND: Group '$($g.displayName)' is not security-enabled." }
        return $g
    }

    if ([string]::IsNullOrWhiteSpace($GroupName)) { throw 'GROUP_NOT_FOUND: Supply GroupName or GroupObjectId.' }
    $v = Escape-OData $GroupName
    $groups = @(Get-GraphCollection -Uri (
        "$script:GraphBase/groups?`$filter=displayName eq '$v'&" +
        '$select=id,displayName,securityEnabled,mailEnabled,groupTypes'
    ))
    if ($groups.Count -eq 0) { throw "GROUP_NOT_FOUND: No group with exact display name '$GroupName' was found." }
    if ($groups.Count -gt 1) { throw "GROUP_NOT_FOUND: Multiple groups named '$GroupName' exist. Supply GroupObjectId." }
    if ($groups[0].securityEnabled -ne $true) { throw "GROUP_NOT_FOUND: '$GroupName' is not a security-enabled group." }
    return $groups[0]
}

function Select-AppRole {
    param([Parameter(Mandatory)]$ServicePrincipal)
    $roles = @($ServicePrincipal.appRoles)
    $enabled = @($roles | Where-Object { $_.isEnabled -eq $true })

    if ([string]::IsNullOrWhiteSpace($RoleName)) {
        if ($roles.Count -eq 0) {
            $script:RoleResolved = 'Default Access'
            Write-Log 'Selected Default Access (zero GUID): the application defines no appRoles.'
            return '00000000-0000-0000-0000-000000000000'
        }

        $userRole = @($enabled | Where-Object {
            $_.displayName -ieq 'User' -and @($_.allowedMemberTypes) -contains 'User'
        } | Select-Object -First 1)
        if ($userRole.Count -gt 0) {
            $script:RoleResolved = [string]$userRole[0].displayName
            Write-Log "Selected role '$($script:RoleResolved)': enabled User role allows User assignments."
            return [string]$userRole[0].id
        }

        $fallback = @($enabled | Where-Object {
            @($_.allowedMemberTypes) -contains 'User'
        } | Select-Object -First 1)
        if ($fallback.Count -eq 0) {
            throw 'ROLE_INVALID: App defines roles but no enabled role allows User assignments.'
        }
        $script:RoleResolved = [string]$fallback[0].displayName
        Write-Log "Selected role '$($script:RoleResolved)': first enabled role allowing User assignments."
        return [string]$fallback[0].id
    }

    $matches = @($enabled | Where-Object { $_.displayName -ieq $RoleName })
    if ($matches.Count -eq 0) {
        $available = @($enabled | ForEach-Object {
            "'$($_.displayName)' [allowedMemberTypes=$(@($_.allowedMemberTypes) -join ',')]"
        })
        $list = if ($available.Count) { $available -join '; ' } else { '(none)' }
        throw "ROLE_INVALID: Enabled role '$RoleName' not found. Available enabled roles: $list"
    }
    if ($matches.Count -gt 1) { throw "ROLE_INVALID: Multiple enabled roles named '$RoleName' exist." }
    if (@($matches[0].allowedMemberTypes) -notcontains 'User') {
        throw "ROLE_INVALID: Role '$RoleName' does not allow User assignments."
    }
    $script:RoleResolved = [string]$matches[0].displayName
    Write-Log "Selected explicitly requested role '$($script:RoleResolved)'."
    return [string]$matches[0].id
}

function Send-OutcomeEmail {
    param([string]$Outcome, [string]$Detail)
    if ($env:MAIL_ENABLED -ine 'true') { Write-Verbose 'Email notification disabled.'; return }
    if ([string]::IsNullOrWhiteSpace($RequesterEmail)) {
        Write-Log 'Requester email is empty; skipping email.' 'WARN'
        return
    }

    try {
        $mailTenant = if ($env:MAIL_SENDER_TENANT_ID) { $env:MAIL_SENDER_TENANT_ID } else { Get-RequiredEnv 'ENTRA_TENANT_ID' }
        $mailClient = if ($env:MAIL_SENDER_CLIENT_ID) { $env:MAIL_SENDER_CLIENT_ID } else { Get-RequiredEnv 'ENTRA_CLIENT_ID' }
        $mailSecret = if ($env:MAIL_SENDER_CLIENT_SECRET) { $env:MAIL_SENDER_CLIENT_SECRET } else { Get-RequiredEnv 'ENTRA_CLIENT_SECRET' }
        $sender = Get-RequiredEnv 'MAIL_SENDER_USER_ID'
        $mailToken = Get-GraphToken -TokenTenantId $mailTenant -Client $mailClient -Secret $mailSecret

        $content = @"
ServiceNow request: $RITMNumber
Application: $script:AppNameResolved
Client ID: $AppId
Group: $script:GroupNameResolved
Role: $script:RoleResolved
Outcome: $Outcome

Details:
$Detail
"@
        $body = @{
            message = @{
                subject = "Entra group assignment: $Outcome - $RITMNumber"
                body = @{ contentType = 'Text'; content = $content }
                toRecipients = @(@{ emailAddress = @{ address = $RequesterEmail } })
            }
            saveToSentItems = $true
        }
        $null = Invoke-Graph -Method POST -Uri "$script:GraphBase/users/$sender/sendMail" -Body $body -AccessToken $mailToken
        Write-Log "Notification submitted to $RequesterEmail."
    } catch {
        Write-Log "Email notification failed: $($_.Exception.Message)" 'ERROR'
    }
}

function Update-ServiceNowRitm {
    param([string]$Outcome, [string]$Detail)
    if ($env:SNOW_ENABLED -ine 'true') { return }
    if ([string]::IsNullOrWhiteSpace($RITMNumber)) { Write-Log 'RITMNumber empty; skipping ServiceNow update.' 'WARN'; return }

    try {
        $base = (Get-RequiredEnv 'SNOW_INSTANCE_URL').TrimEnd('/')
        $username = Get-RequiredEnv 'SNOW_USERNAME'
        $password = Get-RequiredEnv 'SNOW_PASSWORD'
        $table = if ($env:SNOW_RITM_TABLE) { $env:SNOW_RITM_TABLE } else { 'sc_req_item' }
        if ($table -notmatch '^[A-Za-z0-9_]+$') { throw 'Invalid SNOW_RITM_TABLE.' }

        $number = [Uri]::EscapeDataString($RITMNumber)
        $uri = "$base/api/now/table/$table?sysparm_query=number=$number&sysparm_fields=sys_id,number&sysparm_limit=2"
        $basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$username`:$password"))
        $headers = @{ Authorization = "Basic $basic"; Accept = 'application/json' }
        $found = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
        $records = @($found.result)
        if ($records.Count -ne 1) { throw "Expected one RITM record; found $($records.Count)." }

        $notes = "Entra assignment outcome: $Outcome`nApplication: $script:AppNameResolved`nClient ID: $AppId`nGroup: $script:GroupNameResolved`nRole: $script:RoleResolved`nDetails: $Detail"
        $payload = @{ work_notes = $notes }
        if (-not [string]::IsNullOrWhiteSpace($env:SNOW_STATE)) { $payload.state = $env:SNOW_STATE }
        $recordId = [Uri]::EscapeDataString([string]$records[0].sys_id)
        $null = Invoke-RestMethod -Method PATCH -Uri "$base/api/now/table/$table/$recordId" `
            -Headers $headers -ContentType 'application/json' -Body (ConvertTo-Json $payload -Depth 5)
        Write-Log "ServiceNow RITM $RITMNumber updated."
    } catch {
        Write-Log "ServiceNow update failed: $($_.Exception.Message)" 'ERROR'
    }
}

try {
    Write-Log "Starting request RITM='$RITMNumber'."

    $authTenant = Get-RequiredEnv 'ENTRA_TENANT_ID'
    $clientId = Get-RequiredEnv 'ENTRA_CLIENT_ID'
    $clientSecret = Get-RequiredEnv 'ENTRA_CLIENT_SECRET'

    if ($TenantId -and $TenantId -ine $authTenant) {
        throw 'APP_NOT_FOUND: Request TenantId does not match the configured automation tenant. Cross-tenant execution is not enabled.'
    }
    if (-not $TenantId) { $TenantId = $authTenant }

    $script:GraphToken = Get-GraphToken -TokenTenantId $authTenant -Client $clientId -Secret $clientSecret

    $sp = Get-TargetServicePrincipal
    $script:AppNameResolved = [string]$sp.displayName
    if ($AppId -and $sp.appId -ine $AppId) { throw 'APP_NOT_FOUND: Resolved service principal does not match supplied AppId.' }
    Write-Log "Validated Enterprise Application '$($sp.displayName)' (AppId=$($sp.appId); servicePrincipalObjectId=$($sp.id))."

    $group = Get-TargetGroup
    $script:GroupNameResolved = [string]$group.displayName
    Write-Log "Resolved security group '$($group.displayName)' ($($group.id))."

    $roleId = Select-AppRole -ServicePrincipal $sp

    $assignUri = "$script:GraphBase/servicePrincipals/$($sp.id)/appRoleAssignedTo" +
        '?$select=id,principalId,principalDisplayName,principalType,appRoleId'
    $assignments = @(Get-GraphCollection -Uri $assignUri)
    $existing = @($assignments | Where-Object {
        $_.principalId -ieq $group.id -and $_.appRoleId -ieq $roleId -and $_.principalType -ieq 'Group'
    })

    if ($existing.Count -gt 0) {
        $script:Outcome = 'AlreadyAssigned'
        $script:ExitCode = 2
        $script:OutcomeDetail = 'The group already has the selected app role; no change was made.'
        Write-Log $script:OutcomeDetail 'WARN'
    } else {
        $body = @{
            principalId = [string]$group.id
            resourceId = [string]$sp.id
            appRoleId = [string]$roleId
        }
        try {
            $created = Invoke-Graph -Method POST -Uri "$script:GraphBase/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body $body
            $script:Outcome = 'Assigned'
            $script:ExitCode = 0
            $script:OutcomeDetail = "Assignment created. Assignment ID: $($created.id)"
            Write-Log $script:OutcomeDetail
        } catch {
            # Handle a concurrent run that created the same assignment after our pre-check.
            $status = Get-HttpStatusCode $_
            if ($status -eq 400 -or $status -eq 409) {
                $check = @(Get-GraphCollection -Uri $assignUri)
                $duplicate = @($check | Where-Object {
                    $_.principalId -ieq $group.id -and $_.appRoleId -ieq $roleId -and $_.principalType -ieq 'Group'
                })
                if ($duplicate.Count -gt 0) {
                    $script:Outcome = 'AlreadyAssigned'
                    $script:ExitCode = 2
                    $script:OutcomeDetail = 'The assignment was created concurrently by another request.'
                } else { throw }
            } else { throw }
        }
    }
}
catch {
    $message = [string]$_.Exception.Message
    $script:OutcomeDetail = $message
    if ($message -match 'GROUP_NOT_FOUND') {
        $script:Outcome = 'GroupNotFound'; $script:ExitCode = 1
    } elseif ($message -match 'APP_NOT_FOUND|ROLE_INVALID') {
        $script:Outcome = 'ApplicationOrRoleInvalid'; $script:ExitCode = 3
    } else {
        $script:Outcome = 'Failure'; $script:ExitCode = 4
    }
    Write-Log $message 'ERROR'
}
finally {
    Send-OutcomeEmail -Outcome $script:Outcome -Detail $script:OutcomeDetail
    Update-ServiceNowRitm -Outcome $script:Outcome -Detail $script:OutcomeDetail
    $script:GraphToken = $null
    Write-Log "Final outcome=$script:Outcome; exit code=$script:ExitCode."
}
exit $script:ExitCode
