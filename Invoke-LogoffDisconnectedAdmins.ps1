<#
.SYNOPSIS
    Logoff disconnected admin user sessions from Windows systems.
.DESCRIPTION
    Looks for disconnected user sessions. If found checks to determine if the user has local admin rights.
    If the disconnected Desktop session belongs to an Admin user then a logoff is performed for the session.
    This cmdlet only affects connections to the localhost by default. If -IncludeRDSessions is specified then 
    if the localhost is a Remote Desktop Connection Broker servers this will impact all servers in the RD Deployment.
.NOTES
    Author: Robert D. Biddle
    Created: 2022-07-05
.LINK
    https://github.com/RobBiddle/Invoke-LogoffDisconnectedAdmins
.EXAMPLE
    Invoke-LogoffDisconnectedAdmins
    Invoke-LogoffDisconnectedAdmins -IncludeRDSessions
#>
[CmdletBinding()]
param (
    # Switch to logoff via RDUserSession on Connection Brokers in addition to localhost sessions
    [switch]$IncludeRDSessions
)

function IsUserAdmin ($user, $domain) {
    # Determine if user has local Admin rights
    $UserUPN = (Get-ADUser $user -Server $domain).userprincipalname
    $identity = [System.Security.Principal.WindowsIdentity]$UserUPN
    $Principal = New-Object System.Security.Principal.WindowsPrincipal( $identity )
    return $Principal.IsInRole( [System.Security.Principal.WindowsBuiltInRole]::Administrator )
}

function IsUserSessionDisconnected ($user) {
    if ($null -ne $user) {
        try {
        (query.exe session $user)[1] -match '  Disc '
        }
        catch {
            return $false
        }
    }
}

# Connection Brokers allow for logging off RD Sessions quickly so that is preferred
$isConnectionBroker = (Get-WindowsFeature RDS-Connection-Broker | Where-Object Installed).count -gt 0
if ($isConnectionBroker -and $IncludeRDSessions) {
    $DisconnectedAdminDesktopSessions = @()
    $DisconnectedSessions = Get-RDUserSession | Where-Object SessionState -eq 'STATE_DISCONNECTED'
    foreach ($ds in $DisconnectedSessions) {
        # Determine if user has local Admin rights
        $UserIsAdmin = IsUserAdmin $ds.UserName $ds.DomainName
        if (-NOT $UserIsAdmin) {
            Continue
        }
        else {
            $DisconnectedAdminDesktopSessions += [PSCustomObject]@{
                UserName  = $ds.UserName
                Domain    = $ds.DomainName
                SessionId = $ds.UnifiedSessionId
            }
        }
    }
}

# All Logged on Users, includes service accounts and network connections
$Win32_LoggedOnUsers = Get-CimInstance -Class Win32_LoggedOnUser | Select-Object Antecedent, Dependent -Unique
# Limit to matching Remote Desktop Sessions -- Connection state is not known at this point
$DesktopSessionLogonIds = ((Get-CimInstance -Class Win32_LogonSession | Where-Object LogonId -in $Win32_LoggedOnUsers.Dependent.LogonId | Where-Object LogonType -eq 10)).LogonId
$DesktopSessions = $Win32_LoggedOnUsers | Where-Object { $_.Dependent.LogonId -in $DesktopSessionLogonIds }

$DisconnectedAdminDesktopSessions = @()
foreach ($ds in $DesktopSessions) {
    # Determine if user has a disconnected session
    $UserSessionIsDisconnected = IsUserSessionDisconnected $ds.Antecedent.Name
    if (-NOT $UserSessionIsDisconnected) {
        Continue
    }

    # Determine if user has local Admin rights
    $UserIsAdmin = IsUserAdmin $ds.Antecedent.Name $ds.Antecedent.Domain
    if (-NOT $UserIsAdmin) {
        Continue
    }

    # Using process metadata to match Win32_LogonSession LogonId to Session ID of console/terminal session
    $dsProcesses = Get-CimInstance -ClassName Win32_SessionProcess | Where-Object { $_.Antecedent.LogonID -eq $ds.Dependent.LogonId }
    $SessionIdsFromProcesses = @()
    foreach ($dsp in $dsProcesses) {
        $SessionIdsFromProcesses += (Get-Process -Id $dsp.Dependent.Handle -IncludeUserName).SessionId
    }
    $SessionIdsFromProcesses = $SessionIdsFromProcesses | Select-Object -Unique
    if ($SessionIdsFromProcesses.count -gt 1) {
        Write-Warning "Multiple session IDs found. This is unexpected."
        Get-Process -Id $dsp.Dependent.Handle -IncludeUserName
    }
    else {
        $s = $SessionIdsFromProcesses
        if ( query.exe session $s) {
            $SessionId = $s
            $DisconnectedAdminDesktopSessions += [PSCustomObject]@{
                UserName  = $ds.Antecedent.Name
                Domain    = $ds.Antecedent.Domain
                LogonId   = $ds.Dependent.LogonId
                SessionId = $SessionId
            }
        } 
    }
}

$DisconnectedAdminDesktopSessions = $DisconnectedAdminDesktopSessions | Sort-Object Domain, UserName, SessionId -Unique
Write-Output "Logging off Disconnected Admin Session:"
Write-Output $DisconnectedAdminDesktopSessions
foreach ($s in $DisconnectedAdminDesktopSessions) {
    logoff.exe $s.SessionId /v
}
