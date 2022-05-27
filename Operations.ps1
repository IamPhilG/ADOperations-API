####
 
#### OPERATIONS API ??
 
####
Function Request-CcFQDN {
    param (
        [CmdLetBinding()]
        [ValidateSet("fr","us","ca","br","hk")]
        [string] $cc
    )
    $output = @{
        "ErrorNumber" = 1
        "Data" = $null
    }
    if ((Get-ADForest).Name -eq "domainname")
    {
        if ($cc -eq "fr") {
            $output.Data = "domainname"
        }
        elseif (($cc -eq "us") -or ($cc -eq "ca") -or ($cc -eq "br")) {
            $output.Data = "domainname"
        }
        else {
            $output.Data = "domainname"
        }
    }
    elseif ((Get-ADForest).Name -eq "domainname"){
        $output.data = "domainname"
    }
    else {
        $output.ErrorNumber = 100
        $output.Data = "Actually, I need YOU to help me.`nCan you enhance Request-CcFQDN function and provide me more knowlege as I do not recognize $((Get-ADForest).Name)? "
    }
    return $output
}
 
Function Assert-UserInformation {
 
    param (
            [object] $user
        )
    $output = $true
    if ( ($user.mail -eq "") -or ($null -eq $user.mail)  ){
        $output = $false
    }
    return $output
}
 
Function Get-UserInformation {
 
    param (
        [string] $GGI,
        [string] $countrycode
    )
 
    $userProperties = @(
        "EmployeeNumber",
        "EmployeeID",
        "sAMAccountName",
        "sn",
        "givenName",
        "mail"
    )
    $validatedUser = @()
 
    $output = Request-CcFQDN -cc $countrycode
 
    if ($output.ErrorNumber -eq 1) {
        $result = Get-ADUser -Filter { EmployeeNumber -eq $GGI } -Properties $userProperties -server $output.Data
       
        $result | Foreach-Object {
            if (Assert-userInformation -user $_) {
                $validatedUser += $_
            }
             $output.Data = $validatedUser
        }
    }
    else {
        $output.Data
    }
   
    return $output.Data
 
}
 
Function Get-UserName {
    param (
        [string] $sAMAccountName
    )
 
    $userProperties = @(
        "sAMAccountName",
        "DisplayName"
    )
 
    $output = Get-ADUser -Filter { sAMAccountName -eq $sAMAccountName } -Properties $userProperties | Select sAMAccountName,DisplayName
 
    return $output
 
}
 
function Get-TimeSinceLastPWSet {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True,
        Position=1,
        ValueFromPipeline=$True)]
        [DateTime]$Passwordlastset
    )
    $tsSinceLastPWSet = New-TimeSpan $Passwordlastset $(get-date)
    return $tsSinceLastPWSet
}
 
Function Get-FormatedTimeSpan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True,
        Position=1,
        ValueFromPipeline=$True)]
        [TimeSpan]$tsLastPWSet
    )
 
    $strFormatted = '{0:dd} days, {0:hh} hours' -f $tsLastPWSet
    return $strFormatted
}
 
Function Get-PwdExpirationInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true)]
        [string]$sAMAccountName,
 
        [Parameter(Position=1)]
        [switch]$full
    )
 
    $ADM_Properties = @( 
        "AccountExpirationDate",
        "CannotChangePassword",
        "Created",
        "Department",
        "Description",
        "DisplayName",
        "DistinguishedName",
        "EmailAddress",
        "mail",
        "EmployeeID",
        "EmployeeNumber",
        "employeeType",
        "Enabled",
        "GivenName",
        "Info",
        "IsCriticalSystemObject",
        "LastLogonDate",
        "MemberOf",
        "msDS-cloudExtensionAttribute20",
        "Name",
        "ObjectClass",
        "ObjectGUID",
        "PasswordExpired",
        "PasswordNotRequired",
        "ProtectedFromAccidentalDeletion",
        "PasswordLastSet",
        "pwdLastSet",
        "sAMAccountName",
        "SID",
        "SIDHistory",
        "Surname",
        "UserPrincipalName",
        "userAccountControl",
        "whenCreated",
        "whenChanged"
    )
    $defaultMaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop).MaxPasswordAge.Days
 
    $user = get-aduser $sAMAccountName -properties $ADM_Properties
    $userObj = New-Object System.Object
    foreach($admProperty in $ADM_Properties){
        $userObj | Add-Member -Type NoteProperty -Name $admProperty -Value $user.$admProperty
    }
<# |
                 where { ($_.passwordexpired -eq $false) -and
                         ($_.DistinguishedName -notlike "*Service*") -and
                         ($_.IsCriticalSystemObject -ne $true) }#>
    If ($userObj.PasswordExpired) {
        return ( $userObj | Select-Object SamAccountName,Name,Description,PasswordExpired,Passwordlastset )
    }
    else {
        $userObj | Add-Member -Type NoteProperty -Name IsSetToNotExpire  -Value $false
        $userObj | Add-Member -Type NoteProperty -Name NotExpiringReason -Value ""
        $userObj | Add-Member -Type NoteProperty -Name maxPasswordAge -Value $defaultMaxPasswordAge
        $userObj.DistinguishedName
        $PasswordPol = (Get-AduserResultantPasswordPolicy -identity ($userObj.DistinguishedName) -ErrorAction STOP)
        if (($PasswordPol) -ne $null){
            if (($PasswordPol).MaxPasswordAge.Days -ne 0) {
                $userObj.maxPasswordAge = ($PasswordPol).MaxPasswordAge.Days
 
            } else {
                $userObj.IsSetToNotExpire  = $true
                $userObj.NotExpiringReason = "Account not expiring because of FGPP : $(($PasswordPol).Name)"
            }
        }
        If ($userObj.IsSetToNotExpire -eq $false) {
                $userObj | Add-Member -Type NoteProperty -Name ExpiresOn -Value (([datetime]::FromFileTime($userObj.pwdLastSet)).AddDays($maxPasswordAge))
                $userObj | Add-Member -Type NoteProperty -Name daysToExpire -Value (Get-TimeSinceLastPWSet -Passwordlastset ($userobj.PasswordLastSet))
                $userObj.daysToExpire = [math]::Round($userObj.daysToExpire.TotalDays)
                $userObj | Add-Member -Type NoteProperty -Name ExpireDate -Value ($userObj.ExpiresOn)
        } else {
            $userObj | Add-Member -Type NoteProperty -Name ExpiresOn -Value ""
            $userObj | Add-Member -Type NoteProperty -Name daysToExpire -Value ""
            $userObj | Add-Member -Type NoteProperty -Name ExpireDate -Value ""
        }
        if ($full) {
            return $userObj
        }
        else {
            return ( $userObj | Select-Object SamAccountName,Name,Description,ExpiresOn,daysToExpire )
        }
    }
}
 
Function Get-GroupMembers {
    param (
        [string] $sAMAccountName
    )
 
    throw "to do"
}
 
Function Set-NewPassword {
 
   
    $ClearPwd = AliouFunction
    $NewPwd = (ConvertTo-SecureString -AsPlainText $ClearPwd -Force)
    $idDN = (get-ADUser $SamAccountName).distinguishedname
    Set-ADAccountPassword -Identity  $idDN -Reset -NewPassword
 
}
 
function Get-RandomPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true)]
        [ValidateRange(1,40)]
        [int]
        $length,
 
        [Parameter(Position=1)]
        [string]
        $characters = 'abcdefghkmnprstuvwxyzABCDEFGHKLMNPRSTUVWXYZ123456789!"$/()=?+#_'
    )
   
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    return ( $random | ForEach-Object { $characters[$_] } )
 
}
function Randomize-Text {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true)]
        [ValidateRange(1,40)]
        [int]
        $text,
 
        [Parameter(Position=1)]
        [string]
        $characters = 'abcdefghkmnprstuvwxyzABCDEFGHKLMNPRSTUVWXYZ123456789!"$/()=?+#_'
    )
    param(
        $text
    )
    $anzahl = $text.length
    $indizes = Get-Random -InputObject (0..$anzahl) -Count $anzahl
    [String]$text[$indizes]
    }
 
$password = Get-RandomPassword -length 10 -characters 'abcdefghiklmnprstuvwxyz'
$password += Get-RandomPassword -length 7 -characters '!"$/()=?+#_'
$password += Get-RandomPassword -length 6 -characters '123456789'
$password += Get-RandomPassword -length 10 -characters 'ABCDEFGHKLMNPRSTUVWXYZ'
$RandomPassword = Randomize-Text $password
Write-Host "$RandomPassword" -ForegroundColor DarkCyan
$RandomPassword.Length
