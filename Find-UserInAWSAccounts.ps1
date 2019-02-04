param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $UsernameOrPart,

    [Parameter()]
    [Switch]
    $CacheCredentials
)

$config = Get-Content "$PSScriptRoot\config.json" | ConvertFrom-JSON

$profileName = ($ExecutionContext.InvokeCommand.ExpandString($config.profileName), "SamlCreds" -ne "")[0]
$profileLocation = ($ExecutionContext.InvokeCommand.ExpandString($config.profileLocation), "$PSScriptRoot\awscredentials" -ne "")[0]

Set-DefaultAWSRegion -Region $config.region

<#
    .SYNOPSIS
        Get the primary account credentials using the OktaAWSToken module
#>
function Get-PrimaryCredential
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Import-Module ".\OktaAWSToken"
    $credential =  Get-OktaAWSToken

    return $credential
}

<#
    .SYNOPSIS
        Gets a list of users with a username matching at least part of the parameter
    
    .PARAMETER UsernameSearch
        The string to search users for
    
    .PARAMETER Credential
        An IAM Credential with permissions to list IAM users
#>
function Get-MatchingUsers
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UsernameSearch,
    
        [Parameter(Mandatory = $true)]
        [Amazon.Runtime.AWSCredentials]
        $Credentials
    )

    try
    {
        $matchingUsers = Get-IamUser -UserName $UsernameSearch -Credential $Credentials
    }
    catch [Amazon.IdentityManagement.Model.NoSuchEntityException]
    {
        $matchingUsers = Get-IamUserList -Credential $Credentials | Where-Object { $_.UserName -like "*$UsernameSearch*" }
    }

    return $matchingUsers
}

<#
    .SYNOPSIS
        Formats the provided $IamUser into a friendlier format for the script's purpose

    .PARAMETER AccountName
        The associated AWS account for the IAM user to be printed

    .PARAMETER IamUsers
        The IAM user object from AWS or collection of such objects to format
    
    .PARAMETER Credentials
        Credentials with permission to query the given user to check for its Access Keys
#>
function Write-UserInfo
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $AccountName,

        [Parameter()]
        [Amazon.IdentityManagement.Model.User[]]
        $IamUsers = $null,

        [Parameter()]
        [Amazon.Runtime.AWSCredentials]
        $Credentials = $null
    )

    if ($null -eq $IamUsers) {
        Write-Output $AccountName;
        Write-Output "  No account found"
        Write-Output ""
        return
    }

    Write-Output "$($AccountName): $($IamUsers.Length) match(es) found"

    foreach ($iamUser in $IamUsers)
    {
        $accessKeys = Get-IAMAccessKey -UserName $iamUser.UserName -Credential $Credentials
        Write-Output "  UserName: $($iamUser.UserName)"
        $lastUsedValue = $iamUser.PasswordLastUsed
        if ($lastUsedValue -eq [DateTime]::MinValue)
        {
            $lastUsedValue = "Never"
        }
        Write-Output "  Password last used: $lastUsedValue"
        if ($accessKeys.Length -gt 0)
        {
            foreach ($item in $accessKeys)
            {
                $lastUsed = Get-IAMAccessKeyLastUsed -AccessKeyId $item.AccessKeyId -Credential $Credentials
                $lastUsedValue = $lastUsed.AccessKeyLastUsed.LastUsedDate
                if ($lastUsedValue -eq [DateTime]::MinValue)
                {
                    $lastUsedValue = "Never";
                }
                Write-Output "  Access key: $($item.AccessKeyId)   Last used: $lastUsedValue"
            }
        }
        else
        {
            Write-Output "  No account keys found"
        }

        Write-Output ""
    }
}

if ($CacheCredentials)
{
    try
    {
        $mainCredential = Get-AWSCredential -ProfileName $profileName -ProfileLocation $profileLocation
        $users = Get-MatchingUsers $UsernameOrPart $mainCredential
    }
    catch
    {
        $mainCredential = Get-PrimaryCredential
        Set-AWSCredential -AccessKey $mainCredential.AccessKeyId -SecretKey $mainCredential.SecretAccessKey -StoreAs $profileName -ProfileLocation $profileLocation
        Add-Content -Path $profileLocation -Value "$([Environment]::NewLine)aws_session_token=$($mainCredential.SessionToken)"
        $users = Get-MatchingUsers $UsernameOrPart $mainCredential
    }
}
else
{
    $mainCredential = Get-PrimaryCredential
    $users = Get-MatchingUsers $UsernameOrPart $mainCredential
}

Write-UserInfo "Primary Account" $users $mainCredential

foreach ($account in $config.accounts)
{
    $assumedRole = Use-STSRole -RoleArn $account.arn -RoleSessionName "MyRoleSessionName" -Credential $mainCredential
    $users = Get-MatchingUsers $UsernameOrPart $assumedRole.Credentials
    Write-UserInfo $account.AccountName $users $assumedRole.Credentials
}
