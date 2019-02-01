param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $UsernameOrPart
)

$config = Get-Content "$PSScriptRoot\config.json" | ConvertFrom-JSON

$profileName = ($ExecutionContext.InvokeCommand.ExpandString($config.profileName), "SamlCreds" -ne "")[0]
$profileLocation = ($ExecutionContext.InvokeCommand.ExpandString($config.profileLocation), "$PSScriptRoot\awscredentials" -ne "")[0]

Set-DefaultAWSRegion -Region $config.region

try
{
    $mainCredential = Get-AWSCredential -ProfileName $profileName -ProfileLocation $profileLocation
    $user = Get-IamUser -UserName $UsernameOrPart -Credential $mainCredential
}
catch
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Import-Module ".\OktaAWSToken"
    $mainCredential =  Get-OktaAWSToken
    Set-AWSCredential -AccessKey $mainCredential.AccessKeyId -SecretKey $mainCredential.SecretAccessKey -StoreAs $profileName -ProfileLocation $profileLocation
    Add-Content -Path $profileLocation -Value "$([Environment]::NewLine)aws_session_token=$($mainCredential.SessionToken)"
    $user = Get-IamUser -UserName $UsernameOrPart -Credential $mainCredential
}

<#
    .SYNOPSIS
        Formats the provided $IamUser into a friendlier format for the script's purpose

    .PARAMETER AccountName
        The associated AWS account for the IAM user to be printed

    .PARAMETER IamUser
        The IAM user object from AWS to format
    
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
        [Amazon.IdentityManagement.Model.User]
        $IamUser = $null,

        [Parameter()]
        [Amazon.Runtime.AWSCredentials]
        $Credentials = $null
    )

    Write-Output $AccountName;
    if ($null -eq $IamUser) {
        Write-Output "  No account found"
        return
    }

    $accessKeys = Get-IAMAccessKey -UserName $IamUser.UserName -Credential $Credentials
    Write-Output "  UserName: $($IamUser.UserName)"
    $lastUsedValue = $IamUser.PasswordLastUsed
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
}

Write-UserInfo "Primary Account" $user $mainCredential

foreach ($account in $config.accounts)
{
    $assumedRole = Use-STSRole -RoleArn $account.arn -RoleSessionName "MyRoleSessionName" -Credential $mainCredential
    try
    {
        $user = Get-IamUser -UserName $UsernameOrPart -Credential $assumedRole.Credentials
    }
    catch [Amazon.IdentityManagement.Model.NoSuchEntityException]
    {
        $user = $null
    }
    Write-UserInfo $account.AccountName $user $assumedRole.Credentials
}
