# About

This script is meant to query several AWS accounts looking for a specific IAM user. It is written to expect that a 
primary account has a role that then has permission on the other accounts to assume a role, which in turn has 
permission to query IAM users and their Access Keys. 

It uses Okta SAML authentication to access the primary account (see [Credits](#Credits) below).

# Prerequisites

* Install the [AWS PowerTools](https://docs.aws.amazon.com/powershell/latest/userguide/pstools-getting-set-up-windows.html). 
This project was written for version 3.3.
* Federated user (via Okta) must have permissions to read users in the primary account and to assume the configured 
roles in the other accounts.
* A "config.json" file in the script's directory with at least `accounts` and `region` set. See 
[config.json.example](config.json.example) for an example of the format and other options.

# Running the script

In the directory, run `.\Find-UserInAWSAccounts.ps1 [Username or part of it]` and follow the prompts.

## Notes

Credentials are cached in the main script's directory in a file called `awscredentials`. They are temporary credentials
and expire at the default interval (1 hour at time of authoring).

# Credits

Uses [OktaAWSToken](https://github.com/LawrenceHwang/OktaAWSToken) to authenticate to AWS through Okta. The source is
committed because it's small and I don't like working with Git submodules.
