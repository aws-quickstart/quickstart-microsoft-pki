<#
    .SYNOPSIS
    Invoke-TwoTierSubCaPreConfig.ps1

    .DESCRIPTION
    This script installs the required Windows features to make the computer an Subordinate Enterprise CA and joins the computer to the domain specified.
    
    .EXAMPLE
    .\Invoke-TwoTierSubCaPreConfig -SubCaNetBIOSName 'CA01' -DomainNetBIOSName 'example' -DomainDNSName 'example.com' -DomainController1IP '10.20.30.40' DomainController2IP '10.20.30.41' -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example-VX5fcW' -UseS3ForCRL 'Yes'

#>

[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)][String]$SubCaNetBIOSName,
    [Parameter(Mandatory = $true)][String]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][String]$DomainDNSName,
    [Parameter(Mandatory = $true)][String]$DomainController1IP,
    [Parameter(Mandatory = $true)][String]$DomainController2IP,
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL
)

#Requires -Modules PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc

#==================================================
# Variables
#==================================================

$CompName = $env:COMPUTERNAME

#==================================================
# Main
#==================================================

Write-Output 'Getting network configuration'
Try {
    $NetIpConfig = Get-NetIPConfiguration -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get network configuration $_"
    Exit 1
}

Write-Output 'Grabbing the Current Gateway Address in order to Static IP Correctly'
$GatewayAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'

Write-Output 'Formatting IP Address in format needed for IPAdress DSC Resource'
$IP = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
$Prefix = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'PrefixLength'
$IPADDR = 'IP/CIDR' -replace 'IP', $IP -replace 'CIDR', $Prefix

Write-Output 'Getting MAC address'
Try {
    $MacAddress = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'MacAddress'
} Catch [System.Exception] {
    Write-Output "Failed to get MAC address $_"
    Exit 1
}

Write-Output "Getting $ADAdminSecParam Secret"
Try {
    $AdminSecret = Get-SECSecretValue -SecretId $ADAdminSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $ADAdminSecParam Secret $_"
    Exit 1
}

Write-Output 'Converting AdminSecret from JSON'
Try {
    $ADAdminPassword = ConvertFrom-Json -InputObject $AdminSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert $AdminSecret from JSON $_"
    Exit 1
}

Write-Output 'Creating Credential Object for Administrator'
$AdminUserName = $ADAdminPassword.UserName
$AdminUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$DomainNetBIOSName\$AdminUserName", $AdminUserPW)

Write-Output 'Getting the DSC Cert Encryption Thumbprint to Secure the MOF File'
Try {
    $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
} Catch [System.Exception] {
    Write-Output "Failed to get DSC Cert Encryption Thumbprint $_"
    Exit 1
}

Write-Output 'Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing'
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName             = '*'
            CertificateFile = 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer'
            Thumbprint           = $DscCertThumbprint
            PSDscAllowDomainUser = $true
        },
        @{
            NodeName = 'localhost'
        }
    )
}

# PowerShell DSC Configuration Block for Subordinate Enterpise CA
Configuration ConfigSubCa {
    # Credential Objects being passed in
    param
    (
        [PSCredential] $Credentials
    )
    
    # Importing DSC Modules needed for Configuration
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration', 'NetworkingDsc', 'ComputerManagementDsc'

    # Node Configuration block, since processing directly on CA using localhost
    Node LocalHost {
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'Primary'
            MacAddress = $MacAddress
        }
        NetIPInterface DisableDhcp {
            Dhcp           = 'Disabled'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }
        IPAddress SetIP {
            IPAddress      = $IPADDR
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetIPInterface]DisableDhcp'
        }
        DefaultGatewayAddress SetDefaultGateway {
            Address        = $GatewayAddress
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[IPAddress]SetIP'
        }
        DnsServerAddress DnsServerAddress {
            Address        = $DomainController1IP, $DomainController2IP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[DefaultGatewayAddress]SetDefaultGateway'
        }
        DnsConnectionSuffix DnsConnectionSuffix {
            InterfaceAlias = 'Primary'
            ConnectionSpecificSuffix  = $DomainDNSName
            RegisterThisConnectionsAddress = $True
            UseSuffixWhenRegistering = $False
        }
        WindowsFeature ADCSCA
        {
            Name   = 'ADCS-Cert-Authority'
            Ensure = 'Present'
            DependsOn = '[DnsServerAddress]DnsServerAddress'
        }
        WindowsFeature RSAT-ADCS-ManagementTools
        {
            Name   = 'RSAT-ADCS'
            Ensure = 'Present'
            DependsOn = '[DnsServerAddress]DnsServerAddress'
        }
        WindowsFeature RSAT-AD-ManagementTools {
            Ensure    = 'Present'
            Name      = 'RSAT-AD-Tools'
            DependsOn = '[DnsServerAddress]DnsServerAddress'
        }
        If ($UseS3ForCRL -eq 'No') {
            WindowsFeature IIS {
                Ensure    = 'Present'
                Name      = 'Web-WebServer'
                DependsOn = '[DnsServerAddress]DnsServerAddress'
            }
            WindowsFeature IIS-ManagementTools {
                Ensure    = 'Present'
                Name      = 'Web-Mgmt-Console'
                DependsOn = '[DnsServerAddress]DnsServerAddress'
            }
            WindowsFeature RSAT-DNS-ManagementTools {
                Ensure    = 'Present'
                Name      = 'RSAT-DNS-Server'
                DependsOn = '[DnsServerAddress]DnsServerAddress'
            }
        }
        Computer JoinDomain {
            Name       = $SubCaNetBIOSName
            DomainName = $DomainDnsName
            Credential = $Credentials
            DependsOn  = '[WindowsFeature]RSAT-ADCS-ManagementTools'
        }
    }
}

Write-Output 'Generating MOF File'
ConfigSubCa -OutputPath 'C:\AWSQuickstart\ConfigSubCa' -Credentials $Credentials -ConfigurationData $ConfigurationData