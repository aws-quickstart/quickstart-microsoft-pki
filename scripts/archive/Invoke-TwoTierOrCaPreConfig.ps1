<#
    .SYNOPSIS
    Invoke-TwoTierOrCaPreConfig.ps1

    .DESCRIPTION
    This script installs the required Windows features to make the computer an Offline Root CA.
    
    .EXAMPLE
    .\Invoke-TwoTierOrCaPreConfig -OrCaNetBIOSName 'CA01' -DomainController1IP '10.20.30.40' DomainController2IP '10.20.30.41
#>

[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)][String]$OrCaNetBIOSName,
    [Parameter(Mandatory = $true)][String]$DomainController1IP,
    [Parameter(Mandatory = $true)][String]$DomainController2IP
)

#Requires -Modules PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc

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

# PowerShell DSC Configuration Block for Offline Root CA
Configuration ConfigOrCa {
    # Importing DSC Modules needed for Configuration
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration', 'NetworkingDsc', 'ComputerManagementDsc'

    # Node Configuration block, since processing directly on the CA using localhost
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
            DependsOn = '[WindowsFeature]ADCSCA'
        }
        Computer Rename {
            Name       = $OrCaNetBIOSName
            DependsOn  = '[WindowsFeature]RSAT-ADCS-ManagementTools'
        }
    }
}

Write-Output 'Generating MOF File'
ConfigOrCa -OutputPath 'C:\AWSQuickstart\ConfigOrCa' -ConfigurationData $ConfigurationData