<#
    .SYNOPSIS
    Invoke-EnterpriseCaPreConfig.ps1

    .DESCRIPTION
    This script installs the required Windows features to make the computer an Enterprise CA and joins the computer to the domain specified.
    
    .EXAMPLE
    .\Invoke-EnterpriseCaPreConfig -EntCaNetBIOSName 'CA01' -DomainNetBIOSName 'example' -DomainDNSName 'example.com' -DomainController1IP '10.20.30.40' DomainController2IP '10.20.30.41' -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example-VX5fcW' -UseS3ForCRL 'Yes'

#>

[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)][String]$EntCaNetBIOSName,
    [Parameter(Mandatory = $true)][String]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][String]$DomainDNSName,
    [Parameter(Mandatory = $true)][String]$DomainController1IP,
    [Parameter(Mandatory = $true)][String]$DomainController2IP,
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL
)

#Requires -Modules PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc

# Getting Network Configuration
$NetIpConfig = Get-NetIPConfiguration

# Grabbing the Current Gateway Address in order to Static IP Correctly
$GatewayAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'

# Formatting IP Address in format needed for IPAdress DSC Resource
$IP = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
$Prefix = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'PrefixLength'
$IPADDR = 'IP/CIDR' -replace 'IP', $IP -replace 'CIDR', $Prefix

# Grabbing Mac Address for Primary Interface to Rename Interface
$MacAddress = Get-NetAdapter | Select-Object -ExpandProperty 'MacAddress'

# Getting Password from Secrets Manager for AD Admin User
$ADAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $ADAdminSecParam | Select-Object -ExpandProperty 'SecretString')

# Creating Credential Object for Domain Administrator
$AdminUserName = $ADAdminPassword.UserName
$AdminUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$DomainNetBIOSName\$AdminUserName", $AdminUserPW)

# Getting the DSC Cert Encryption Thumbprint to Secure the MOF File
$DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'

# Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing
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

# PowerShell DSC Configuration Block for Domain Controller 2
Configuration ConfigEntCa {
    # Credential Objects being passed in
    param
    (
        [PSCredential] $Credentials
    )
    
    # Importing DSC Modules needed for Configuration
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration', 'NetworkingDsc', 'ComputerManagementDsc'

    # Node Configuration block, since processing directly on DC using localhost
    Node LocalHost {
        # Renaming Primary Adapter in order to Static the IP for AD installation
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'Primary'
            MacAddress = $MacAddress
        }

        # Disabling DHCP on the Primary Interface
        NetIPInterface DisableDhcp {
            Dhcp           = 'Disabled'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }

        # Setting the IP Address on the Primary Interface
        IPAddress SetIP {
            IPAddress      = $IPADDR
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetIPInterface]DisableDhcp'
        }

        # Setting Default Gateway on Primary Interface
        DefaultGatewayAddress SetDefaultGateway {
            Address        = $GatewayAddress
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[IPAddress]SetIP'
        }

        # Setting DNS Server IPs on Primary Interface
        DnsServerAddress DnsServerAddress {
            Address        = $DomainController1IP, $DomainController2IP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[DefaultGatewayAddress]SetDefaultGateway'
        }

        # Setting Connection Suffix Primary Interface to domain FQDN
        DnsConnectionSuffix DnsConnectionSuffix {
            InterfaceAlias = 'Primary'
            ConnectionSpecificSuffix  = $DomainDNSName
            RegisterThisConnectionsAddress = $True
            UseSuffixWhenRegistering = $False
        }
       
        # Adding Required Windows Features
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

        WindowsFeature RSAT-AD-ManagementTools
        {
            Ensure    = 'Present'
            Name      = 'RSAT-AD-Tools'
            DependsOn = '[WindowsFeature]ADCSCA'
        }
        
        If ($UseS3ForCRL -eq 'No') {
            WindowsFeature IIS
            {
                Ensure    = 'Present'
                Name      = 'Web-WebServer'
                DependsOn = '[WindowsFeature]ADCSCA'
            }

            WindowsFeature IIS-ManagementTools
            {
                Ensure    = 'Present'
                Name      = 'Web-Mgmt-Console'
                DependsOn = '[WindowsFeature]ADCSCA'
            }
 
            WindowsFeature RSAT-DNS-ManagementTools
            {
                Ensure    = 'Present'
                Name      = 'RSAT-DNS-Server'
                DependsOn = '[WindowsFeature]ADCSCA'
            }
        }

        # Rename Computer and Join Domain
        Computer JoinDomain {
            Name       = $EntCaNetBIOSName
            DomainName = $DomainDnsName
            Credential = $Credentials
            DependsOn  = '[WindowsFeature]RSAT-ADCS-ManagementTools'
        }
    }
}

# Generating MOF File
ConfigEntCa -OutputPath 'C:\AWSQuickstart\ConfigEntCa' -Credentials $Credentials -ConfigurationData $ConfigurationData