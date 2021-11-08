Function New-VolumeFromRawDisk {

    #==================================================
    # Main
    #==================================================

    Write-Output 'Finding RAW Disk'
    $Counter = 0
    Do {
        Try {
            $BlankDisks = Get-Disk -ErrorAction Stop | Where-Object { $_.PartitionStyle -eq 'RAW' } | Select-Object -ExpandProperty 'Number'
        } Catch [System.Exception] {
            Write-Output "Failed to get disk $_"
            $BlankDisks = $Null
        }    
        If (-not $BlankDisks) {
            $Counter ++
            Write-Output 'RAW Disk not found sleeping 10 seconds and will try again.'
            Start-Sleep -Seconds 10
        }
    } Until ($BlankDisks -or $Counter -eq 12)

    If ($Counter -ge 12) {
        Write-Output 'RAW Disk not found exiting'
        Return
    }

    Foreach ($BlankDisk in $BlankDisks) {
        Write-Output 'Data Volume not initialized attempting to bring online'
        Try {
            Initialize-Disk -Number $BlankDisk -PartitionStyle 'GPT' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed attempting to bring Data Volume online $_"
            Exit 1
        }

        Start-Sleep -Seconds 5

        Write-Output 'Creating new partition for Data Volume'
        Try {
            $DriveLetter = New-Partition -DiskNumber $BlankDisk -AssignDriveLetter -UseMaximumSize -ErrorAction Stop | Select-Object -ExpandProperty 'DriveLetter'
        } Catch [System.Exception] {
            Write-Output "Failed creating new partition for Data Volume $_"
            Exit 1
        }

        Start-Sleep -Seconds 5

        Write-Output 'Formatting partition on Data Volume'
        Try {
            $Null = Format-Volume -DriveLetter $DriveLetter -FileSystem 'NTFS' -NewFileSystemLabel 'Data' -Confirm:$false -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to format partition on Data Volume $_"
            Exit 1
        }

        Write-Output 'Turning off Data Volume indexing'
        Try {
            $Null = Get-CimInstance -ClassName 'Win32_Volume' -Filter "DriveLetter='$($DriveLetter):'" -ErrorAction Stop | Set-CimInstance -Arguments @{ IndexingEnabled = $False }
        } Catch [System.Exception] {
            Write-Output "Failed to turn off Data Volume indexing $_"
            Exit 1
        }
    }
}

Function Set-CredSSP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable')][string]$Action
    )

    #==================================================
    # Variables
    #==================================================

    $RootKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows'
    $CredDelKey = 'CredentialsDelegation'
    $FreshCredKey = 'AllowFreshCredentials'
    $FreshCredKeyNTLM = 'AllowFreshCredentialsWhenNTLMOnly'

    #==================================================
    # Main
    #==================================================

    Switch ($Action) {
        'Enable' {
            Write-Output 'Enabling CredSSP'
            Try {
                $Null = Enable-WSManCredSSP -Role 'Client' -DelegateComputer '*' -Force -ErrorAction Stop
                $Null = Enable-WSManCredSSP -Role 'Server' -Force -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to enable CredSSP $_"
                $Null = Disable-WSManCredSSP -Role 'Client' -ErrorAction SilentlyContinue
                $Null = Disable-WSManCredSSP -Role 'Server' -ErrorAction SilentlyContinue
                Exit 1
            }
       
            Write-Output 'Setting CredSSP registry entries'
            $CredDelKeyPresent = Test-Path -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -ErrorAction SilentlyContinue
            If (-not $CredDelKeyPresent) {
                Try {
                    $CredDelPath = New-Item -Path $RootKey -Name $CredDelKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'

                    $FreshCredKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKey) -ErrorAction SilentlyContinue
                    If (-not $FreshCredKeyPresent) {
                        $FreshCredKeyPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                    }

                    $FreshCredKeyNTLMPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKeyNTLM) -ErrorAction SilentlyContinue
                    If (-not $FreshCredKeyNTLMPresent) {
                        $FreshCredKeyNTLMPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKeyNTLM -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                    }

                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentials' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFresh' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentialsWhenNTLMOnly' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$FreshCredKeyPath" -Name '1' -Value 'WSMAN/*' -PropertyType 'String' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$FreshCredKeyNTLMPath" -Name '1' -Value 'WSMAN/*' -PropertyType 'String' -Force -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-Output "Failed to create CredSSP registry entries $_"
                    Remove-Item -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -Force -Recurse
                    Exit 1
                }
            }
        }
        'Disable' {
            Write-Output 'Disabling CredSSP'
            Try {
                Disable-WSManCredSSP -Role 'Client' -ErrorAction Continue
                Disable-WSManCredSSP -Role 'Server' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to disable CredSSP $_"
                Exit 1
            }

            Write-Output 'Removing CredSSP registry entries'
            Try {
                Remove-Item -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -Force -Recurse
            } Catch [System.Exception] {
                Write-Output "Failed to remove CredSSP registry entries $_"
                Exit 1
            }
        }
        Default { 
            Write-Output 'InvalidArgument: Invalid value is passed for parameter Type' 
            Exit 1
        }
    }
}

Function Invoke-PreConfig {
    #==================================================
    # Main
    #==================================================
    Write-Output 'Temporarily disabling Windows Firewall'
    Try {
        Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled False -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to disable Windows Firewall $_"
        Exit 1
    }
    
    Write-Output 'Creating file directory for DSC public cert'
    Try {
        $Null = New-Item -Path 'C:\AWSQuickstart\publickeys' -ItemType 'Directory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create file directory for DSC public cert $_"
        Exit 1
    }
    
    Write-Output 'Creating certificate to encrypt credentials in MOF file'
    Try {
        $cert = New-SelfSignedCertificate -Type 'DocumentEncryptionCertLegacyCsp' -DnsName 'AWSQSDscEncryptCert' -HashAlgorithm 'SHA256' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create certificate to encrypt credentials in MOF file $_"
        Exit 1
    }
    
    Write-Output 'Exporting the self signed public key certificate'
    Try {
        $Null = $cert | Export-Certificate -FilePath 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy self signed cert to publickeys directory $_"
        Exit 1
    }    
}

Function Invoke-LcmConfig {
    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting the DSC cert thumbprint to secure the MOF file'
    Try {
        $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    } Catch [System.Exception] {
        Write-Output "Failed to get DSC cert thumbprint $_"
        Exit 1
    } 
    
    [DSCLocalConfigurationManager()]
    Configuration LCMConfig
    {
        Node 'localhost' {
            Settings {
                RefreshMode                    = 'Push'
                ConfigurationModeFrequencyMins = 15
                ActionAfterReboot              = 'StopConfiguration'                      
                RebootNodeIfNeeded             = $false
                ConfigurationMode              = 'ApplyAndAutoCorrect'
                CertificateId                  = $DscCertThumbprint  
            }
        }
    }
    
    Write-Output 'Generating MOF file for DSC LCM'
    LCMConfig -OutputPath 'C:\AWSQuickstart\LCMConfig'
        
    Write-Output 'Setting the DSC LCM configuration from the MOF generated in previous command'
    Try {
        Set-DscLocalConfigurationManager -Path 'C:\AWSQuickstart\LCMConfig' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set LCM configuration $_"
        Exit 1
    } 
}

Function Get-EniConfig {
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

    Write-Output 'Grabbing the current gateway address in order to static IP correctly'
    $GatewayAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'

    Write-Output 'Formatting IP address in format needed for IPAdress DSC resource'
    $IpAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
    $Prefix = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'PrefixLength'
    $IpAddr = 'IP/CIDR' -replace 'IP', $IpAddress -replace 'CIDR', $Prefix

    Write-Output 'Getting MAC address'
    Try {
        $MacAddress = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'MacAddress'
    } Catch [System.Exception] {
        Write-Output "Failed to get MAC address $_"
        Exit 1
    }

    $Output = [PSCustomObject][Ordered]@{
        'GatewayAddress' = $GatewayAddress
        'IpAddress'      = $IpAddr
        'MacAddress'     = $MacAddress
    }
    Return $Output
}

Function Get-SecretInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$Domain,
        [Parameter(Mandatory = $True)][String]$SecretArn
    )

    #==================================================
    # Main
    #==================================================

    Write-Output "Getting $SecretArn Secret"
    Try {
        $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get $SecretArn Secret $_"
        Exit 1
    }
       
    Write-Output 'Creating PSCredential object from Secret'
    $Username = $SecretContent.username
    $UserPassword = ConvertTo-SecureString ($SecretContent.password) -AsPlainText -Force
    $Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$Domain\$Username", $UserPassword)

    $Output = [PSCustomObject][Ordered]@{
        'Credentials'  = $Credentials
        'Username'     = $Username
        'UserPassword' = $UserPassword
    }

    Return $Output
}

Function Invoke-DscStatusCheck {

    #==================================================
    # Main
    #==================================================

    $LCMState = Get-DscLocalConfigurationManager -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'LCMState'
    If ($LCMState -eq 'PendingConfiguration' -Or $LCMState -eq 'PendingReboot') {
        Exit 3010
    } Else {
        Write-Output 'DSC configuration completed'
    }
}

Function Set-DscConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Enterprise', 'Offline')][string]$CaType,
        [Parameter(Mandatory = $false)][PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][string]$DomainController1IP,
        [Parameter(Mandatory = $true)][string]$DomainController2IP,
        [Parameter(Mandatory = $false)][string]$DomainDNSName,
        [Parameter(Mandatory = $true)][string]$GatewayAddress,
        [Parameter(Mandatory = $true)][string]$InstanceNetBIOSName,
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $true)][string]$MacAddress,
        [Parameter(Mandatory = $false)][ValidateSet('Yes', 'No')][string]$UseS3ForCRL
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting the DSC encryption certificate thumbprint to secure the MOF file'
    Try {
        $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    } Catch [System.Exception] {
        Write-Output "Failed to get DSC encryption certificate thumbprint $_"
        Exit 1
    }
    
    Write-Output 'Creating configuration data block that has the certificate information for DSC configuration processing'
    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName             = '*'
                CertificateFile      = 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer'
                Thumbprint           = $DscCertThumbprint
                PSDscAllowDomainUser = $true
            },
            @{
                NodeName = 'localhost'
            }
        )
    }
    
    Configuration ConfigInstance {

        Import-DscResource -ModuleName 'PSDesiredStateConfiguration', 'NetworkingDsc', 'ComputerManagementDsc'

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
                IPAddress      = $IpAddress
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
            WindowsFeature ADCSCA {
                Name      = 'ADCS-Cert-Authority'
                Ensure    = 'Present'
                DependsOn = '[DnsServerAddress]DnsServerAddress'
            }
            WindowsFeature RSAT-ADCS-ManagementTools {
                Name      = 'RSAT-ADCS'
                Ensure    = 'Present'
                DependsOn = '[WindowsFeature]ADCSCA'
            }
            Switch ($CaType) {
                'Enterprise' {
                    WindowsFeature RSAT-AD-ManagementTools {
                        Ensure    = 'Present'
                        Name      = 'RSAT-AD-Tools'
                        DependsOn = '[WindowsFeature]RSAT-ADCS-ManagementTools'
                    }
                    DnsConnectionSuffix DnsConnectionSuffix {
                        InterfaceAlias                 = 'Primary'
                        ConnectionSpecificSuffix       = $DomainDNSName
                        RegisterThisConnectionsAddress = $True
                        UseSuffixWhenRegistering       = $False
                        DependsOn                      = '[WindowsFeature]RSAT-AD-ManagementTools'
                    }
                    If ($UseS3ForCRL -eq 'No') {
                        WindowsFeature IIS {
                            Ensure    = 'Present'
                            Name      = 'Web-WebServer'
                            DependsOn = '[DnsConnectionSuffix]DnsConnectionSuffix'
                        }
                        WindowsFeature IIS-ManagementTools {
                            Ensure    = 'Present'
                            Name      = 'Web-Mgmt-Console'
                            DependsOn = '[WindowsFeature]IIS'
                        }
                        WindowsFeature RSAT-DNS-ManagementTools {
                            Ensure    = 'Present'
                            Name      = 'RSAT-DNS-Server'
                            DependsOn = '[WindowsFeature]IIS-ManagementTools'
                        }
                    }
                    Computer JoinDomain {
                        Name       = $InstanceNetBIOSName
                        DomainName = $DomainDnsName
                        Credential = $Credentials
                        DependsOn  = '[DnsConnectionSuffix]DnsConnectionSuffix'
                    }
                }
                'Offline' {
                    Computer Rename {
                        Name      = $InstanceNetBIOSName
                        DependsOn = '[WindowsFeature]RSAT-ADCS-ManagementTools'
                    }
                }
            }
        }    
    }
    
    Write-Output 'Generating MOF file'
    ConfigInstance -OutputPath 'C:\AWSQuickstart\ConfigInstance' -ConfigurationData $ConfigurationData
}

Function Invoke-EnterpriseCaConfig {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$EntCaCommonName,
        [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$EntCaHashAlgorithm,
        [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$EntCaKeyLength,
        [Parameter(Mandatory = $true)][String]$EntCaValidityPeriodUnits,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL
    )

    #==================================================
    # Variables
    #==================================================

    Write-Output 'Getting AD domain information'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain information $_"
        Exit 1
    }

    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
    $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $Netbios = $Domain | Select-Object -ExpandProperty 'NetBIOSName'
    $CompName = $env:COMPUTERNAME
    $Folders = @(
        'D:\Pki\Req',
        'D:\ADCS\DB',
        'D:\ADCS\Log'
    )
    $FilePath = 'D:\Pki'
    $Principals = @(
        'ANONYMOUS LOGON',
        'EVERYONE'
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting a Domain Controller to perform actions against'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-Output "Failed to get a Domain Controller $_"
        Exit 1
    }

    If ($UseS3ForCRL -eq 'No') {
        $Counter = 0
        Do {
            $ARecordPresent = Resolve-DnsName -Name "$CompName.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $ARecordPresent) {
                $Counter ++
                Write-Output 'CA A record missing.'
                Register-DnsClient
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($ARecordPresent -or $Counter -eq 12)

        If ($Counter -ge 12) {
            Write-Output 'CA A record never created'
            Exit 1
        }

        If ($DirectoryType -eq 'AWSManaged') {
            Write-Output 'Enabling CredSSP'
            Set-CredSSP -Action 'Enable'
        }

        Write-Output 'Creating PKI CNAME record'
        $Counter = 0
        Do {
            $CnameRecordPresent = Resolve-DnsName -Name "PKI.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $CnameRecordPresent) {
                $Counter ++
                Write-Output 'PKI CNAME record missing.'
                $HostNameAlias = "$CompName.$FQDN"
                Switch ($DirectoryType) {
                    'SelfManaged' {
                        Invoke-Command -ComputerName $DC -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                    'AWSManaged' {
                        Invoke-Command -Authentication 'CredSSP' -ComputerName $env:COMPUTERNAME -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -ComputerName $using:DC -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                }
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($CnameRecordPresent -or $Counter -eq 12)

        Write-Output 'Disabling CredSSP'
        Set-CredSSP -Action 'Disable'
        
        If ($Counter -ge 12) {
            Write-Output 'ERROR: CNAME record never created, please create the record manually'
        }
    }

    Write-Output 'Creating PKI directories'
    Foreach ($Folder in $Folders) {
        $PathPresent = Test-Path -Path $Folder -ErrorAction SilentlyContinue
        If (-not $PathPresent) {
            Try {
                $Null = New-Item -Path $Folder -Type 'Directory' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create $Folder directory $_"
                Exit 1
            }
        } 
    }

    Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'

    If ($UseS3ForCRL -eq 'No') {
        Write-Output 'Sharing PKI folder'
        $SharePresent = Get-SmbShare -Name 'Pki' -ErrorAction SilentlyContinue
        If (-not $SharePresent) {
            Try {
                $Null = New-SmbShare -Name 'Pki' -Path 'D:\Pki' -FullAccess 'SYSTEM', "$Netbios\Domain Admins" -ChangeAccess "$Netbios\Cert Publishers" -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create PKI SMB share $_"
                Exit 1
            }
        }

        Write-Output 'Creating PKI IIS virtual directory'
        $VdPresent = Get-WebVirtualDirectory -Name 'Pki'
        If (-not $VdPresent) {
            Try {
                $Null = New-WebVirtualDirectory -Site 'Default Web Site' -Name 'Pki' -PhysicalPath 'D:\Pki' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create IIS virtual directory $_"
                Exit 1
            }
        }

        Write-Output 'Setting PKI IIS virtual directory requestFiltering'
        Try {
            Set-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set IIS requestFiltering $_"
            Exit 1
        }

        Write-Output 'Setting PKI IIS virtual directory directoryBrowse'
        Try {
            Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set IIS directoryBrowse $_"
            Exit 1
        }

        Write-Output 'Setting PKI folder file system ACLs'
        Foreach ($Princ in $Principals) {
            $Principal = New-Object -TypeName 'System.Security.Principal.NTAccount'($Princ)
            $Perms = [System.Security.AccessControl.FileSystemRights]'Read, ReadAndExecute, ListDirectory'
            $Inheritance = [System.Security.AccessControl.InheritanceFlags]::'ContainerInherit', 'ObjectInherit'
            $Propagation = [System.Security.AccessControl.PropagationFlags]::'None'
            $Access = [System.Security.AccessControl.AccessControlType]::'Allow'
            $AccessRule = New-Object -TypeName 'System.Security.AccessControl.FileSystemAccessRule'($Principal, $Perms, $Inheritance, $Propagation, $Access) 
            Try {
                $Acl = Get-Acl -Path $FilePath -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to get ACL for PKI directory $_"
                Exit 1
            }
            $Acl.AddAccessRule($AccessRule)
            Try {
                Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to set ACL for PKI directory $_"
                Exit 1
            }
        }

        Write-Output 'Resetting IIS service'
        Try {
            & iisreset.exe > $null
        } Catch [System.Exception] {
            Write-Output "Failed to reset IIS service $_"
            Exit 1
        }
        If ($DirectoryType -eq 'SelfManaged') {
            $URL = "URL=http://pki.$FQDN/pki/cps.txt"
        } Else {
            $URL = "URL=http://$CompName.$FQDN/pki/cps.txt"
        }
    } Else {
        Write-Output 'Getting S3 bucket location'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get S3 bucket location $_"
            Exit 1
        }  

        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }
        $URL = "URL=http://$S3BucketUrl/$CompName/cps.txt"

        Write-Output 'Copying cps.txt to S3 bucket'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'D:\Pki\' -KeyPrefix "$CompName\" -SearchPattern 'cps.txt' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to copy cps.txt to S3 bucket $_"
            Exit 1
        }
    }

    $Inf = @(
        '[Version]',
        'Signature="$Windows NT$"',
        '[PolicyStatementExtension]',
        'Policies=InternalPolicy',
        '[InternalPolicy]',
        'OID=1.2.3.4.1455.67.89.5', 
        'Notice="Legal Policy Statement"',
        $URL
        '[Certsrv_Server]',
        "RenewalKeyLength=$EntCaKeyLength",
        'RenewalValidityPeriod=Years',
        "RenewalValidityPeriodUnits=$EntCaValidityPeriodUnits",
        'CRLPeriod=Weeks',
        'CRLPeriodUnits=1',
        'CRLDeltaPeriod=Days',  
        'CRLDeltaPeriodUnits=0',
        'LoadDefaultTemplates=0',
        'AlternateSignatureAlgorithm=0',
        '[CRLDistributionPoint]',
        '[AuthorityInformationAccess]'
    )

    Write-Output 'Creating CAPolicy.inf'
    Try {
        $Inf | Out-File -FilePath 'C:\Windows\CAPolicy.inf' -Encoding 'ascii'
    } Catch [System.Exception] {
        Write-Output "Failed to create CAPolicy.inf $_"
        Exit 1
    }

    Write-Output 'Installing Enterprise Root CA'
    Try {
        $Null = Install-AdcsCertificationAuthority -CAType 'EnterpriseRootCA' -CACommonName $EntCaCommonName -KeyLength $EntCaKeyLength -HashAlgorithm $EntCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -ValidityPeriod 'Years' -ValidityPeriodUnits $EntCaValidityPeriodUnits -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -ErrorAction Stop -Credential $Credentials
    } Catch [System.Exception] {
        Write-Output "Failed to install Enterprise Root CA $_"
        Exit 1
    }

    If ($UseS3ForCRL -eq 'No') {
        If ($DirectoryType -eq 'SelfManaged') {
            $CDP = "http://pki.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://pki.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        } Else {
            $CDP = "http://$CompName.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://$CompName.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        }
    } Else {
        $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
    }

    Write-Output 'Configuring CRL distro points'
    Try {
        $Null = Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
        $Null = Add-CACRLDistributionPoint -Uri $CDP -AddToCertificateCDP -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed set CRL distro points $_"
        Exit 1
    }

    Write-Output 'Configuring AIA distro points'
    Try {
        $Null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop
        $Null = Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri $AIA -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed set AIA distro points $_"
        Exit 1
    }

    Write-Output 'Configuring Enterprise Root CA'
    & certutil.exe -setreg CA\CRLOverlapPeriodUnits '12' > $null
    & certutil.exe -setreg CA\CRLOverlapPeriod 'Hours' > $null
    & certutil.exe -setreg CA\ValidityPeriodUnits '5' > $null
    & certutil.exe -setreg CA\ValidityPeriod 'Years' > $null
    & certutil.exe -setreg CA\AuditFilter '127' > $null
    & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable > $null

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
        Exit 1
    }

    Start-Sleep -Seconds 10

    Write-Output 'Publishing CRL'
    & certutil.exe -crl > $null

    Write-Output 'Copying CRL to PKI folder'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy CRL to PKI folder $_"
        Exit 1
    }

    If ($UseS3ForCRL -eq 'Yes') {
        Write-Output 'Copying CRL to S3 bucket'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'C:\Windows\System32\CertSrv\CertEnroll\' -KeyPrefix "$CompName\" -SearchPattern '*.cr*' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to copy CRL to S3 bucket $_"
            Exit 1
        }
    }

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
    }

    Write-Output 'Creating LdapOverSSL-QS certificate template'
    New-KerbCertTemplate -BaseDn $BaseDn -Credential $Credentials -Server $DC

    If ($DirectoryType -eq 'SelfManaged') {
        Write-Output 'Getting domain controllers'
        Try {
            $DomainControllers = Get-ADComputer -SearchBase "OU=Domain Controllers,$BaseDn" -Filter * | Select-Object -ExpandProperty 'DNSHostName'
        } Catch [System.Exception] {
            Write-Output "Failed to get domain controllers $_"
        }

        Write-Output 'Running Group Policy update'
        Foreach ($DomainController in $DomainControllers) {
            Invoke-Command -ComputerName $DomainController -Credential $Credentials -ScriptBlock { Invoke-GPUpdate -RandomDelayInMinutes '0' -Force }
        }
    }

    Write-Output 'Creating Update CRL Scheduled Task'
    Try {
        If ($UseS3ForCRL -eq 'No') {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
        } Else {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
        }
        $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval '5' -At '12am' -ErrorAction Stop
        $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
        $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
        $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
        $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed register Update CRL Scheduled Task $_"
    }

    Write-Output 'Running CRL Scheduled Task'
    Try {
        Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed run CRL Scheduled Task $_"
    }

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
    }
}

Function Invoke-Cleanup {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$VPCCIDR
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic'
    Try {
        Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed allow WinRM Traffic from VPC CIDR $_"
    }

    Write-Output 'Removing DSC configuration'
    Try {    
        Remove-DscConfigurationDocument -Stage 'Current' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to remove DSC configuration $_"
    }

    Write-Output 'Re-enabling Windows Firewall'
    Try {
        Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled 'True' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed re-enable Windows Firewall $_"
    }

    Write-Output 'Removing QuickStart build files'
    Try {
        Remove-Item -Path 'C:\AWSQuickstart' -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove QuickStart build files $_"
    }

    Write-Output 'Removing self signed cert'
    Try {
        $SelfSignedThumb = Get-ChildItem -Path 'cert:\LocalMachine\My\' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
        Remove-Item -Path "cert:\LocalMachine\My\$SelfSignedThumb" -DeleteKey -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove self signed cert $_"
    }
}

Function Invoke-TwoTierOrCaConfig {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$DomainDNSName,
        [Parameter(Mandatory = $true)][String]$OrCaCommonName,
        [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$OrCaHashAlgorithm,
        [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$OrCaKeyLength,
        [Parameter(Mandatory = $true)][String]$OrCaValidityPeriodUnits,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][String]$SubCaServerNetBIOSName,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL
    )
    #==================================================
    # Variables
    #==================================================

    $CompName = $env:COMPUTERNAME
    $Folders = @(
        'D:\Pki\SubCA',
        'D:\ADCS\DB',
        'D:\ADCS\Log'
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Creating PKI directories'
    Foreach ($Folder in $Folders) {
        $PathPresent = Test-Path -Path $Folder
        If (-not $PathPresent) {
            Try {
                $Null = New-Item -Path $Folder -Type 'Directory' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create $Folder directory $_"
                Exit 1
            }
        } 
    }

    Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'

    If ($UseS3ForCRL -eq 'No') {
        If ($DirectoryType -eq 'SelfManaged') {
            $URL = "URL=http://pki.$DomainDNSName/pki/cps.txt"
        } Else {
            $URL = "URL=http://$SubCaServerNetBIOSName.$DomainDNSName/pki/cps.txt"
        }
    } Else {
        Write-Output 'Getting S3 bucket location'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get S3 bucket location $_"
            Exit 1
        }

        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }
        $URL = "URL=http://$S3BucketUrl/$CompName/cps.txt"

        Write-Output 'Copying cps.txt to S3 bucket'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'D:\Pki\' -KeyPrefix "$CompName\" -SearchPattern 'cps.txt' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to copy cps.txt to S3 bucket $_"
            Exit 1
        }
    }

    $Inf = @(
        '[Version]',
        'Signature="$Windows NT$"',
        '[PolicyStatementExtension]',
        'Policies=InternalPolicy',
        '[InternalPolicy]',
        'OID=1.2.3.4.1455.67.89.5', 
        'Notice="Legal Policy Statement"',
        $URL
        '[Certsrv_Server]',
        "RenewalKeyLength=$OrCaKeyLength",
        'RenewalValidityPeriod=Years',
        "RenewalValidityPeriodUnits=$OrCaValidityPeriodUnits",
        'CRLPeriod=Weeks',
        'CRLPeriodUnits=26',
        'CRLDeltaPeriod=Days',  
        'CRLDeltaPeriodUnits=0',
        'LoadDefaultTemplates=0',
        'AlternateSignatureAlgorithm=0',
        '[CRLDistributionPoint]',
        '[AuthorityInformationAccess]'
    )

    Write-Output 'Creating CAPolicy.inf'
    Try {
        $Inf | Out-File -FilePath 'C:\Windows\CAPolicy.inf' -Encoding 'ascii'
    } Catch [System.Exception] {
        Write-Output "Failed to create CAPolicy.inf $_"
        Exit 1
    }

    Write-Output 'Installing Offline Root CA'
    Try {
        $Null = Install-AdcsCertificationAuthority -CAType 'StandaloneRootCA' -CACommonName $OrCaCommonName -KeyLength $OrCaKeyLength -HashAlgorithm $OrCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -ValidityPeriod 'Years' -ValidityPeriodUnits $OrCaValidityPeriodUnits -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to install Offline Root CA $_"
        Exit 1
    }

    If ($UseS3ForCRL -eq 'No') {
        If ($DirectoryType -eq 'SelfManaged') {
            $CDP = "http://pki.$DomainDNSName/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://pki.$DomainDNSName/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        } Else {
            $CDP = "http://$SubCaServerNetBIOSName.$DomainDNSName/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://$SubCaServerNetBIOSName.$DomainDNSName/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        }
    } Else {
        $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
    }

    Write-Output 'Configuring CRL distro points'
    Try {
        $Null = Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
        $Null = Add-CACRLDistributionPoint -Uri $CDP -AddToCertificateCDP -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed set CRL distro points $_"
        Exit 1
    }

    Write-Output 'Configuring AIA distro points'
    Try {
        $Null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop
        $Null = Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri $AIA -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed set AIA distro points $_"
        Exit 1
    }

    Write-Output 'Configuring Offline Root CA'
    & certutil.exe -setreg CA\CRLOverlapPeriodUnits '12' > $null
    & certutil.exe -setreg CA\CRLOverlapPeriod 'Hours' > $null
    & certutil.exe -setreg CA\ValidityPeriodUnits '5' > $null
    & certutil.exe -setreg CA\ValidityPeriod 'Years' > $null
    & certutil.exe -setreg CA\AuditFilter '127' > $null
    & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable > $null

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
        Exit 1
    }

    Start-Sleep -Seconds 10

    Write-Output 'Publishing CRL'
    & certutil.exe -crl > $null

    Write-Output 'Copying CRL to PKI folder'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy CRL to PKI folder  $_"
        Exit 1
    }

    If ($UseS3ForCRL -eq 'Yes') {
        Write-Output 'Copying CRL to S3 bucket'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'C:\Windows\System32\CertSrv\CertEnroll\' -KeyPrefix "$CompName\" -SearchPattern '*.cr*' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to copy CRL to S3 bucket $_"
            Exit 1
        }
    }

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
    }

    Write-Output 'Creating Update CRL Scheduled Task'
    Try {
        If ($UseS3ForCRL -eq 'No') {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
        } Else {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
        }
        $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval '25' -DaysOfWeek 'Sunday' -At '12am' -ErrorAction Stop
        $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
        $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
        $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
        $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed register Update CRL Scheduled Task $_"
    }

    Write-Output 'Running CRL Scheduled Task'
    Try {
        Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed run CRL Scheduled Task $_"
    }

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
    }

    Write-Output 'Creating PkiSysvolPSDrive'
    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName"
    } Else {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName\Policies"
    }

    Try {
        $Null = New-PSDrive -Name 'PkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create PkiSysvolPSDrive $_"
        Exit 1
    }

    Write-Output 'Creating the PkiRootCA SYSVOL folder'
    Try {
        $Null = New-Item -ItemType 'Directory' -Path 'PkiSysvolPSDrive:\PkiRootCA' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create PkiRootCA SYSVOL folder $_"
        Exit 1
    }

    Write-Output 'Copying CertEnroll contents to SYSVOL PkiRootCA folder'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'PkiSysvolPSDrive:\PkiRootCA' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy CertEnroll contents to SYSVOL PkiRootCA folder $_"
        Exit 1
    }

    Write-Output 'Removing PkiSysvolPSDrive'
    Try {
        Remove-PSDrive -Name 'PkiSysvolPSDrive' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to remove PkiSysvolPSDrive $_"
        Exit 1
    }
}

Function Invoke-TwoTierSubCaInstall {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][String]$SubCaCommonName,
        [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$SubCaHashAlgorithm,
        [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$SubCaKeyLength,
        [Parameter(Mandatory = $true)][String]$SubCaValidityPeriodUnits,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL
    )

    #==================================================
    # Variables
    #==================================================

    $CompName = $env:COMPUTERNAME

    Write-Output 'Getting AD domain information'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain information $_"
        Exit 1
    }

    Write-Output 'Getting a Domain Controller to perform actions against'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-Output "Failed to get a Domain Controller $_"
        Exit 1
    }

    $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $Netbios = $Domain | Select-Object -ExpandProperty 'NetBIOSName'
    $Folders = @(
        'D:\Pki\Req',
        'D:\ADCS\DB',
        'D:\ADCS\Log'
    )
    $FilePath = 'D:\Pki'
    $Principals = @(
        'ANONYMOUS LOGON',
        'EVERYONE'
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Adding computer account to elevated permission group for install'
    If ($DirectoryType -eq 'SelfManaged') {
        Try {
            Add-ADGroupMember -Identity 'Enterprise Admins' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName') -Credential $Credentials -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to add computer account to Enterprise Admins $_"
            Exit 1
        }
    } Else {
        Try {
            Add-ADGroupMember -Identity 'AWS Delegated Enterprise Certificate Authority Administrators' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName') -Credential $Credentials -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to add computer account to AWS Delegated Enterprise Certificate Authority Administrators $_"
            Exit 1
        }
    }

    Write-Output 'Sleeping to ensure replication of group membership has completed'
    Start-Sleep -Seconds 60 

    Write-Output 'Clearing all SYSTEM Kerberos tickets'
    & Klist.exe -li 0x3e7 purge > $null
    Start-Sleep -Seconds 5

    If ($UseS3ForCRL -eq 'No') {
        $Counter = 0
        Do {
            $ARecordPresent = Resolve-DnsName -Name "$CompName.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $ARecordPresent) {
                $Counter ++
                Write-Output 'CA A record missing.'
                Register-DnsClient
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($ARecordPresent -or $Counter -eq 12)

        If ($Counter -ge 12) {
            Write-Output 'CA A record never created'
            Exit 1
        }

        If ($DirectoryType -eq 'AWSManaged') {
            Write-Output 'Enabling CredSSP'
            Set-CredSSP -Action 'Enable'
        }

        Write-Output 'Creating PKI CNAME record'
        $Counter = 0
        Do {
            $CnameRecordPresent = Resolve-DnsName -Name "PKI.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $CnameRecordPresent) {
                $Counter ++
                Write-Output 'PKI CNAME record missing.'
                $HostNameAlias = "$CompName.$FQDN"
                Switch ($DirectoryType) {
                    'SelfManaged' {
                        Invoke-Command -ComputerName $DC -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                    'AWSManaged' {
                        Invoke-Command -Authentication 'CredSSP' -ComputerName $env:COMPUTERNAME -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -ComputerName $using:DC -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                }
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($CnameRecordPresent -or $Counter -eq 12)

        Write-Output 'Disabling CredSSP'
        Set-CredSSP -Action 'Disable'

        If ($Counter -ge 12) {
            Write-Output 'ERROR: CNAME record never created, please create the record manually'
        }
    }

    Write-Output 'Creating PKI folders'
    Foreach ($Folder in $Folders) {
        $PathPresent = Test-Path -Path $Folder -ErrorAction SilentlyContinue
        If (-not $PathPresent) {
            Try {
                $Null = New-Item -Path $Folder -Type 'Directory' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create $Folder folder $_"
                Exit 1
            }
        } 
    }

    Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'

    If ($UseS3ForCRL -eq 'No') {
        Write-Output 'Sharing PKI folder'
        $SharePresent = Get-SmbShare -Name 'Pki' -ErrorAction SilentlyContinue
        If (-not $SharePresent) {
            Try {
                $Null = New-SmbShare -Name 'Pki' -Path 'D:\Pki' -FullAccess 'SYSTEM', "$Netbios\Domain Admins" -ChangeAccess "$Netbios\Cert Publishers" -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create PKI SMB share $_"
                Exit 1
            }
        }

        Write-Output 'Creating PKI IIS virtual directory'
        $VdPresent = Get-WebVirtualDirectory -Name 'Pki'
        If (-not $VdPresent) {
            Try {
                $Null = New-WebVirtualDirectory -Site 'Default Web Site' -Name 'Pki' -PhysicalPath 'D:\Pki' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create IIS virtual directory $_"
                Exit 1
            }
        }

        Write-Output 'Setting PKI IIS virtual directory requestFiltering'
        Try {
            $Null = Set-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set IIS requestFiltering $_"
            Exit 1
        }

        Write-Output 'Setting PKI IIS virtual directory directoryBrowse'
        Try {
            $Null = Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set IIS directoryBrowse $_"
            Exit 1
        }
        Write-Output 'Setting PKI folder file system ACLs'
        Foreach ($Princ in $Principals) {
            $Principal = New-Object -TypeName 'System.Security.Principal.NTAccount'($Princ)
            $Perms = [System.Security.AccessControl.FileSystemRights]'Read, ReadAndExecute, ListDirectory'
            $Inheritance = [System.Security.AccessControl.InheritanceFlags]::'ContainerInherit', 'ObjectInherit'
            $Propagation = [System.Security.AccessControl.PropagationFlags]::'None'
            $Access = [System.Security.AccessControl.AccessControlType]::'Allow'
            $AccessRule = New-Object -TypeName 'System.Security.AccessControl.FileSystemAccessRule'($Principal, $Perms, $Inheritance, $Propagation, $Access) 
            Try {
                $Acl = Get-Acl -Path $FilePath -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to get ACL for PKI directory $_"
                Exit 1
            }
            $Acl.AddAccessRule($AccessRule)
            Try {
                Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to set ACL for PKI directory $_"
                Exit 1
            }
        }

        Write-Output 'Resetting IIS service'
        Try {
            & iisreset.exe > $null
        } Catch [System.Exception] {
            Write-Output "Failed to reset IIS service $_"
            Exit 1
        }

        If ($DirectoryType -eq 'SelfManaged') {
            $URL = "URL=http://pki.$FQDN/pki/cps.txt"
        } Else {
            $URL = "URL=http://$CompName.$FQDN/pki/cps.txt"
        }
    } Else {
        Write-Output 'Getting S3 bucket location'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get S3 bucket location $_"
            Exit 1
        }

        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }
        $URL = "URL=http://$S3BucketUrl/SubCa/cps.txt"

        Write-Output 'Copying cps.txt to S3 bucket'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'D:\Pki\' -KeyPrefix "$CompName\" -SearchPattern 'cps.txt' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to copy cps.txt to S3 bucket $_"
            Exit 1
        }
    }

    $Inf = @(
        '[Version]',
        'Signature="$Windows NT$"',
        '[PolicyStatementExtension]',
        'Policies=InternalPolicy',
        '[InternalPolicy]',
        'OID=1.2.3.4.1455.67.89.5', 
        'Notice="Legal Policy Statement"',
        $URL
        '[Certsrv_Server]',
        "RenewalKeyLength=$SubCaKeyLength",
        'RenewalValidityPeriod=Years',
        "RenewalValidityPeriodUnits=$SubCaValidityPeriodUnits",
        'CRLPeriod=Weeks',
        'CRLPeriodUnits=1',
        'CRLDeltaPeriod=Days',  
        'CRLDeltaPeriodUnits=0',
        'LoadDefaultTemplates=0',
        'AlternateSignatureAlgorithm=0',
        '[CRLDistributionPoint]',
        '[AuthorityInformationAccess]'
    )

    Write-Output 'Creating CAPolicy.inf'
    Try {
        $Inf | Out-File -FilePath 'C:\Windows\CAPolicy.inf' -Encoding 'ascii'
    } Catch [System.Exception] {
        Write-Output "Failed to create CAPolicy.inf $_"
        Exit 1
    }

    Write-Output 'Creating SubPkiSysvolPSDrive'
    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN"
    } Else {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN\Policies"
    }

    Try {
        $Null = New-PSDrive -Name 'SubPkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create SubPkiSysvolPSDrive $_"
        Exit 1
    }

    Write-Output 'Creating the PkiSubCA SYSVOL folder'
    Try {
        $Null = New-Item -ItemType 'Directory' -Path 'SubPkiSysvolPSDrive:\PkiSubCA' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create PkiSubCA SYSVOL folder $_"
        Exit 1
    }

    Write-Output 'Copying the SYSVOL PkiRootCA Contents to local folder'
    Try {
        Copy-Item -Path 'SubPkiSysvolPSDrive:\PkiRootCA\*.cr*' -Destination 'D:\Pki' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy PkiRootCA SYSVOL folder contents $_"
        Exit 1
    }

    $OrcaCert = Get-ChildItem -Path 'D:\Pki\*.crt' -ErrorAction Stop
    $OrcaCertFn = $OrcaCert | Select-Object -ExpandProperty 'FullName'
    $OrcaCrlFn = Get-ChildItem -Path 'D:\Pki\*.crl' | Select-Object -ExpandProperty 'FullName'

    Write-Output 'Publishing Offline CA certificates and CRLs'
    & certutil.exe -dspublish -f $OrcaCertFn RootCA > $null
    & certutil.exe -addstore -f root $OrcaCertFn > $null
    & certutil.exe -addstore -f root $OrcaCrlFn > $null

    Write-Output 'Installing Subordinate CA'
    Try {
        Install-AdcsCertificationAuthority -CAType 'EnterpriseSubordinateCA' -CACommonName $SubCaCommonName -KeyLength $SubCaKeyLength -HashAlgorithm $SubCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -OutputCertRequestFile 'D:\Pki\Req\SubCa.req' -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -WarningAction SilentlyContinue -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create install Subordinate CA $_"
    }

    Write-Output 'Copying SubCa.req to PkiSubCA SYSVOL folder'
    Try {
        Copy-Item -Path 'D:\Pki\Req\SubCa.req' -Destination 'SubPkiSysvolPSDrive:\PkiSubCA\SubCa.req'
    } Catch [System.Exception] {
        Write-Output "Failed to copy SubCa.req to PkiSubCA SYSVOL folder $_"
        Exit 1
    }

    Write-Output 'Removing SubPkiSysvolPSDrive'
    Try {
        Remove-PSDrive -Name 'SubPkiSysvolPSDrive' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to remove SubPkiSysvolPSDrive $_"
        Exit 1
    }
}

Function Invoke-TwoTierSubCaCertIssue {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$DomainDNSName
    )

    #==================================================
    # Variables
    #==================================================

    $CAComputerName = "$env:COMPUTERNAME\$env:COMPUTERNAME"

    #==================================================
    # Main
    #==================================================

    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName"
    } Else {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName\Policies"
    }

    Write-Output 'Creating IssuePkiSysvolPSDrive'
    Try {
        $Null = New-PSDrive -Name 'IssuePkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create IssuePkiSysvolPSDrive $_"
        Exit 1
    }

    Write-Output 'Copying SubCa.req from PkiSubCA SYSVOL folder'
    Try {
        Copy-Item -Path 'IssuePkiSysvolPSDrive:\PkiSubCA\SubCa.req' -Destination 'D:\Pki\SubCA\SubCa.req' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy SubCa.req from PkiSubCA SYSVOL folder $_"
        Exit 1
    }

    Write-Output 'Submitting, issuing and retrieving the SubCA certificate'
    $SubReq = 'D:\Pki\SubCA\SubCa.req'
    $Request = & Certreq.exe -f -q -config $CAComputerName -Submit $SubReq 'D:\Pki\SubCA\SubCa.cer'
    $RequestString = $Request | Select-String -Pattern 'RequestId:.\d$'
    $RequestId = $RequestString -replace ('RequestId: ', '')
    & Certutil.exe -config $CAComputerName -Resubmit $RequestId > $null
    & Certreq.exe -f -q -config $CAComputerName -Retrieve $RequestId 'D:\Pki\SubCA\SubCa.cer' > $null

    Write-Output 'Copying SubCa.cer to PkiSubCA SYSVOL folder'
    Try {
        Copy-Item -Path 'D:\Pki\SubCA\SubCa.cer' -Destination 'IssuePkiSysvolPSDrive:\PkiSubCA\SubCa.cer' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy SubCa.req from PkiSubCA SYSVOL folder $_"
        Exit 1
    }

    Write-Output 'Removing IssuePkiSysvolPSDrive'
    Try {
        Remove-PSDrive -Name 'IssuePkiSysvolPSDrive' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to remove IssuePkiSysvolPSDrive $_"
        Exit 1
    }

    Write-Output 'Removing SubCA certificate request files'
    Try {
        Remove-Item -Path 'D:\Pki\SubCA' -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove SubCA certificate files $_"
    }
}

Function Invoke-TwoTierSubCaConfig {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL
    )

    #==================================================
    # Variables
    #==================================================

    Write-Output 'Getting AD domain information'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain information $_"
        Exit 1
    }

    $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
    $CompName = $env:COMPUTERNAME
    $SvolFolders = @(
        'CertPkiSysvolPSDrive:\PkiSubCA',
        'CertPkiSysvolPSDrive:\PkiRootCA'
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting a Domain Controller to perform actions against'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-Output "Failed to get a Domain Controller $_"
        Exit 1
    }

    Write-Output 'Creating CertPkiSysvolPSDrive'
    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN"
    } Else {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN\Policies"
    }

    Try {
        $Null = New-PSDrive -Name 'CertPkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create CertPkiSysvolPSDrive $_"
        Exit 1
    }

    Write-Output 'Copying SubCa.cer from PkiSubCA SYSVOL folder'
    Try {
        Copy-Item -Path 'CertPkiSysvolPSDrive:\PkiSubCA\SubCa.cer' -Destination 'D:\Pki\Req\SubCa.cer' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy SubCa.cer from PkiSubCA SYSVOL folder $_"
        Exit 1
    }

    Write-Output 'Installing SubCA certificate'
    & certutil.exe -f -silent -installcert 'D:\Pki\Req\SubCa.cer' > $null

    Start-Sleep -Seconds 5

    Write-Output 'Starting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
        Exit 1
    }

    If ($UseS3ForCRL -eq 'Yes') {
        Write-Output 'Getting S3 bucket location'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get S3 bucket location $_"
            Exit 1
        }

        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }

        $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
    } Else {
        If ($DirectoryType -eq 'SelfManaged') {
            $CDP = "http://pki.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://pki.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        } Else {
            $CDP = "http://$CompName.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://$CompName.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        }
    }

    Write-Output 'Configuring CRL distro points'
    Try {
        $Null = Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
        $Null = Add-CACRLDistributionPoint -Uri $CDP -AddToCertificateCDP -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed set CRL istro points $_"
        Exit 1
    }

    Write-Output 'Configuring AIA distro points'
    Try {
        $Null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop
        $Null = Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri $AIA -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed set AIA distro points $_"
        Exit 1
    }

    Write-Output 'Configuring Subordinate Enterprise CA'
    & certutil.exe -setreg CA\CRLOverlapPeriodUnits '12' > $null
    & certutil.exe -setreg CA\CRLOverlapPeriod 'Hours' > $null
    & certutil.exe -setreg CA\ValidityPeriodUnits '5' > $null
    & certutil.exe -setreg CA\ValidityPeriod 'Years' > $null
    & certutil.exe -setreg CA\AuditFilter '127' > $null
    & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable > $null

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
        Exit 1
    }

    Start-Sleep -Seconds 10

    Write-Output 'Publishing CRL'
    & certutil.exe -crl > $null

    Write-Output 'Copying CRL to PKI folder'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy CRL to PKI folder  $_"
        Exit 1
    }

    If ($UseS3ForCRL -eq 'Yes') {
        Write-Output 'Copying CRL to S3 bucket'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'C:\Windows\System32\CertSrv\CertEnroll\' -KeyPrefix "$CompName\" -SearchPattern '*.cr*' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to copy CRL to S3 bucket $_"
            Exit 1
        }
    }

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
    }

    Write-Output 'Creating LdapOverSSL-QS certificate template'
    New-KerbCertTemplate -BaseDn $BaseDn -Credential $Credentials -Server $DC

    If ($DirectoryType -eq 'SelfManaged') {

        Write-Output 'Getting domain controllers'
        Try {
            $DomainControllers = Get-ADComputer -SearchBase "OU=Domain Controllers,$BaseDn" -Filter * | Select-Object -ExpandProperty 'DNSHostName'
        } Catch [System.Exception] {
            Write-Output "Failed to get domain controllers $_"
        }

        Write-Output 'Running Group Policy update against all domain controllers'
        Foreach ($DomainController in $DomainControllers) {
            Invoke-Command -ComputerName $DomainController -Credential $Credentials -ScriptBlock { Invoke-GPUpdate -RandomDelayInMinutes '0' -Force }
        }
    }

    Write-Output 'Creating Update CRL Scheduled Task'
    Try {
        If ($UseS3ForCRL -eq 'Yes') {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
        } Else {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
        }
        $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval '5' -At '12am' -ErrorAction Stop
        $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
        $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
        $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
        $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed register Update CRL Scheduled Task $_"
    }

    Write-Output 'Running CRL Scheduled Task'
    Try {
        Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed run CRL Scheduled Task $_"
    }

    Write-Output 'Restarting CA service'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed restart CA service $_"
    }

    Write-Output 'Removing Subordinate CA Cert request files'
    Try {
        Remove-Item -Path 'D:\Pki\Req' -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove Subordinate CA Cert request files $_"
    }
 
    Write-Output 'Removing the PkiSubCA and PKIRootCA SYSVOL folders'
    Foreach ($SvolFolder in $SvolFolders) {
        Try {
            Remove-Item -Path $SvolFolder -Recurse -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to remove PkiSubCA and PKIRootCA SYSVOL folders $_"
            Exit 1
        }
    }

    Write-Output 'Removing computer account from elevated groups'
    If ($DirectoryType -eq 'SelfManaged') {
        Try {
            Remove-ADGroupMember -Identity 'Enterprise Admins' -Members (Get-ADComputer -Identity $CompName | Select-Object -ExpandProperty 'DistinguishedName') -Confirm:$false -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to remove computer account from Enterprise Admins $_"
            Exit 1
        }
    } Else {
        Try {
            Remove-ADGroupMember -Identity 'AWS Delegated Enterprise Certificate Authority Administrators' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials | Select-Object -ExpandProperty 'DistinguishedName') -Confirm:$false -ErrorAction Stop -Credential $Credentials
        } Catch [System.Exception] {
            Write-Output "Failed to remove computer account from AWS Delegated Enterprise Certificate Authority Administrators $_"
            Exit 1
        }
    }

    Write-Output 'Clearing all SYSTEM kerberos tickets'
    & Klist.exe -li 0x3e7 purge > $null
}

Function New-TemplateOID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$ConfigNC
    )

    #==================================================
    # Variables
    #==================================================

    $Hex = '0123456789ABCDEF'

    #==================================================
    # Main
    #==================================================

    Do {
        [string]$RandomHex = $null
        For ($i = 1; $i -le 32; $i++) {
            $RandomHex += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16), 1)
        }

        $OID_Part_1 = Get-Random -Minimum 1000000 -Maximum 99999999
        $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $OID_Part_3 = $RandomHex
        $OID_Forest = Get-ADObject -Server $Server -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID -ErrorAction SilentlyContinue
        $msPKICertTemplateOID = "$OID_Forest.$OID_Part_1.$OID_Part_2"
        $Name = "$OID_Part_2.$OID_Part_3"
        $Search = Get-ADObject -Server $Server -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Filter { cn -eq $Name -and msPKI-Cert-Template-OID -eq $msPKICertTemplateOID } -ErrorAction SilentlyContinue
        If ($Search) { 
            $Unique = 'False'
        } Else { 
            $Unique = 'True'
        }
    } Until ($Unique = 'True')
    Return @{
        TemplateOID  = $msPKICertTemplateOID
        TemplateName = $Name
    }
}

Function New-KerbCertTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseDn,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Server
    )

    $CA = $env:COMPUTERNAME

    #==================================================
    # Main
    #==================================================

    $OID = New-TemplateOID -Server $Server -ConfigNC "CN=Configuration,$BaseDn"

    $TemplateOIDPath = "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"
    $OidOtherAttributes = @{
        'DisplayName'             = 'LdapOverSSL-QS'
        'flags'                   = [System.Int32]'1'
        'msPKI-Cert-Template-OID' = $OID.TemplateOID
    }

    $OtherAttributes = @{
        'flags'                                = [System.Int32]'131168'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.2.3.5', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
        'msPKI-Certificate-Name-Flag'          = [System.Int32]'138412032'
        'msPKI-Enrollment-Flag'                = [System.Int32]'40'
        'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
        'msPKI-Private-Key-Flag'               = [System.Int32]'84279552'
        'msPKI-Template-Minor-Revision'        = [System.Int32]'1'
        'msPKI-Template-Schema-Version'        = [System.Int32]'4'
        'msPKI-RA-Signature'                   = [System.Int32]'0'
        'pKIMaxIssuingDepth'                   = [System.Int32]'0'
        'ObjectClass'                          = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.17', '2.5.29.15')
        'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider')
        'pKIDefaultKeySpec'                    = [System.Int32]'1'
        'pKIExpirationPeriod'                  = [System.Byte[]]@('0', '64', '57', '135', '46', '225', '254', '255')
        'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.2.3.5', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
        'pKIKeyUsage'                          = [System.Byte[]]@('160', '0')
        'pKIOverlapPeriod'                     = [System.Byte[]]@('0', '128', '166', '10', '255', '222', '255', '255')
        'revision'                             = [System.Int32]'100'
        'msPKI-Cert-Template-OID'              = $OID.TemplateOID
    }

    Try {
        New-ADObject -Path $TemplateOIDPath -OtherAttributes $OidOtherAttributes -Name $OID.TemplateName -Type 'msPKI-Enterprise-Oid' -Server $Server -Credential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create new LdapOverSSL-QS certificate template OID $_"
        Exit 1
    }

    $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"

    Try {
        New-ADObject -Path $TemplatePath -OtherAttributes $OtherAttributes -Name 'LdapOverSSL-QS' -DisplayName 'LdapOverSSL-QS' -Type 'pKICertificateTemplate' -Server $Server -Credential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create new LdapOverSSL-QS certificate template $_"
        Exit 1
    }

    $SidsToAdd = @(
        [Security.Principal.SecurityIdentifier]'S-1-5-9'
        (Get-ADGroup -Identity 'Domain Controllers' | Select-Object -ExpandProperty 'SID')
    )

    $SidsToRemove = @(
        [Security.Principal.SecurityIdentifier]'S-1-5-18',
        (Get-ADGroup -Identity 'Domain Admins' | Select-Object -ExpandProperty 'SID')
    )

    Write-Output 'Enabling CredSSP'
    Set-CredSSP -Action 'Enable'

    Write-Output 'Sleeping to ensure replication of certificate template has completed'
    Start-Sleep -Seconds 60 

    Write-Output 'Cleaning up ACLs on LdapOverSSL-QS certificate template'
    $ExtendedRightGuids = @(
        [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55',
        [GUID]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    )
    Foreach ($SidToAdd in $SidsToAdd) {
        Add-CertTemplateAcl -Credential $Credential -Path "CN=LdapOverSSL-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToAdd -ActiveDirectoryRights 'GenericRead,GenericWrite,WriteDacl,WriteOwner,Delete' -AccessControlType 'Allow' -ActiveDirectorySecurityInheritance 'None'

        Foreach ($ExtendedRightGuid in $ExtendedRightGuids) {
            Add-CertTemplateAcl -Credential $Credential -Path "CN=LdapOverSSL-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToAdd -ActiveDirectoryRights 'ExtendedRight' -AccessControlType 'Allow' -ObjectGuid $ExtendedRightGuid -ActiveDirectorySecurityInheritance 'None'
        }
    }

    Set-CertTemplateAclInheritance -Credential $Credential -Path "CN=LdapOverSSL-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"

    Foreach ($SidToRemove in $SidsToRemove) {
        Remove-CertTemplateAcl -Credential $Credential -Path "CN=LdapOverSSL-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToRemove -AccessControlType 'Allow'
    }

    Write-Output "Publishing LdapOverSSL-QS template to allow enrollment"
    $Counter = 0
    Do {
        $TempPresent = $Null
        Try {
            $TempPresent = Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock { 
                Get-ADObject "CN=$Using:CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$Using:BaseDn" -Partition "CN=Configuration,$Using:BaseDn" -Properties 'certificateTemplates' | Select-Object -ExpandProperty 'certificateTemplates' | Where-Object { $_ -contains 'LdapOverSSL-QS' }
            }
        } Catch [System.Exception] {
            Write-Output "LdapOverSSL-QS template missing"
            $TempPresent = $Null
        }
        If (-not $TempPresent) {
            $Counter ++
            Write-Output "LdapOverSSL-QS template missing adding it."
            Try {
                Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
                    Set-ADObject "CN=$Using:CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$Using:BaseDn" -Partition "CN=Configuration,$Using:BaseDn" -Add @{ 'certificateTemplates' = 'LdapOverSSL-QS' } 
                }
            } Catch [System.Exception] {
                Write-Output "Failed to add publish LdapOverSSL-QS template $_"
            }
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($TempPresent -or $Counter -eq 12)

    Write-Output 'Sleeping to ensure replication of certificate template publish has completed'
    Start-Sleep -Seconds 60 

    Write-Output 'Disabling CredSSP'
    Set-CredSSP -Action 'Disable'
}

Function Add-CertTemplateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$IdentityReference,
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$ActiveDirectoryRights,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.AccessControlType]$AccessControlType,
        [Parameter(Mandatory = $false)][Guid]$ObjectGuid,        
        [Parameter(Mandatory = $false)][System.DirectoryServices.ActiveDirectorySecurityInheritance]$ActiveDirectorySecurityInheritance,
        [Parameter(Mandatory = $false)][Guid]$InheritedObjectGuid
    )

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force

        [Security.Principal.SecurityIdentifier]$IdentityReference = $Using:IdentityReference | Select-Object -ExpandProperty 'Value'

        $ArgumentList = $IdentityReference, $Using:ActiveDirectoryRights, $Using:AccessControlType, $Using:ObjectGuid, $Using:ActiveDirectorySecurityInheritance, $Using:InheritedObjectGuid
        $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })

        Try {
            $Rule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ArgumentList -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create ACL object $_"
            Exit 1
        }

        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get ACL for $Using:Path $_"
            Exit 1
        }

        $ObjectAcl.AddAccessRule($Rule) 

        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set ACL for $Using:Path $_"
            Exit 1
        }
    }
}

Function Set-CertTemplateAclInheritance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path
    )

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force

        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get ACL for $Using:Path $_"
            Exit 1
        }

        $ObjectAcl.SetAccessRuleProtection($true, $false)

        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set ACL inheritance for $Using:Path $_"
            Exit 1
        }
    }
}

Function Remove-CertTemplateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$IdentityReference,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.AccessControlType]$AccessControlType
    )

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force

        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get ACL for $Using:Path $_"
            Exit 1
        }

        [Security.Principal.SecurityIdentifier]$IdentityReference = $Using:IdentityReference | Select-Object -ExpandProperty 'Value'

        $ObjectAcl.RemoveAccess($IdentityReference, $Using:AccessControlType)

        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set ACL for $Using:Path $_"
            Exit 1
        }
    }
}