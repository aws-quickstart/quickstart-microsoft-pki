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
            $DriveLetter = New-Partition -Alignment '4096000' -DiskNumber $BlankDisk -AssignDriveLetter -UseMaximumSize -ErrorAction Stop | Select-Object -ExpandProperty 'DriveLetter'
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

    $RootKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows'
    $CredDelKey = 'CredentialsDelegation'
    $FreshCredKey = 'AllowFreshCredentials'
    $FreshCredKeyNTLM = 'AllowFreshCredentialsWhenNTLMOnly'

    #==================================================
    # Main
    #==================================================

    Switch ($Action) {
        'Enable' {
            Write-Output 'Enabling CredSSP'
            $CredDelKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -ErrorAction SilentlyContinue
            If (-not $CredDelKeyPresent) {
                Write-Output "Setting CredSSP registry entry $CredDelKey"
                Try {
                    $CredDelPath = New-Item -Path "Registry::$RootKey" -Name $CredDelKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                } Catch [System.Exception] {
                    Write-Output "Failed to create CredSSP registry entry $CredDelKey $_"
                    Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                    Exit 1
                }
            } Else {
                $CredDelPath = Join-Path -Path $RootKey -ChildPath $CredDelKey
            }

            $FreshCredKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKey) -ErrorAction SilentlyContinue
            If (-not $FreshCredKeyPresent) {
                Write-Output "Setting CredSSP registry entry $FreshCredKey"
                Try {
                    $FreshCredKeyPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                } Catch [System.Exception] {
                    Write-Output "Failed to create CredSSP registry entry $FreshCredKey $_"
                    Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                    Exit 1
                }
            } Else {
                $FreshCredKeyPath = Join-Path -Path $CredDelPath -ChildPath $FreshCredKey
            }

            $FreshCredKeyNTLMPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKeyNTLM) -ErrorAction SilentlyContinue
            If (-not $FreshCredKeyNTLMPresent) {
                Write-Output "Setting CredSSP registry entry $FreshCredKeyNTLM"
                Try {
                    $FreshCredKeyNTLMPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKeyNTLM -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                } Catch [System.Exception] {
                    Write-Output "Failed to create CredSSP registry entry $FreshCredKeyNTLM $_"
                    Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                    Exit 1
                }
            } Else {
                $FreshCredKeyNTLMPath = Join-Path -Path $CredDelPath -ChildPath $FreshCredKeyNTLM
            }

            Try {
                $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentials' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFresh' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentialsWhenNTLMOnly' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                $Null = Set-ItemProperty -Path "Registry::$FreshCredKeyPath" -Name '1' -Value 'WSMAN/*' -Type 'String' -Force -ErrorAction Stop
                $Null = Set-ItemProperty -Path "Registry::$FreshCredKeyNTLMPath" -Name '1' -Value 'WSMAN/*' -Type 'String' -Force -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create CredSSP registry properties $_"
                Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                Exit 1
            }

            Try {
                $Null = Enable-WSManCredSSP -Role 'Client' -DelegateComputer '*' -Force -ErrorAction Stop
                $Null = Enable-WSManCredSSP -Role 'Server' -Force -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to enable CredSSP $_"
                $Null = Disable-WSManCredSSP -Role 'Client' -ErrorAction SilentlyContinue
                $Null = Disable-WSManCredSSP -Role 'Server' -ErrorAction SilentlyContinue
                Exit 1
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
                Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to remove CredSSP registry entries $_"
                Exit 1
            }
        }
        Default { 
            Write-Output 'InvalidArgument: Invalid value is passed for parameter Action'
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

        If ($DirectoryType -eq 'AWSManaged') {
            Set-CredSSP -Action 'Disable'
        }
        
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
        
        If ($DirectoryType -eq 'AWSManaged') {
            Set-CredSSP -Action 'Disable'
        }

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

Function Set-AuditDscConfiguration {

    #==================================================
    # Main
    #==================================================

    Configuration ConfigInstance {
        Import-DscResource -ModuleName 'AuditPolicyDsc'
        Node LocalHost {
            AuditPolicySubcategory CredentialValidationSuccess {
                Name      = 'Credential Validation'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory CredentialValidationFailure {
                Name      = 'Credential Validation'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory KerberosAuthenticationServiceSuccess {
                Name      = 'Kerberos Authentication Service'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KerberosAuthenticationServiceFailure {
                Name      = 'Kerberos Authentication Service'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KerberosServiceTicketOperationsSuccess {
                Name      = 'Kerberos Service Ticket Operations'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KerberosServiceTicketOperationsFailure {
                Name      = 'Kerberos Service Ticket Operations'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountLogonEventsSuccess {
                Name      = 'Other Account Logon Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountLogonEventsFailure {
                Name      = 'Other Account Logon Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGroupManagementSuccess {
                Name      = 'Application Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGroupManagementFailure {
                Name      = 'Application Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ComputerAccountManagementSuccess {
                Name      = 'Computer Account Management'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ComputerAccountManagementFailure {
                Name      = 'Computer Account Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DistributionGroupManagementSuccess {
                Name      = 'Distribution Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DistributionGroupManagementFailure {
                Name      = 'Distribution Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountManagementEventsSuccess {
                Name      = 'Other Account Management Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherAccountManagementEventsFailure {
                Name      = 'Other Account Management Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SecurityGroupManagementSuccess {
                Name      = 'Security Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityGroupManagementFailure {
                Name      = 'Security Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory UserAccountManagementSuccess {
                Name      = 'User Account Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserAccountManagementFailure {
                Name      = 'User Account Management'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DPAPIActivitySuccess {
                Name      = 'DPAPI Activity'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DPAPIActivityFailure {
                Name      = 'DPAPI Activity'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory PNPActivitySuccess {
                Name      = 'Plug and Play Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory PNPActivityFailure {
                Name      = 'Plug and Play Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ProcessCreationSuccess {
                Name      = 'Process Creation'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory ProcessCreationFailure {
                Name      = 'Process Creation'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ProcessTerminationSuccess {
                Name      = 'Process Termination'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory ProcessTerminationFailure {
                Name      = 'Process Termination'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory RPCEventsSuccess {
                Name      = 'RPC Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory RPCEventsFailure {
                Name      = 'RPC Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory TokenRightAdjustedSuccess {
                Name      = 'Token Right Adjusted Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory TokenRightAdjustedFailure {
                Name      = 'Token Right Adjusted Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedDirectoryServiceReplicationSuccess {
                Name      = 'Detailed Directory Service Replication'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedDirectoryServiceReplicationFailure {
                Name      = 'Detailed Directory Service Replication'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceAccessSuccess {
                Name      = 'Directory Service Access'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceAccessFailure {
                Name      = 'Directory Service Access'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceChangesSuccess {
                Name      = 'Directory Service Changes'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceChangesFailure {
                Name      = 'Directory Service Changes'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceReplicationSuccess {
                Name      = 'Directory Service Replication'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceReplicationFailure {
                Name      = 'Directory Service Replication'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AccountLockoutSuccess {
                Name      = 'Account Lockout'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AccountLockoutFailure {
                Name      = 'Account Lockout'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserDeviceClaimsSuccess {
                Name      = 'User / Device Claims'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserDeviceClaimsFailure {
                Name      = 'User / Device Claims'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory GroupMembershipSuccess {
                Name      = 'Group Membership'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory GroupMembershipFailure {
                Name      = 'Group Membership'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory IPsecExtendedModeSuccess {
                Name      = 'IPsec Extended Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecExtendedModeFailure {
                Name      = 'IPsec Extended Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecMainModeSuccess {
                Name      = 'IPsec Main Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecMainModeFailure {
                Name      = 'IPsec Main Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecQuickModeSuccess {
                Name      = 'IPsec Quick Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecQuickModeFailure {
                Name      = 'IPsec Quick Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory LogoffSuccess {
                Name      = 'Logoff'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory Logoffailure {
                Name      = 'Logoff'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory LogonSuccess {
                Name      = 'Logon'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory LogonFailure {
                Name      = 'Logon'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NetworkPolicyServerSuccess {
                Name      = 'Network Policy Server'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NetworkPolicyServerFailure {
                Name      = 'Network Policy Server'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherLogonLogoffEventsSuccess {
                Name      = 'Other Logon/Logoff Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherLogonLogoffEventsFailure {
                Name      = 'Other Logon/Logoff Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SpecialLogonSuccess {
                Name      = 'Special Logon'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SpecialLogonFailure {
                Name      = 'Special Logon'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGeneratedSuccess {
                Name      = 'Application Generated'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGeneratedFailure {
                Name      = 'Application Generated'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CertificationServicesSuccess {
                Name      = 'Certification Services'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory CertificationServicesFailure {
                Name      = 'Certification Services'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DetailedFileShareSuccess {
                Name      = 'Detailed File Share'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DetailedFileShareFailure {
                Name      = 'Detailed File Share'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileShareSuccess {
                Name      = 'File Share'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileShareFailure {
                Name      = 'File Share'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileSystemSuccess {
                Name      = 'File System'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileSystemFailure {
                Name      = 'File System'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformConnectionSuccess {
                Name      = 'Filtering Platform Connection'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformConnectionFailure {
                Name      = 'Filtering Platform Connection'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformPacketDropSuccess {
                Name      = 'Filtering Platform Packet Drop'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory FilteringPlatformPacketDropFailure {
                Name      = 'Filtering Platform Packet Drop'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory HandleManipulationSuccess {
                Name      = 'Handle Manipulation'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory HandleManipulationFailure {
                Name      = 'Handle Manipulation'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KernelObjectSuccess {
                Name      = 'Kernel Object'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KernelObjectFailure {
                Name      = 'Kernel Object'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherObjectAccessEventsSuccess {
                Name      = 'Other Object Access Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherObjectAccessEventsFailure {
                Name      = 'Other Object Access Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RegistrySuccess {
                Name      = 'Registry'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RegistryFailure {
                Name      = 'Registry'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RemovableStorageSuccess {
                Name      = 'Removable Storage'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RemovableStorageFailure {
                Name      = 'Removable Storage'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory CentralAccessPolicyStagingSuccess {
                Name      = 'Central Policy Staging'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CentralAccessPolicyStagingFailure {
                Name      = 'Central Policy Staging'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuditPolicyChangeSuccess {
                Name      = 'Audit Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuditPolicyChangeFailure {
                Name      = 'Audit Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AuthenticationPolicyChangeSuccess {
                Name      = 'Authentication Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuthenticationPolicyChangeFailure {
                Name      = 'Authentication Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AuthorizationPolicyChangeSuccess {
                Name      = 'Authorization Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuthorizationPolicyChangeFailure {
                Name      = 'Authorization Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory MPSSVCRule-LevelPolicyChangeSuccess {
                Name      = 'MPSSVC Rule-Level Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory MPSSVCRule-LevelPolicyChangeFailure {
                Name      = 'MPSSVC Rule-Level Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherPolicyChangeEventsSuccess {
                Name      = 'Other Policy Change Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPolicyChangeEventsFailure {
                Name      = 'Other Policy Change Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NonSensitivePrivilegeUseSuccess {
                Name      = 'Non Sensitive Privilege Use'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory NonSensitivePrivilegeUseFailure {
                Name      = 'Non Sensitive Privilege Use'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPrivilegeUseEventsSuccess {
                Name      = 'Other Privilege Use Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPrivilegeUseEventsFailure {
                Name      = 'Other Privilege Use Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SensitivePrivilegeUseSuccess {
                Name      = 'Sensitive Privilege Use'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SensitivePrivilegeUseFailure {
                Name      = 'Sensitive Privilege Use'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecDriverSuccess {
                Name      = 'IPsec Driver'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecDriverFailure {
                Name      = 'IPsec Driver'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherSystemEventsSuccess {
                Name      = 'Other System Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherSystemEventsFailure {
                Name      = 'Other System Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityStateChangeSuccess {
                Name      = 'Security State Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityStateChangeFailure {
                Name      = 'Security State Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SecuritySystemExtensionSuccess {
                Name      = 'Security System Extension'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecuritySystemExtensionFailure {
                Name      = 'Security System Extension'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SystemIntegritySuccess {
                Name      = 'System Integrity'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SystemIntegrityFailure {
                Name      = 'System Integrity'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
        }
    }
    Write-Output 'Generating MOF file'
    ConfigInstance -OutputPath 'C:\AWSQuickstart\AuditConfigInstance' -ConfigurationData $ConfigurationData
}

Function Set-LogsAndMetricsCollection {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Stackname
    )

    #==================================================
    # Variables
    #==================================================

    $KenesisAgentSettings = @{
        'Sources'    = @(
            @{
                'Id'         = 'PerformanceCounter'
                'SourceType' = 'WindowsPerformanceCounterSource'
                'Categories' = @(
                    @{
                        'Category'  = 'ENA Packets Shaping'
                        'Instances' = 'ENA #1'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Aggregate inbound BW allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'Aggregate outbound BW allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'Connection tracking allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'Link local packet rate allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'PPS allowance exceeded'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'LogicalDisk'
                        'Instances' = 'D:'
                        'Counters'  = @(
                            @{
                                'Counter' = '% Free Space'
                                'Unit'    = 'Percent'
                            },
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'LogicalDisk'
                        'Instances' = 'C:'
                        'Counters'  = @(
                            @{
                                'Counter' = '% Free Space'
                                'Unit'    = 'Percent'
                            },
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category' = 'Memory'
                        'Counters' = @(
                            @{
                                'Counter' = '% Committed Bytes in Use'
                                'Unit'    = 'Percent'
                            },
                            @{
                                'Counter' = 'Available MBytes'
                                'Unit'    = 'Megabytes'
                            },
                            @{
                                'Counter' = 'Long-Term Average Standby Cache Lifetime (s)'
                                'Unit'    = 'Seconds'
                            }
                        )
                    },
                    @{
                        'Category'  = 'Network Interface'
                        'Instances' = 'Amazon Elastic Network Adapter'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Bytes Received/sec'
                                'Unit'    = 'Count/Second'
                            },
                            @{
                                'Counter' = 'Bytes Sent/sec'
                                'Unit'    = 'Count/Second'
                            },
                            @{
                                'Counter' = 'Current Bandwidth'
                                'Unit'    = 'Bits/Second'
                            }
                        )
                    },
                    @{
                        'Category'  = 'PhysicalDisk'
                        'Instances' = '0 C:'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'PhysicalDisk'
                        'Instances' = '1 D:'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'Processor'
                        'Instances' = '*'
                        'Counters'  = @(
                            @{
                                'Counter' = '% Processor Time'
                                'Unit'    = 'Percent'
                            }
                        )
                    },
                    @{
                        'Category'  = 'Certification Authority'
                        'Instances' = '*'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Failed Request/sec'
                                'Unit'    = 'Count/Second'
                            },
                            @{
                                'Counter' = 'Request/sec'
                                'Unit'    = 'Count/Second'
                            },
                            @{
                                'Counter' = 'Request processing time (ms)'
                                'Unit'    = 'Milliseconds'
                            }
                        )
                    },
                    @{
                        'Category'  = 'Certification Authority Connections'
                        'Instances' = '*'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Active connections'
                                'Unit'    = 'Count'
                            }
                        )
                    }                    
                )
            },
            @{
                'Id'         = 'ApplicationLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'Application'
            },
            @{
                'Id'         = 'SecurityLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'Security'
            },
            @{
                'Id'         = 'SystemLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'System'
            },
            @{
                'Id'         = 'CertificateServicesClient-Lifecycle-SystemOperationalLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational'
            }
        )
        'Sinks'      = @(
            @{
                'Namespace' = "EC2-Domain-Member-Metrics-$Stackname"
                'Region'    = 'ReplaceMe'
                'Id'        = 'CloudWatchSink'
                'Interval'  = '60'
                'SinkType'  = 'CloudWatch'
            },
            @{
                'Id'             = 'ApplicationLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'ApplicationLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            },
            @{
                'Id'             = 'SecurityLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'SecurityLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            },
            @{
                'Id'             = 'SystemLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'SystemLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            },
            @{
                'Id'             = 'CertificateServicesClient-Lifecycle-SystemOperationalLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'CertificateServicesClient-Lifecycle-SystemOperationalLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            }
        )
        'Pipes'      = @(
            @{
                'Id'        = 'PerformanceCounterToCloudWatch'
                'SourceRef' = 'PerformanceCounter'
                'SinkRef'   = 'CloudWatchSink'
            },
            @{
                'Id'        = 'ApplicationLogToCloudWatch'
                'SourceRef' = 'ApplicationLog'
                'SinkRef'   = 'ApplicationLog-CloudWatchLogsSink'
            },
            @{
                'Id'        = 'SecurityLogToCloudWatch'
                'SourceRef' = 'SecurityLog'
                'SinkRef'   = 'SecurityLog-CloudWatchLogsSink'
            },
            @{
                'Id'        = 'SystemLogToCloudWatch'
                'SourceRef' = 'SystemLog'
                'SinkRef'   = 'SystemLog-CloudWatchLogsSink'
            },
            @{
                'Id'        = 'CertificateServicesClient-Lifecycle-SystemOperationalLogToCloudWatch'
                'SourceRef' = 'CertificateServicesClient-Lifecycle-SystemOperationalLog'
                'SinkRef'   = 'CertificateServicesClient-Lifecycle-SystemOperationalLog-CloudWatchLogsSink'
            }
        )
        'SelfUpdate' = 0
    }


    #==================================================
    # Main
    #==================================================

    Try {
        $Version = (Invoke-WebRequest 'https://s3-us-west-2.amazonaws.com/kinesis-agent-windows/downloads/packages.json' -Headers @{"Accept" = "application/json" } -UseBasicParsing | Select-Object -ExpandProperty 'Content' | ConvertFrom-Json | Select-Object -ExpandProperty 'Packages').Version[0]
    } Catch [System.Exception] {
        Write-Output "Failed to get latest KTAP version $_"
        Exit 1
    }

    (New-Object -TypeName 'System.Net.WebClient').DownloadFile("https://s3-us-west-2.amazonaws.com/kinesis-agent-windows/downloads/AWSKinesisTap.$Version.msi", 'C:\AWSQuickstart\AWSKinesisTap.msi')

    Write-Output 'Installing KinesisTap'
    $Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/I C:\AWSQuickstart\AWSKinesisTap.msi /quiet /l C:\AWSQuickstart\ktap-install-log.txt' -NoNewWindow -PassThru -Wait -ErrorAction Stop
    
    If ($Process.ExitCode -ne 0) {
        Write-Output "Error installing KinesisTap -exit code $($Process.ExitCode)"
        Exit 1
    }

    Write-Output 'Getting region'
    Try {
        [string]$Token = Invoke-RestMethod -Headers @{'X-aws-ec2-metadata-token-ttl-seconds' = '3600' } -Method 'PUT' -Uri 'http://169.254.169.254/latest/api/token' -UseBasicParsing -ErrorAction Stop
        $Region = (Invoke-RestMethod -Headers @{'X-aws-ec2-metadata-token' = $Token } -Method 'GET' -Uri 'http://169.254.169.254/latest/dynamic/instance-identity/document' -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty 'Region').ToUpper()
    } Catch [System.Exception] {
        Write-Output "Failed to get region $_"
        Exit 1
    }

    $KenesisAgentSettings.Sinks | Where-Object { $_.Region -eq 'ReplaceMe' } | ForEach-Object { $_.Region = $Region }
    
    Write-Output 'Exporting appsettings.json content'
    Try {
        $KenesisAgentSettings | ConvertTo-Json -Depth 10 -ErrorAction Stop | Out-File 'C:\Program Files\Amazon\AWSKinesisTap\appsettings.json' -Encoding 'ascii' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Unable to export appsettings.json $_"
        Exit 1
    }

    Write-Output 'Restarting AWSKinesisTap service'
    Try {
        Restart-Service 'AWSKinesisTap' -Force
    } Catch [System.Exception] {
        Write-Output "Unable to restart AWSKinesisTap $_"
        Exit 1
    }
}