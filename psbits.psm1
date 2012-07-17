<#
.SYNOPSIS

Get the thumbprint from a .CER file.
#>
function Get-CertificateThumbprint {
param(
  [string]$file
);

    $cert = New-Object -Type System.Security.Cryptography.X509Certificates.X509Certificate2 (Get-Item $file)
    $cert.Thumbprint
}

<#
.SYNOPSIS

Export a certificate to a .CER file. Doesn't include the private key.
#>
function Export-Certificate {
param(
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert,
    [string] $path
);

    $destination = Qualify-Path $path
    
    $bytes = $cert.Export('Cert', $null)
    [System.IO.File]::WriteAllBytes($destination, $bytes)
}

<#
.SYNOPSIS

netstat for PowerShell; from http://poshcode.org/560
#>
function Get-Netstat {
    $null, $null, $null, $null, $netstat = netstat -a -n -o
    [regex]$regexTCP = '(?<Protocol>\S+)\s+((?<LAddress>(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?))|(?<LAddress>\[?[0-9a-fA-f]{0,4}(\:([0-9a-fA-f]{0,4})){1,7}\%?\d?\]))\:(?<Lport>\d+)\s+((?<Raddress>(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?))|(?<RAddress>\[?[0-9a-fA-f]{0,4}(\:([0-9a-fA-f]{0,4})){1,7}\%?\d?\]))\:(?<RPort>\d+)\s+(?<State>\w+)\s+(?<PID>\d+$)'

    [regex]$regexUDP = '(?<Protocol>\S+)\s+((?<LAddress>(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?)\.(2[0-4]\d|25[0-5]|[01]?\d\d?))|(?<LAddress>\[?[0-9a-fA-f]{0,4}(\:([0-9a-fA-f]{0,4})){1,7}\%?\d?\]))\:(?<Lport>\d+)\s+(?<RAddress>\*)\:(?<RPort>\*)\s+(?<PID>\d+)'

    [psobject]$process = "" | Select-Object Protocol, LocalAddress, Localport, RemoteAddress, Remoteport, State, PID, ProcessName, Services

    $Services = @{}
    get-wmiobject win32_service | ForEach-Object { 
        [String]$SvcPID = $_.processid
        If ($Services.ContainsKey($SvcPID))
        {
            $Services.Item($SvcPID) = $Services.Item($SvcPID) += $($_.Name)
        }
        Else
        {
            $Services.Add($SvcPID,@($_.Name))
        }
    }

    foreach ($net in $netstat)
    {
        switch -regex ($net.Trim())
        {
            $regexTCP
            {          
                $process.Protocol = $matches.Protocol
                $process.LocalAddress = $matches.LAddress
                $process.Localport = $matches.LPort
                $process.RemoteAddress = $matches.RAddress
                $process.Remoteport = $matches.RPort
                $process.State = $matches.State
                $process.PID = $matches.PID
                $process.ProcessName = ( Get-Process -Id $matches.PID -ea 0).ProcessName
                $process.Services = $Services.Item($matches.PID)
            }
            $regexUDP
            {          
                $process.Protocol = $matches.Protocol
                $process.LocalAddress = $matches.LAddress
                $process.Localport = $matches.LPort
                $process.RemoteAddress = $matches.RAddress
                $process.Remoteport = $matches.RPort
                $process.State = $matches.State
                $process.PID = $matches.PID
                $process.ProcessName = ( Get-Process -Id $matches.PID -ea 0).ProcessName
                $process.Services = $Services.Item($matches.PID)
            }
        }
    $process
    }
}

function Is-Newer {
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$source,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$dest
);

    # If destination does not exist, or if the source is older than the destination.
    if (!$(Test-Path -LiteralPath $dest) -or ((Get-Item -LiteralPath $source).LastWriteTime -gt (Get-Item -LiteralPath $dest).LastWriteTime)) {
        $true
    } else {
        $false
    }
}

# BUG: Doesn't work if the module is specified by path, rather than name.
function Reload-Module($ModuleName)
{
    if((get-module -list | where{$_.name -eq "$ModuleName"} | measure-object).count -gt 0)
    {
        if((get-module -all | where{$_.Name -eq "$ModuleName"} | measure-object).count -gt 0)
        {
            Remove-Module $ModuleName
            Write-Host "Unloaded module '$ModuleName'."
        }
    }
    else
    {
	   Write-Host "Warning: Module '$ModuleName' doesn't exist."
    }

    Import-Module $ModuleName
    Write-Host "Loaded module '$ModuleName'."
}

# From http://poshcode.org/1751
function Get-RelativePath {
<#
.SYNOPSIS
   Get a path to a file (or folder) relative to another folder
.DESCRIPTION
   Converts the FilePath to a relative path rooted in the specified Folder
.PARAMETER Folder
   The folder to build a relative path from
.PARAMETER FilePath
   The File (or folder) to build a relative path TO
.PARAMETER Resolve
   If true, the file and folder paths must exist
.Example
   Get-RelativePath ~\Documents\WindowsPowerShell\Logs\ ~\Documents\WindowsPowershell\Modules\Logger\log4net.xslt
   
   ..\Modules\Logger\log4net.xslt
   
   Returns a path to log4net.xslt relative to the Logs folder
#>
[CmdletBinding()]
param(
   [Parameter(Mandatory=$true, Position=0)]
   [string]$Folder
, 
   [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
   [Alias("FullName")]
   [string]$FilePath
,
   [switch]$Resolve
)
process {
   Write-Verbose "Resolving paths relative to '$Folder'"
   $from = $Folder = split-path $Folder -NoQualifier -Resolve:$Resolve
   $to = $filePath = split-path $filePath -NoQualifier -Resolve:$Resolve

   while($from -and $to -and ($from -ne $to)) {
      if($from.Length -gt $to.Length) {
         $from = split-path $from
      } else {
         $to = split-path $to
      }
   }

   $filepath = $filepath -replace "^"+[regex]::Escape($to)+"\\"
   $from = $Folder
   while($from -and $to -and $from -gt $to ) {
      $from = split-path $from
      $filepath = join-path ".." $filepath
   }
   Write-Output $filepath
}
}

function Qualify-Path($path) {
    $provider = $null
    $drive = $null
    
    $result = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path, [ref]$provider, [ref]$drive)
    if ( $provider.Name -ne 'FileSystem' ) {
        throw "Only the FileSystem provider is supported. ${path} has provider ${provider}."
    }
    
    $result
}

function Remove-EmptyFolders {
    Get-ChildItem . -Recurse |
        Where-Object { $_.PSIsContainer } |
        Where-Object { $_.GetFileSystemInfos().Count -eq 0 } |
        Sort-Object -Property @{Expression={$_.FullName.Length}} -Descending | % {
            Write-Verbose $_.FullName
            Remove-Item $_.FullName
        }
}

