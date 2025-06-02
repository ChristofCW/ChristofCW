<#
.DESCRIPTION
	The script is provided as a template to perform an install or uninstall or udpate an application(s).
	The script either performs an "Install" deployment type or an "Uninstall" or an "Update" deployment type.
	The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.
.PARAMETER DeploymentType
	The type of deployment to perform. Default is: DeploymentType = Install
Author: Christof Panneels (1028737)
Date: 22/04/2025
#>

# PARAMETERS============================================================================
[CmdletBinding()]
Param (
	[Parameter(Mandatory=$false)]
	[ValidateSet('Install','Uninstall','Update','Repair')]
	[string]$DeploymentType = 'Install'
)

#=================================================================================================================================
# HEADER==========================================================================================================================
# Unattended installation procedure
# Definitions-explain:
# 	appScriptAuthor		: name of author of this script (userID)
# 	appName			    : software name + version (platform=x86 or x64)
# 	scriptCategory	    : Install, Update, Manage, UnInstall
# 	scriptDetail		: additional description about the action
#   appInstallType      : define which kind of installer has to be run to install the application (MSI, executable, FileCopy)
# ===============================================================================================================================

# BEGIN VARIABLES =============================================================================
[string]$appVendor = 'O.S.G. bv'
[string]$appName = 'BrainRT'
[string]$appVersion = '4.6.0.5880'
[string]$appLang = 'EN'
[string]$appRevision = '01'
[string]$appScriptVersion = '1.9.2'
[string]$appScriptDate = '8/05/2025'
[string]$appScriptAuthor = 'Christof Panneels (1028737)'
#executable installation details
[string]$appInstaller = "BrainRT_x64_4.06.00build5880.exe"
[string]$appInstallParameters = "/s /v""/qn ADDLOCAL=CommonLibs,LanguagePack,BrainRT,BrainRTFull,Somnolter,WMFdist95,RTViewerRedist,MSChart,VideoRecording,WMEncoder,IV,BrainBox,VideoReplay,Infinity,GPLMPegDecoder,AC3Filter,FFDShow,VideoSplitterMPEGHD,ShellPlus,BrainRTPlugin,ShellPlusAgent,IMAPI,HaspRuntimeEnvironment""" #removed from commandline SQLFeaturePack_x64,Somnolter, SQL_CLR_x64,SQL_NCLI_x64,SQL_SMO_x64
#File Copy installantion details
[string]$installFolder = "$(${env:ProgramFiles(x86)})\BrainRT"
[string]$sourceFolder = "Installer\hasp_96490.ini"
[string]$appShortcutEXE = ""
[string]$appshortcutArgs = ""
[string]$appShortcutDestination = ""
[string]$appShortcutIconLocation = ""
[string]$appShortcutIconArrayIndex  = ""
[string]$appExecutable = "ShellPlus" 
[string]$appExecutablePath = "$(${env:ProgramFiles(x86)})\BrainRT" 
#MSI isntallation details
[string]$InstallMSI = ""
[string]$InstallMST = ""
[string]$InstallMSP = ""
[string]$appProductCode = ""
[string]$MSIParameters = ""
# Other
[string]$DLLFilePath = ""
[string]$strKeyPath = ""
[string]$strRegName = ""
[string]$strRegValue = ""
[string]$strRegType = ""
[boolean]$boolRestartNeeded = $false
[string]$InfDir = ""

# CUSTOM: PARAMETERS===========================================================================
## Variables: RegEx Patterns
[string]$MSIProductCodeRegExPattern = '^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$'
$StartDate = (Get-Date -Format "dd/MM/yyyy")
$dirInstallFiles = Split-Path(Split-Path -parent $MyInvocation.MyCommand.Definition)
$logFilePath = "C:\ProgramData\Logs"
$Error.clear()

# BEGIN Functions =============================================================================

#This function returns the path where the script is located.
function Get-ScriptDirectory
{
  $Invocation = (Get-Variable MyInvocation -Scope 1).Value
  Split-Path $Invocation.MyCommand.Path
}


#This function check whether there is a restart waiting to be executed, if it returns $false, no reboot is pending
function Test-RebootRequired 
{
    $result = @{
        CBSRebootPending =$false
        WindowsUpdateRebootRequired = $false
        FileRenamePending = $false
        SCCMRebootPending = $false
    }
    write-log -Message "Testing if a Reboot is required...." -Severity Warning -FunctionType Test-RebootRequired
    #Check CBS Registry
    $key = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
    if ($key -ne $null) 
    {
        $result.CBSRebootPending = $true
        write-log -Message "CBS Registry Reboot required!" -Severity Warning -FunctionType Test-RebootRequired
    }
   
    #Check Windows Update
    $key = Get-Item "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
    if($key -ne $null) 
    {
        $result.WindowsUpdateRebootRequired = $true
        write-log -Message "Windows Updates Reboot required!" -Severity Warning -FunctionType Test-RebootRequired
    }
    
    #Check SCCM Client <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542/view/Discussions#content>
    try 
    { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if(($status -ne $null) -and $status.RebootPending){
            $result.SCCMRebootPending = $true
            write-log -Message "SCCM Reboot required!" -Severity Warning -FunctionType Test-RebootRequired
        }

    }catch{}

    #exit with Reboot notification
    return $result.ContainsValue($true)
}
#Creates a custom shortcut 
function Set-Shortcut
{
    param ( 
        [Parameter(Mandatory=$true)]
        [string]$SourceExe, 
        [string]$Arguments, 
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        [Int]$IconArrayIndex,
        [string]$IconLocation
    )
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Set-Shortcut"
    write-log -Message "[FUNCTION - Set-Shortcut]" -Severity Information -FunctionType "Set-Shortcut"
    write-log -Message "[FUNCTION START TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Set-Shortcut"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Set-Shortcut"
    
    write-log -Message "shortcut for $SourceExe will be created in: $DestinationPath, with arguments $Arguments" -Severity Information -FunctionType "Set-Shortcut"
    try {
        $DestinationDir = Split-Path $DestinationPath -Parent
        if ( !(Test-Path -Path $DestinationDir))
        {
            write-log -Message "creating destination folder, does not exist ..." -Severity Information -FunctionType "Set-Shortcut"
            New-Item -Path $DestinationDir -ItemType Directory -Force
            write-log -Message "created destination folder!" -Severity Information -FunctionType "Set-Shortcut"
        }
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($DestinationPath)
        $Shortcut.TargetPath = $SourceExe
        $Shortcut.Arguments = $Arguments
        $Shortcut.WorkingDirectory = $installFolder
        if (($IconLocation -ne "")-and ($IconArrayIndex -ne "")){$Shortcut.IconLocation = "$IconLocation, $IconArrayIndex"}
        elseif (($IconLocation -ne "")-and ($IconArrayIndex -eq "")){$Shortcut.IconLocation = "$IconLocation"}
        $Shortcut.Save()
        write-log -Message "The shortcut has been created succesfully!!" -Severity Success -FunctionType "Set-Shortcut"

    }
    catch {    write-log -Message "There was an issue creating the shortcut, please check the paramaters!" -Severity Error -FunctionType "Set-Shortcut"
}

    write-log -Message "==================================================================================" -Severity Information -FunctionType "Set-Shortcut"
    write-log -Message "[FUNCTION - Set-Shortcut]" -Severity Information -FunctionType "Set-Shortcut"
    write-log -Message "[FUNCTION END TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Set-Shortcut"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Set-Shortcut"

}


# Create a registry key 
Function Create-RegKey {
    param (
        [Parameter(Mandatory=$true)]
		[string]$strKeyPath,
        
        [Parameter(Mandatory=$true)]
		[string]$strName, 
        
		[string]$strValue ="default value",
        
        [Parameter(Mandatory=$true)]
		[ValidateSet('String','ExpandString','MultiString','Binary','DWord','QWord')]
        [string]$strType
    )
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Create-RegKey"
    write-log -Message "[FUNCTION - Create-RegKey]" -Severity Information -FunctionType "Create-RegKey"
    write-log -Message "[FUNCTION START TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Create-RegKey"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Create-RegKey"

try
{

    if ( !(Test-Path -Path $strKeyPath))
    {
        New-Item -Path $strKeyPath
        if($strValue -eq " "){New-ItemProperty -Path $strKeyPath -Name $strName -Type $strType -Value ""}
		else {New-ItemProperty -Path $strKeyPath -Name $strName -Type $strType -Value $strValue}
    }
    else
    {
        if($strValue -eq " "){Set-ItemProperty -Path $strKeyPath -Name $strName -Type $strType -Value ""}
        else{Set-ItemProperty -Path $strKeyPath -Name $strName -Type $strType -Value $strValue }
    }
    write-log -Message "Registry key created: $strKeyPath\$strName" -Severity Success -FunctionType "Create-RegKey"
}
catch
{
    write-log -Message "Errormessage: $($_.Exception.Message)" -Severity Error -FunctionType "Create-RegKey"
    write-log -Message "Registry key kan niet worden aangemaakt." -Severity Error -FunctionType "Create-RegKey"
    Exit 99
}
write-log -Message "==================================================================================" -Severity Information -FunctionType "Create-RegKey"
write-log -Message "[FUNCTION - Create-RegKey]" -Severity Information -FunctionType "Create-RegKey"
write-log -Message "[FUNCTION END TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Create-RegKey"
write-log -Message "==================================================================================" -Severity Information -FunctionType "Create-RegKey"

}

# write a mesasge in a logfile
function write-log
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
 
        [Parameter()]
        [ValidateSet('Information','Warning','Error','Success')]
        [string]$Severity = 'Information',

        [Parameter()]
        [string]$FunctionType = "MAIN"
    )

    $logFile = "$logFilePath\$appName-$DeploymentType.log"

    if(!(Test-Path $logFilePath))
    {
        try {New-Item -Path $logFilePath -ItemType Directory -ErrorAction Stop}
        catch [system.NotSupportedException]{Write-Warning -Message "Illegal character used in the filename."}
        catch [system.IO.DirectoryNotFoundException]{Write-Warning -Message "The path is not valid."}
        catch {Write-Warning -Message "An unexpectec error occured: $($error[1])"}
    }
    # Write message on screen with colorcoding for warning and error
    switch ($Severity) {
        "Success"{write-host "$(Get-Date -f g) - $Severity - $Message" -ForegroundColor Green}
        "Warning"{write-host "$(Get-Date -f g) - $Severity - $Message" -ForegroundColor Yellow}
        "Error"{write-host "$(Get-Date -f g) - $Severity - $Message" -ForegroundColor Red}
        Default {write-host "$(Get-Date -f g) - $Severity - $Message"}
    }

    [pscustomobject]@{
        Time = (Get-Date -f g)
        Severity = $Severity
        Message = $Message
    } | Export-Csv -Path $logFile -Delimiter ";" -Append -NoTypeInformation    
}

# Build and execute the MSIexec command
function Execute-MSI {

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateSet('Install','Uninstall','Patch','Repair','ActiveSetup')]
		[string]$Action = 'Install',
		[string]$Transform,
		[Parameter(Mandatory=$false)]
		[Alias('Arguments')]
		[ValidateNotNullorEmpty()]
		[string]$Parameters,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$AddParameters,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$Patch,
	    [Parameter(Mandatory=$true)]
		[ValidateScript({($_ -match $MSIProductCodeRegExPattern) -or ('.msi','.msp' -contains [IO.Path]::GetExtension($_))})]
		[Alias('FilePath')]
		[string]$Path
	)
    # Variables
    [string]$exeMsiexec = "$env:WinDir\System32\msiexec.exe" # Installs MSI Installers

    write-log -Message "==================================================================================" -Severity Information -FunctionType "Execute-MSI"
    write-log -Message "[FUNCTION - Execute-MSI]" -Severity Information -FunctionType "Execute-MSI"
    write-log -Message "[FUNCTION START TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Execute-MSI"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Execute-MSI"

    $logFile = "$logFilePath\$appName-$action-MSI.log"
    
    ## Build the MSI Parameters
    Switch ($action) {
        'Install' { $option = '/i'; [string]$msiLogFile = "$logFile"; $msiDefaultParams = $msiInstallDefaultParams }
        'Uninstall' { $option = '/x'; [string]$msiLogFile = "$logFile"; $msiDefaultParams = $msiUninstallDefaultParams }
        'Patch' { $option = '/update'; [string]$msiLogFile = "$logFile"; $msiDefaultParams = $msiInstallDefaultParams }
        'Repair' { $option = '/f'; If ($RepairFromSource) {	$option += "v" } [string]$msiLogFile = "$logFile"; $msiDefaultParams = $msiInstallDefaultParams }
        'ActiveSetup' { $option = '/fups'; [string]$msiLogFile = "$logFile" }
    }
    ## Initialize variable indicating whether $Path variable is a Product Code or not
    [boolean]$PathIsProductCode = $false
    ## If the MSI is in the Files directory, set the full path to the MSI
    If (Test-Path -LiteralPath (Join-Path -Path $dirInstallFiles -ChildPath $path -ErrorAction 'SilentlyContinue') -PathType 'Leaf' -ErrorAction 'SilentlyContinue') {
        [string]$msiFile = Join-Path -Path $dirInstallFiles -ChildPath $path
    }
    ElseIf (Test-Path -LiteralPath $Path -ErrorAction 'SilentlyContinue') {
        [string]$msiFile = (Get-Item -LiteralPath $Path).FullName
    }
        ElseIf ($Path -match $MSIProductCodeRegExPattern) {
        [string]$msiFile = $Path
        $PathIsProductCode = $true
    }
    Else {
        write-log -message "Failed to find MSI file [$($path)]." -Severity Error -FunctionType "Execute-MSI"
        If (-not $ContinueOnError) {
            Throw "Failed to find MSI file [$path]."
        }
        Continue
    }

    ## Set the working directory of the MSI
    If ((-not $PathIsProductCode) -and (-not $workingDirectory)) { [string]$workingDirectory = Split-Path -Path $msiFile -Parent }

    ## Enclose the MSI file in quotes to avoid issues with spaces when running msiexec
	[string]$msiFile = "`"$msiFile`""

	## Start building the MsiExec command line starting with the base action and file
	[string]$argsMSI = "$option $msiFile"
	#  Add MST
	If ($transform) { $argsMSI = "$argsMSI TRANSFORMS=$mstFile TRANSFORMSSECURE=1" }
	#  Add MSP
	If ($patch) { $argsMSI = "$argsMSI PATCH=$mspFile" }
	#  Replace default parameters if specified.
	If ($Parameters) { $argsMSI = "$argsMSI $Parameters" } Else { $argsMSI = "$argsMSI $msiDefaultParams" }
	#  Add reinstallmode and reinstall variable for Patch
	If ($action -eq 'Patch') {$argsMSI += " REINSTALLMODE=ecmus REINSTALL=ALL"}
	#  Append parameters to default parameters if specified.
	If ($AddParameters) { $argsMSI = "$argsMSI $AddParameters" }
	#  Add custom Logging Options if specified, otherwise, add default Logging Options from Config file
	If ($LoggingOptions) { $argsMSI = "$argsMSI $LoggingOptions $msiLogFile" } 
    Else { 
        if ($configMSILoggingOptions){$argsMSI += $configMSILoggingOptions + " /l*v `"$msiLogFile`"" }
        else{$argsMSI += " /l*v `"$msiLogFile`"" }
    }
    # Add silent install parameter
    if ($argsMSI) {
        if (-not($AddParameters.contains("/q"))){$argsMSI += " /qn"}
        }

	write-log -Message "Executing MSI action [$Action]..." -Severity Information -FunctionType "Execute-MSI"
    # Install the application through the MSI file.
    write-log -Message "MSI command: $exeMsiexec $argsMSI"  -Severity Information -FunctionType "Execute-MSI"
    $installcommand  = Start-Process  $exeMsiexec -ArgumentList $argsMSI -Wait -NoNewWindow -Verbose
    
    if ($installcommand.ExitCode -ne 0){write-log -Message "The MSI has been executed successfully!" -Severity Success -FunctionType "Execute-MSI"}
    else {write-log -Message "The MSI command could not complete correctly: exit code= $($installcommand.ExitCode)" -Severity Error -FunctionType "Execute-MSI"}

    write-log -Message "==================================================================================" -Severity Information -FunctionType "Execute-MSI"
    write-log -Message "[FUNCTION - Execute-MSI]" -Severity Information -FunctionType "Execute-MSI"
    write-log -Message "[FUNCTION END TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Execute-MSI"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Execute-MSI"
    return $installcommand.ExitCode
}


# Stop process from running 
function Kill-Process {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ProcessName
    )
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Stop-Process"
    write-log -Message "[FUNCTION - Stop-Process]" -Severity Information -FunctionType "Stop-Process"
    write-log -Message "[FUNCTION START TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Stop-Process"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Stop-Process"

    try{
        $RunningProcess = Get-Process -Name $ProcessName
        write-log -Message "Process $ProcessName running" -Severity Information -FunctionType "Stop-Process"

        if($RunningProcess -ne $null) {
            try {
                Stop-Process -name "$($ProcessName)" -Force
                write-log -Message "Process $ProcessName stopped" -Severity Information -FunctionType "Stop-Process"
            }catch{
                write-log -Message "Process $ProcessName cannot be stopped: $($Error[0])." -Severity Error -FunctionType "Stop-Process"

            }
        }
    }
    catch{
        write-log -Message "Process $ProcessName not running" -Severity Error -FunctionType "Stop-Process"
    }
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Stop-Process"
    write-log -Message "[FUNCTION - Stop-Process]" -Severity Information -FunctionType "Stop-Process"
    write-log -Message "[FUNCTION END TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Stop-Process"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Stop-Process"

}
function Register-DLL {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
        [String]$FilePath,
        [Switch]$Unregister,
        [Switch]$Register
    )
    # Error codes are documented in this Microsoft article
	  # <https://devblogs.microsoft.com/oldnewthing/20180920-00/?p=99785>
      $ExitCodes = @{
        0 = "SUCCESS";
        1 = "FAIL_ARGS - Invalid Argument";
        2 = "FAIL_OLE - OleInitialize Failed";
        3 = "FAIL_LOAD - LoadLibrary Failed";
        4 = "FAIL_ENTRY - GetProcAddress failed";
        5 = "FAIL_REG - DllRegisterServer or DllUnregisterServer failed.";}

        write-log -Message "==================================================================================" -Severity Information -FunctionType "Register-DLL"
        write-log -Message "[FUNCTION - Register-DLL]" -Severity Information -FunctionType "Register-DLL"
        write-log -Message "[FUNCTION START TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Register-DLL"
        write-log -Message "==================================================================================" -Severity Information -FunctionType "Register-DLL"
    
        if ($Register){$RegAguments = "$FilePath /s"}
        elseif ($Unregister) { $RegAguments = "/U $FilePath /s"}

        Try {
            write-log -Message "Command: Start-Process -FilePath 'regsvr32.exe' -Args $RegAguments -Wait -NoNewWindow -PassThru"
            $Result = Start-Process -FilePath 'regsvr32.exe' -Args $RegAguments -Wait -NoNewWindow -PassThru
      
            If ($Result.ExitCode -NE 0) {
                write-log -Message "Exit Code:$($ExitCodes[$Result.ExitCode])" -Severity Error -FunctionType "Register-DLL"
            }
            else {
                write-log -Message "DLL $filepath succesfully registered - Exit Code:$($ExitCodes[$Result.ExitCode])" -Severity Success -FunctionType "Register-DLL"
            }
          } 
        Catch {
            write-log -Message $_.Exception.Message -Severity Error -FunctionType "Register-DLL" 
          }
          write-log -Message "==================================================================================" -Severity Information -FunctionType "Register-DLL"
          write-log -Message "[FUNCTION - Register-DLL]" -Severity Information -FunctionType "Register-DLL"
          write-log -Message "[FUNCTION END TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Register-DLL"
          write-log -Message "==================================================================================" -Severity Information -FunctionType "Register-DLL"
  
}

# Copy and verify if the copy was succesfull
function Copy-FileSafer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$sourceFolder,
        [Parameter(Mandatory=$true)]
        [string]$destinationfolder
    )
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Copy-FileSafer"
    write-log -Message "[FUNCTION - Copy-FileSafer]" -Severity Information -FunctionType "Copy-FileSafer"
    write-log -Message "[FUNCTION START TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Copy-FileSafer"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Copy-FileSafer"

    if (-not (Test-Path -Path $sourceFolder)) { Write-log -Message "Sourcefolder not found: $sourceFolder, no copy will be executed!" -Severity Warning -FunctionType "Copy-FileSafer"}
    
    if((Get-Item $sourceFolder).Attributes -eq "Directory") # Check whether The destination folder is a folder or a file
    {
        $sourcefiles = Get-ChildItem ("$sourceFolder")
        $isFile = $false
        $isFolder = $true
    }
    else {
        $sourcefiles = $sourceFolder
        $sourceFolder = Split-Path $sourceFolder -Parent
        $isFile = $true
    }
    foreach($sourcefile in $sourcefiles)
    {
        $sourcefilename = Split-Path -Path $sourcefile -Leaf
        $isFolder = $false
        if (!([IO.Path]::HasExtension($sourcefile))){$isFolder = $true}
        if((-not ($isFile)) -or ((Get-Item $destinationfolder).Attributes -eq "Directory")) # Check whether The destination folder is a folder or a file
        {
            $destinationfile = Join-Path -Path $destinationfolder -ChildPath $sourcefilename
            if (-not (Test-Path -LiteralPath $destinationfolder -PathType 'Container')){New-Item -path $destinationfolder -ItemType Directory -Force -ErrorAction Stop}
        }
        else {
            $destinationfile = $destinationfolder
            $destinationfolder = Split-Path $destinationfolder -Parent
        }
        $b4hash = Get-FileHash -Path "$sourceFolder\$sourcefilename"
        try {
            if(!(Test-Path $destinationfolder)){New-Item -Path $destinationfolder -ItemType Directory}
            if($isFolder){Copy-Item -Path "$sourceFolder\$sourcefilename" -Destination $destinationfolder -Recurse -ErrorAction Stop }
            else {Copy-Item -Path "$sourceFolder\$sourcefilename" -Destination $destinationfolder -ErrorAction Stop}
            write-log -Message "$sourcefilename copied successfully!" -Severity Success -FunctionType "Copy-FileSafer"
        }
        catch {write-log -Message "$sourcefilename copy Failed: $($Error[0])" -Severity Information -FunctionType "Copy-FileSafer"}
        finally {$afhash = Get-FileHash -Path $destinationfile
            if ($afhash.Hash -ne $b4hash.Hash) {
                write-log -Message "File corrupted during copy!" -Severity Error -FunctionType "Copy-FileSafer"
                write-log -Message "The hash of the sourcefile: $($b4hash.hash)" -Severity Error -FunctionType "Copy-FileSafer"
                write-log -Message "The hash of the destinationfile: $($afhash.hash)" -Severity Error -FunctionType "Copy-FileSafer"
                $CopyVerified = 1
            }
            else {
                write-log -Message "The hash of the sourcefile: $($b4hash.hash)" -Severity Information -FunctionType "Copy-FileSafer"
                write-log -Message "The hash of the destinationfile: $($afhash.hash)" -Severity Information -FunctionType "Copy-FileSafer"
                write-log -Message "$sourceFolder\$sourcefilename copied successfully!" -Severity Success -FunctionType "Copy-FileSafer"
                $CopyVerified = 0
            }
        }
    }
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Copy-FileSafer"
    write-log -Message "[FUNCTION - Copy-FileSafer]" -Severity Information -FunctionType "Copy-FileSafer"
    write-log -Message "[FUNCTION END TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "Copy-FileSafer"
    write-log -Message "==================================================================================" -Severity Information -FunctionType "Copy-FileSafer"

    return $CopyVerified
}

#Function to add applciation path to path environment variable
Function Add-PathVariable {
    param (
        [string]$addPath
    )
    write-log -Message "Adding Application path to the PATH environment variable..." -Severity Information -FunctionType "Add-PathVariable"
    if (Test-Path $addPath){
        $regexAddPath = [regex]::Escape($addPath)
        $arrPath = $env:Path -split ';' | Where-Object {$_ -notMatch "^$regexAddPath\\?"}
        $env:Path = ($arrPath + $addPath) -join ';'
        write-log -Message "Sucessfully added Application path to the PATH environment variable!" -Severity Success -FunctionType "Add-PathVariable"
    } 
    else {
        write-log -Message "The path does not exist" -Severity Error -FunctionType "Add-PathVariable"
    }
}

#Add a path to the PATH envirmentont variable
function AddEnvironmentPath {
    param (
        [string] $envPathToAdd
    )
    #*add installation path to PATH environment variable
    $PathExist = ""
    write-log "Checking the path does not exist in the PATH environment variable ..."
    $Path = [Environment]::GetEnvironmentVariable("PATH", "Machine") 
    $PathExist = ($Path.Split(';') | Where-Object { $_ -eq "$($envPathToAdd)"})
    
    if ($PathExist -eq $null) #~Changed in version 1.7.1 in order to fix the condition to work when the environment varaiable does not exist.
    {
        try{
            write-log "Adding the ""$($envPathToAdd)"" path to the PATH environment variable ..."
            $Path = [Environment]::GetEnvironmentVariable("PATH", "Machine") + [IO.Path]::PathSeparator + $envPathToAdd
            [Environment]::SetEnvironmentVariable( "Path", $Path, "Machine" )
            write-log "Sucesfully added the installation path to the PATH environment variable!" -Severity Success
        }
        catch{write-log -message "An error occured adding the installation path to the PATH environment variable. $($Error)" -Severity Error}
    }
    else{write-log -Message "This path ""$($envPathToAdd)""is already in the PATH; no need to add." -FunctionType "AddEnvironmentPath" -Severity Warning}
}

function Uninstall-Application{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ApplicationName
    )
    ### Uninstall Previous installations, if exists
    $IsInstalled = Get-Package -Name "$($ApplicationName)*" -EA SilentlyContinue
    If ($IsInstalled) {
        $Version = $IsInstalled.Version
        $Name = $IsInstalled.Name
        $ProductCode = $IsInstalled.Metadata["ProductCode"]
        try{$UninstallString=$IsInstalled.Metadata["UninstallString"].Split("""")}
        catch{$UninstallString = $null}
        if ($UninstallString -ne $null){
            Write-Log -Message "[UNINSTALL] Uninstall string Found: $Name ($Version)" -FunctionType Uninstall-Application
            try{Kill-Process @("$($appExecutable)")}
            catch{}
            $InstallAction = (Start-Process "$($UninstallString)" -NoNewWindow -Wait -PassThru -ArgumentList "/VERYSILENT /NORESTART")

        }
        elseif ($ProductCode -ne "")
        {
            Write-Log -Message "[UNINSTALL] ProductCode Found: $Name ($Version)" -FunctionType Uninstall-Application
            try{Kill-Process @("$($appExecutable)")}
            catch{}
            $InstallAction = (Start-Process "$($env:WinDir)\System32\msiexec.exe" -NoNewWindow -Wait -PassThru -ArgumentList " /x $($ProductCode) /qb-!") #/l*v""$logFilePath\$appName-Uninstall-MSI.log""")
        }
        Remove-Item -Path "$env:ProgramFiles\$($appName)*" -Force -Recurse -EA SilentlyContinue
        Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$($appName)*" -Force -Recurse -EA SilentlyContinue

        $ReturnCode = $InstallAction.ExitCode
        Write-Log -Message "[UNINSTALL] $Name $Version returned $ReturnCode" -FunctionType Uninstall-Application   
        Return $ReturnCode  
    }
}



# BEGIN MAIN =============================================================================
write-log -Message  "==================================================================================" -Severity Information -FunctionType "MAIN"
write-log -Message  "[SCRIPT TITLE: $appVendor $appName]" -Severity Information -FunctionType "MAIN"
write-log -Message  "[SCRIPT AUTHOR: $appScriptAuthor]" -Severity Information -FunctionType "MAIN"
write-log -Message  "[SCRIPT CEATION DATE: $appScriptDate]" -Severity Information -FunctionType "MAIN"
write-log -Message  "[SCRIPT VERSION: $appScriptVersion]" -Severity Information -FunctionType "MAIN"
write-log -Message  "[EXECUTION DATE: $StartDate]"  -Severity Information -FunctionType "MAIN"
write-log -Message  "[EXECUTION START TIME:  $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "MAIN"
write-log -Message  "[EXECUTION CONTEXT: $([Security.Principal.WindowsIdentity]::GetCurrent().Name) (empty=System account)]"  -Severity Information -FunctionType "MAIN"
write-log -Message  "==================================================================================" -Severity Information -FunctionType "MAIN"
write-log -Message  "[SOFTWARE FRIENDLY NAME: $appFriendlyName]"  -Severity Information -FunctionType "MAIN"
write-log -Message  "[INSTALL TYPE: $appInstallType]"  -Severity Information -FunctionType "MAIN"
write-log -Message  "[SOFTWARE ACTION: $scriptCategory]"  -Severity Information -FunctionType "MAIN"
write-log -Message  "[SOFTWARE LANGUAGE: $appLang]"  -Severity Information -FunctionType "MAIN"
write-log -Message  "[SOFTWARE REVISION: $appRevision]"  -Severity Information -FunctionType "MAIN"
write-log -Message  "==================================================================================" -Severity Information -FunctionType "MAIN"
# ==================================================================================

if (!(Test-RebootRequired))
{
    write-log -Message  "No reboot required, Application can be installed!" -Severity Information -FunctionType "MAIN"
    if(!($appProductCode)-and ($deploymentType -eq "MSI"))
    {
        if ($InstallMSP)
        {
           $appProductCode = Get-MsiPropertyValue -Path "$dirInstallFiles\$InstallMSP" -Property "ProductCode"
        }
        else {
            $appProductCode = Get-MsiPropertyValue -Path "$dirInstallFiles\$InstallMSI" -Property "ProductCode"
        }
    }
    #* Check the runnig process and stop them if needed
    try
    {
        write-log -Message "Check running $($appName) Instances ..." -Severity Information -FunctionType "MAIN"
        if (Test-Path $appExecutablePath)
        {
            write-log -Message "$($appName) Instances detected ..." -Severity Information -FunctionType "MAIN"
            # get application Monitoring process
            if($appExecutable.Contains(".exe"))
            {$processName = $appExecutable.Substring(0,$appExecutable.IndexOf("."))}
            else{$processName = $appExecutable}
            $ProcessMon = Get-Process $ProcessName -ErrorAction SilentlyContinue
            if ($ProcessMon -ne $null)
            {
                    write-log -Message "Killing the process $($appName) Instances ..." -Severity Warning -FunctionType "MAIN"
                    Kill-Process $ProcessName 
            }
            Remove-Variable ProcessMon
        }
    }
    catch { write-log -Message "Warning: no running instances for: $($appName)" -Severity Warning -FunctionType "MAIN" }

    Switch ($deploymentType)
    {
        {($_ -eq "Uninstall") -or ($_ -eq "Install") -or ($_-eq "Repair")} # BEGIN Uninstall commands
        {
            write-log -Message "Start Uninstalling $appName ..." -Severity Information -FunctionType "MAIN"
            Uninstall-Application -ApplicationName $appName

            ### Copyfolder commands
            if (!($installFolder -eq ""))   #Check to define if there is an copyfolder installation defined.
            {
                write-log -Message "Start CopyFolder uninstall ..." -Severity Information -FunctionType "MAIN"
                write-log -Message "InstallFolder: $installFolder" -Severity Information -FunctionType "MAIN"
                write-log -Message "SourceFolder: $dirInstallFiles\$sourceFolder" -Severity Information -FunctionType "MAIN"
                write-log -Message "Start uninstalling $appName ..." -Severity Information -FunctionType "MAIN"
                #* Remove the Installation folder
                try
                {
                    if(Test-Path $installFolder){
                        write-log -Message "Command: Remove-Item $installFolder -Recurse -Force"
                        Remove-Item $installFolder -Recurse -Force
                        
                        write-log -Message  "$installFolder has been removed!" -Severity Success -FunctionType "MAIN"
                    }
                    else{write-log -Message "$installFolder could not be found" -Severity Warning}
                }
                catch{write-log -Message  "$installFolder cannot be removed!" -Severity Error -FunctionType "MAIN"}
                #* Remove the Shortcut, if it has been defined
                if ($appShortcutIconLocation -ne "")
                {
                    try{
                        write-log -Message "Command: Remove-Item ""$appShortcutDestination"" -Force" -Severity Information
                        Remove-Item "$appShortcutDestination" -Force
                        
                        if(!(test-path $appShortcutDestination)) {write-log -Message  "$appShortcutDestination has been removed!" -Severity Information -FunctionType "MAIN"}
                        else {write-log -Message "$appShortcutDestination could not be removed: $($error[0])"}
                    }
                    catch{write-log -Message "$appShortcutDestination cannot be removed: $($Error[0])" -Severity Error 
                    }
                }
                else {
                    write-log -Message  "No shortcut created during install process, no furhter actions." -Severity Error -FunctionType "MAIN"
                }

                if (!(Test-Path $installFolder))
                {
                    write-log -Message "Application $appName removed." -Severity Information -FunctionType "MAIN"
                }
            }
            write-log -Message "End copy uninstall ..." -Severity Information -FunctionType "MAIN"   
        }
        {($_ -eq "Install") -or ($_-eq "Repair")} # BEGIN install or repair commands
        {
            write-log -Message "Start Installing $appName ..." -Severity Information -FunctionType "MAIN"
            ###  Executable install commands
            if ($appInstaller -ne ""){   #Check to define if there is an executable installation defined.
                write-log -Message "Start Executable install ..." -Severity Information -FunctionType "MAIN"
                try{
                    write-log -Message "Command: Start-Process $dirInstallFiles\Installer\$appInstaller -ArgumentList $appInstallParameters -Wait -NoNewWindow -Verbose"
                    Start-Process "$dirInstallFiles\Installer\$appInstaller" -ArgumentList "$appInstallParameters" -Wait -NoNewWindow -Verbose
                    write-log -Message "$appInstaller sucessfully executed!" -Severity Success
                }
                catch{
                    write-log -Message "$appInstaller has run onto an error: $($Error)" -Severity Error
                }
               #!customization
                if (Test-Path $installFolder) 
                {
                    <#* Copy the config files 
                    write-log -Message "Command: Copy-FileSafer -sourceFolder $sourcefolder -destinationfolder $installFolder"
                    try {
                        Copy-FileSafer -sourceFolder "$($sourceFolder)" -destinationfolder "$installFolder"
                        write-log -Message "All files and folders successully copied!" -Severity Success
                    }
                    catch
                    {
                        write-log -Message "Application files are not copied- Error: $($Error[0])" -Severity Error
                    }
                    #>
                    #* write the XML config file
                    $ComputerName = ($env:COMPUTERNAME)
                    $xmlPath = "$dirInstallFiles\Installer\LocalSetting.xml"
                    $xml = [xml](get-content -path $xmlPath)
                    foreach( $obj in $xml.configuration.appSettings.add){
                        if ($obj.key -eq "UseOfflineDatabase"){
                            Write-Host "key: $($obj.key) - Value: $($obj.value)"  
                            if (($ComputerName) -like "IPX*")
                            {
                                $obj.value = "True"
                            }
                            else{
                                $obj.value= "False"
                            }
                            Write-Host "key: $($obj.key) - Value: $($obj.value)"
                        }
                    }
                    $xml.Save("c:\ProgramData\OSG\ShellPlus\Config\LocalSetting.xml")
                }
               #!end of customizaion
                write-log -Message "End executable install ..." -Severity Information -FunctionType "MAIN"
            }
            ###  MSI Install commands
            if ($InstallMSI -ne ""){   #Check to define if there is an MSI installation defined.
                write-log -Message "Start MSI install ..." -Severity Information -FunctionType "MAIN"
                if($InstallMST)
                    {
                        if($MSIParameters){
                            write-log -Message "Command: Execute-MSI -Action Install -Path $InstallMSI -Transform $InstallMST -AddParameters $MSIParameters"
                            $ErrorLevel = Execute-MSI -Action Install -Path "$InstallMSI" -Transform "$InstallMST" -AddParameters $MSIParameters
                        }
                        else{
                            write-log -Message "Command: Execute-MSI -Action Install -Path $InstallMSI -Transform $InstallMST"
                            $ErrorLevel = Execute-MSI -Action Install -Path "$InstallMSI" -Transform "$InstallMST"
                        }
                    }
                    else 
                    {
                        if($MSIParameters){
                            write-log -Message "Command: Execute-MSI -Action Install -Path $InstallMSI -AddParameters $MSIParameters"
                            $ErrorLevel = Execute-MSI -Action Install -Path "$InstallMSI" -AddParameters $MSIParameters
                        }
                        else{
                            write-log -Message "Command: Execute-MSI -Action Install -Path $InstallMSI"
                            $ErrorLevel = Execute-MSI -Action Install -Path "$InstallMSI"
                        }
                    }
                write-log -Message "End MSI install ..." -Severity Information -FunctionType "MAIN"
            }
            ### Copyfolder commands
            if (!($installFolder -eq ""))   #Check to define if there is an copyfolder installation defined.
            {
                write-log -Message "Start Copy install ..." -Severity Information -FunctionType "MAIN"
                #* Copying Application files and folder
                write-log -message "InstallFolder: $installFolder"-Severity Information -FunctionType "MAIN"
                write-log -message "SourceFolder: $dirInstallFiles\$sourceFolder"-Severity Information -FunctionType "MAIN"
                #* Copy the folder content 
                write-log -Message "Command: Copy-FileSafer -sourceFolder $dirInstallFiles\$sourceFolder -destinationfolder $installFolder"
                try {
                    Copy-FileSafer -sourceFolder "$dirInstallFiles\$sourceFolder" -destinationfolder "$installFolder"
                    write-log -Message "All files and folders successully copied!" -Severity Success
                }
                catch
                {
                    write-log -Message "Application files are not copied- Error: $($Error[0])" -Severity Error
                }
                #* Create a Shortcut
                if ($appShortcutEXE -ne "" -and ((Test-Path -path $appShortcutEXE) -eq $true))
                {
                        write-log -message "The shortcut to $appShortcutEXE is going to be created ..." 
                        write-log -Message "Command: Set-Shortcut -SourceExe $appShortcutEXE -DestinationPath $appShortcutDestination -Arguments $appshortcutArgs"
                    try
                    {
                        Set-Shortcut -SourceExe "$($appShortcutEXE)" -DestinationPath "$($appShortcutDestination)" -Arguments "$($appshortcutArgs)"
                        write-log -Message "Shortcut for $appName successully created!" -Severity Success
                    }
                    catch{write-log -Message "Shortcut not created - Error: $($Error[0])" -Severity Error}
                }
                
                #* Create a registry key
                if ($strKeyPath -ne ""){
                    try{
                        write-log -message "The registry key $strKeyPath is going to be created ..." 
                        write-log -Message "Command: Create-RegKey -strKeyPath $strKeyPath -strName $strRegName -strValue $strRegValue -strType $strRegType"
                        Create-RegKey -strKeyPath $strKeyPath -strName $strRegName -strValue $strRegValue -strType $strRegType
                        write-log -Message "Registry key created successfully" -Severity Success
                    }
                    catch{
                        write-log -message "The Registry key $strKeyPath cannot be created!"-Severity Error -FunctionType "MAIN"
                    }
                }
                else {
                    write-log -message "The registry key is empty, no registry key will be created" -Severity Information -FunctionType "MAIN"
                }
                
                #* Registers a DLL
                if ($DLLFilePath -ne ""){
                        try{
                            write-log -message "The DLL $DLLFilePath is going to be registered ..." 
                            write-log -Message "Command: Register-DLL -FilePath $DLLFilePath -Register"
                            Register-DLL -FilePath $DLLFilePath -Register
                            write-log -message "The DLL $DLLFilePath is registered successfully" -Severity Success
                        }
                        catch{write-log -message "The DLL $DLLFilePath cannot be registered, Check the function log." -Severity Error}
                    }
                    write-log -Message "End copy install ..." -Severity Information -FunctionType "MAIN"

            }
            #~ Driver installation
            if (($InfDirs -ne "")){
                write-log -Message "Start Driver install ..." -Severity Information -FunctionType "MAIN"
                foreach ($INFDir in $InfDirs)
                {
                    write-log -Message "[Driver Install] Getting the drivers in the folder: ""$($dirInstallFiles)\$($InfDir)""" -Severity Information
                    $CATPaths = get-ChildItem "$($dirInstallFiles)\$($InfDir)" -Recurse -Filter "*inf"
                    ForEach($CATPath in $CATPaths) {
                    #import driver signature and install driver
                        $signature = Get-AuthenticodeSignature $CATPath.FullName
                        $store = Get-Item -Path Cert:\LocalMachine\TrustedPublisher
                        $store.Open("ReadWrite")
                        $store.Add($signature.SignerCertificate)
                        $store.Close()
                    }
                    
                    $INFPaths = get-ChildItem "$($dirInstallFiles)\$($InfDir)" -Recurse -Filter "*inf"
                    foreach ($INFpath in $INFPaths){
                    try{
                        write-log -Message "Command: Start-Process pnputil.exe -ArgumentList ""/add-driver $($INFpath.FullName) /install"" -Wait -NoNewWindow -Verbose"
                        Start-Process "pnputil.exe" -ArgumentList "/add-driver $($INFpath.FullName) /install" -Wait -NoNewWindow -Verbose
                        write-log -Message "Driver installation sucessfully executed!" -Severity Success
                    }
                    catch{
                        write-log -Message "Driver installation has run onto an error: $($Error)" -Severity Error
                    }
                    write-log -Message "End Driver install ..." -Severity Information -FunctionType "MAIN"
                    }
                }
            }
        }
    }
    write-log -Message  "==================================================================================" -Severity Information -FunctionType "MAIN"
    write-log -Message  "[EXECUTION END TIME: $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "MAIN"
    write-log -Message  "[SCRIPT EXIT CODE: $($ErrorLevel)] " -Severity Information -FunctionType "MAIN"
    write-log -Message  "==================================================================================" -Severity Information -FunctionType "MAIN"

    #return exit-code to SCCM
    if($boolRestartNeeded)
    {Exit 3010}
    else 
    {Exit 0}
}
else 
{
    write-log -Message  "REBOOT required" -Severity Warning -FunctionType "MAIN"
    write-log -Message  "==================================================================================" -Severity Information -FunctionType "MAIN"
    write-log -Message  "[EXECUTION END TIME: $(Get-Date -Format "HH:mm:ss")]" -Severity Information -FunctionType "MAIN"
    write-log -Message  "[SCRIPT EXIT CODE: $($ErrorLevel)] " -Severity Information -FunctionType "MAIN"
    write-log -Message  "==================================================================================" -Severity Information -FunctionType "MAIN"
    
    #return exit-code to SCCM
    Exit 3010
}



