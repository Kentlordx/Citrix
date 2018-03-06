 # Seal Master-image and convert to PVS
import-module activedirectory

$Source = ''
$SystemDrive = get-content env:Systemdrive
$Windir = get-content env:systemroot
$ProgramData = get-content env:ProgramData
$ProgramFiles = get-content env:ProgramFiles
$ProgramFilesx86 = get-content env:'ProgramFiles(x86)'
$ComputerName = get-content env:ComputerName
$UserTemp = get-content env:Temp
$Seal = "HKLM:\SOFTWARE\Sicra\reseal"
$date = get-date

#flytter server til Utviklings OU
Write-Host 'Move server to Utvikling OU' -ForegroundColor Green
get-adcomputer $ComputerName | Move-ADObject -TargetPath "OU=prod,OU=citrix,OU=server,DC=lordx,DC=org" 

##Server Tuning ##

Write-Host 'Prevent Server manager and Powershell in Taskbar for users' -ForegroundColor Yellow
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows PowerShell" /T /inheritance:d
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows PowerShell" /T /remove:g "BUILTIN\Users" Everyone
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Server Manager.lnk" /inheritance:d
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Server Manager.lnk" /remove:g "BUILTIN\Users" Everyone
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\System Tools\Task Manager.lnk" /inheritance:d
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\System Tools\Task Manager.lnk\Server Manager.lnk" /remove:g "BUILTIN\Users" Everyone
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\System Tools\Windows PowerShell.lnk" /inheritance:d
ICACLS "$ProgramData\Microsoft\Windows\Start Menu\Programs\System Tools\Task Manager\Windows PowerShell.lnk" /remove:g "BUILTIN\Users" Everyone

# 'Noisy Logon'
REG ADD "HKLM\SOFTWARE\WOW6432Node\Citrix\Logon" /V DisableStatus /T REG_DWORD /D 1 /F

Write-Host 'IE Enhanced Security from System' -ForegroundColor Green
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v "IsInstalled" /t REG_DWORD /d 0 /f /reg:64
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /v "IsInstalled" /t REG_DWORD /d 0 /f /reg:64

# Removing IE Enhanced Security from System
invoke-expression -command "Rundll32 iesetup.dll,IEHardenUser"
invoke-expression -command "Rundll32 iesetup.dll,IEHardenAdmin"
invoke-expression -command "Rundll32 iesetup.dll,IEHardenMachineNow"

# Removes from Add Remove Components
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OC Manager\Subcomponents" /v "iehardenadmin" /t REG_DWORD /d 0 /f /reg:64
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OC Manager\Subcomponents" /v "iehardenuser" /t REG_DWORD /d 0 /f /reg:64

# Remove the Values from the IEHarden installed components key
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /f /va /reg:64
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /f /va /reg:64

Write-Host 'Disable Last Access Time Stamp' -ForegroundColor Green
FSUTIL behavior set disablelastaccess 1

# 'Powersettings tuning for VMs'
Write-Host 'Powersettings tuning for VMs' -ForegroundColor Green
Powercfg -setacvalueindex scheme_current sub_processor 45bcc044-d885-43e2-8605-ee0ec6e96b59 100
Powercfg -setactive scheme_current
Powercfg -setacvalueindex scheme_current sub_processor 893dee8e-2bef-41e0-89c6-b55d0929964c 100
Powercfg -setactive scheme_current
Powercfg -setacvalueindex scheme_current sub_processor bc5038f7-23e0-4960-96da-33abaf5935ec 100
Powercfg -setactive scheme_current
# hard disk timeout
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0 

# Disable Disable TCP/IP / Large Send Offload
New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name 'DisableTaskOffload' -value '00000001' -PropertyType 'dword'

# Increase service startup timeouts
# New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control" -name 'ServicesPipeTimeout' -value '00002bf20' -PropertyType 'dword'

# Clean run registry key
reg delete 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' /va /f

Write-Host 'Turn off DEP' -ForegroundColor Green
BCDEDIT /set "{current}" nx AlwaysOff

Write-Host 'Disable the boot animation' -ForegroundColor Green
BCDEDIT /set BOOTUX disabled

Write-Host 'Set the Pagefile size on the Target Device' -ForegroundColor Green
$ComputerSystem = Get-WmiObject Win32_computersystem -EnableAllPrivileges
$ComputerSystem.AutomaticManagedPagefile = $false
$ComputerSystem.Put()
$PageFile = Get-WmiObject -class Win32_PageFileSetting
$PageFile.InitialSize = 0
$PageFile.MaximumSize = 0
$PageFile.Put()

Write-Host 'Enable Automount av disker' -ForegroundColor Green
Mountvol /E

# Running PVS Device Optimalization

Write-Host 'Running PVS Device Optimalization' -ForegroundColor Green
REG ADD HKLM\Software\Citrix\ProvisioningServices /v DeviceOptimizerRun /d 1 /t REG_DWORD /f /reg:64

Write-Host 'Disable Offline Files' -ForegroundColor Yellow
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache /v Enabled /d 0 /t REG_DWORD /f /reg:64

Write-Host 'Disable Defrag BootOptimizeFunction' -ForegroundColor Yellow
REG ADD HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction /v Enable /d "N" /t REG_SZ /f /reg:64

Write-Host 'Disable Background Layout Service' -ForegroundColor Yellow
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout /v EnableAutoLayout /d 0 /t REG_DWORD /f /reg:64

Write-Host 'Disable Last Access Timestamp' -ForegroundColor Yellow
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v NtfsDisableLastAccessUpdate /d 1 /t REG_DWORD /f /reg:64

Write-Host 'Disable Hibernate' -ForegroundColor Yellow
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /d 0 /t REG_DWORD /f /reg:64

Write-Host 'Disable CrashDump' -ForegroundColor Yellow
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /d 0 /t REG_DWORD /f /reg:64
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v LogEvent /d 0 /t REG_DWORD /f /reg:64
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v SendAlert /d 0 /t REG_DWORD /f /reg:64

Write-Host 'Disable Indexing Service' -ForegroundColor Yellow
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\cisvc /v Start /d 4 /t REG_DWORD /f /reg:64

Write-Host 'Reduce Event Log Size to 64k' -ForegroundColor Yellow
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application /v MaxSize /d 65536 /t REG_DWORD /f /reg:64
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security /v MaxSize /d 65536 /t REG_DWORD /f /reg:64
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System /v MaxSize /d 65536 /t REG_DWORD /f /reg:64

Write-Host 'Reduce IE Temp File' -ForegroundColor Yellow
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths" /v Paths /d 4 /t REG_DWORD /f /reg:64
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path1" /v CacheLimit /d 256 /t REG_DWORD /f /reg:64
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path2" /v CacheLimit /d 256 /t REG_DWORD /f /reg:64
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path3" /v CacheLimit /d 256 /t REG_DWORD /f /reg:64
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path4" /v CacheLimit /d 256 /t REG_DWORD /f /reg:64

Write-Host 'Disable Clear Page File at Shutdown' -ForegroundColor Yellow
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /d 0 /t REG_DWORD /f /reg:64

Write-Host 'Disable Machine Account Password Changes' -ForegroundColor Yellow
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v DisablePasswordChange /d 1 /t REG_DWORD /f /reg:64

Write-Host 'Disable Vista/7 Windows Search' -ForegroundColor Yellow
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\WSearch /v Start /d 4 /t REG_DWORD /f /reg:64

Write-Host 'Disable BITS og Shell Hardware detection' -ForegroundColor Yellow
Get-Service bits,ShellHWDetection | where-object {$_.status -eq "running"} | Stop-Service -PassThru | Set-Service -StartupType Disabled 

Write-Host 'Disable scheduled tasks' -ForegroundColor Yellow
Get-ScheduledTask -TaskName aitagent,AnalyzeSystem,BfeOnServiceStartTypeChange,UPnPHostConfig | Disable-ScheduledTask

Write-Host 'Get updates for other Microsoft Products' -ForegroundColor Yellow

$mu = New-Object -ComObject Microsoft.Update.ServiceManager -Strict 
$mu.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")

 #Optimalisering av image

Write-Host 'Flush DNS cache' -ForegroundColor Yellow
IPCONFIG /flushdns

Write-Host 'Flush ARP table' -ForegroundColor Yellow
ARP.exe -d *

Write-Host "Disable Receive Side Scaling (RSS)" -ForegroundColor Yellow
Start-Process -FilePath 'netsh.exe' -Argumentlist 'int tcp set global rss=disable' -Wait -WindowStyle Hidden

# Turn on 8dot3name for App-v5
Write-Host "Turn on 8dot3name for App-v5" -ForegroundColor Yellow
fsutil.exe 8dot3name set C: 0
fsutil.exe 8dot3name set 0

Write-Host 'Remove All Windows features not used' -ForegroundColor Yellow
# Remove All Windows features not used
Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Available'} | Uninstall-WindowsFeature -Remove

Write-Host 'adobe services' -ForegroundColor Yellow
$Servicelist="AdobeARMservice", "ctxProfile"
Get-Service $Servicelist| Stop-Service -PassThru | Set-Service -StartupType Disabled

　
Write-Host 'Disable useless scheduled tasks' -ForegroundColor Yellow
## Disable useless scheduled tasks
	IF (($OSVersion -like "6.3*") -or ($OSVersion -like "10*"))
	{
				$ScheduledTasksList = @("AitAgent","ProgramDataUpdater","StartupAppTask","Proxy","UninstallDeviceTask","BthSQM","Consolidator","KernelCeipTask","Uploader","UsbCeip","Scheduled","Microsoft-Windows-DiskDiagnosticDataCollector","Microsoft-Windows-DiskDiagnosticResolver","WinSAT","HotStart","AnalyzeSystem","RacTask","MobilityManager","RegIdleBackup","FamilySafetyMonitor","FamilySafetyRefresh","AutoWake","GadgetManager","SessionAgent","SystemDataProviders","UPnPHostConfig","ResolutionHost","BfeOnServiceStartTypeChange","UpdateLibrary","ServerManager","Proxy","UninstallDeviceTask","Scheduled","Microsoft-Windows-DiskDiagnosticDataCollector","Microsoft-Windows-DiskDiagnosticResolver","WinSAT","MapsToastTask","MapsUpdateTask","ProcessMemoryDiagnosticEvents","RunFullMemoryDiagnostic","MNO Metadata Parser","AnalyzeSystem","MobilityManager","RegIdleBackup","CleanupOfflineContent","FamilySafetyMonitor","FamilySafetyRefresh","SR","UPnPHostConfig","ResolutionHost","UpdateLibrary","WIM-Hash-Management","WIM-Hash-Validation" )
		ForEach ($ScheduledTaskList in $ScheduledTasksList)
		{
			$task = Get-ScheduledTask -TaskName $ScheduledTaskList -ErrorAction SilentlyContinue
			IF ($task)
			{

				$TaskPathName = Get-ScheduledTask -TaskName $ScheduledTaskList | % {$_.TaskPath}
				$PrepCommands +=  [pscustomobject]@{Order="$ordercnt"; Enabled="$true"; showmessage="N"; CLI="";                Description="Disable scheduled Task $ScheduledTaskList ";                                                    		   Command="Disable-ScheduledTask -Taskname $ScheduledTaskList -TaskPath '$TaskPathName' | Out-Null"};$ordercnt += 1
			
	}
}
}
 
 
