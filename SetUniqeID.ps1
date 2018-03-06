 $DiskpartFile = "C:\Windows\Temp\DiskpartFile.txt"
$Diskpartlog = "C:\Windows\Temp\DiskpartFile.log.txt"
$DriveLetter ='C'
Write-host "Which driveletters do we have?" -ForegroundColor Yellow 

 $Searchvol = "list volume" | C:\Windows\System32\diskpart.exe | select-string -pattern "Volume" | select-string -pattern "$DriveLetter " -casesensitive | select-string -pattern NTFS | out-string    
	    Write-host "$Searchvol"

 $Searchvol2 = "list volume" | C:\Windows\System32\diskpart.exe | select-string -pattern "Volume" | select-string -pattern "E" -casesensitive | select-string -pattern NTFS | out-string    
	    Write-host "$Searchvol2"

$getvolNbr = $Searchvol.substring(11,1)   # get Volumenumber from DiskLabel
        Write-host  "Get Volumenumber $getvolNbr from Disklabel $DriveLetter" -ForegroundColor Yellow

$getvolNbr2 = $Searchvol2.substring(11,1)   # get Volumenumber from DiskLabel E
        Write-host  "Get Volumenumber $getvolNbr2 from Disklabel E" -ForegroundColor Yellow

　
        Remove-Item $DiskpartFile -recurse -ErrorAction SilentlyContinue
        # Write Diskpart File
        "select volume $getvolNbr" | out-file -filepath $DiskpartFile -encoding Default
        "uniqueid disk" | out-file -filepath $DiskpartFile -encoding Default -append
        Get-Content "$DiskpartFile"
        $result = diskpart /s $DiskpartFile
	    $getid = $result | select-string -pattern "ID" -casesensitive | out-string
        $getid = $getid.Split(":")  #split string on ":"
		$getid = $getid[1] #get the first string after ":" to get the Disk ID only without the Text 
		$getid = $getid.trim() #remove empty spaces on the right and left
       Write-host "Get uniqe ID for C: $getid" -ForegroundColor Yellow
       Write-host "Create diskpart file" -ForegroundColor Yellow
        Remove-Item $DiskpartFile -recurse -ErrorAction SilentlyContinue
        "select volume $getvolNbr2" | out-file -filepath $DiskpartFile -encoding Default
        "uniqueid disk id=$getid" | out-file -filepath $DiskpartFile -encoding Default -append
        Get-Content "$DiskpartFile"

　
Write-host "Set uniqe ID from C: to vdisk" -ForegroundColor Yellow		
Diskpart /s $DiskpartFile

$offlinedisk = "list disk" | diskpart | where {$_ -match "offline"}
{

        #if offline disk(s) are available then display.    
        if($offlinedisk)
        {
        
            #Display offline disks on the server
            Write-Host "Det gikk i orden. du kan skru av serveren og sette vDisken til standard" -ForegroundColor Green
            Write-Output "  Disk ###  Status         Size     Free     Dyn  Gpt"
            Write-Output " --------  -------------  -------  -------  ---  ---"
            $offlinedisk
        }
        else
        {
        
            #No disks are offline
            Write-Output "I helvete da. vi må ringe Kent"
        
        }
        } 
