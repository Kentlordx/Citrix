  $menuPrompt=$title
 #add a return
 $menuprompt+=”`n”
 #add an underline
 $menuprompt+=”-”*$title.Length
 $menuprompt+=”`n”
 #add the menu
 $menuPrompt+=$menu
 
Read-Host -Prompt $menuprompt
 
}  #end function
 
#define a menu here string
 $menu=@”
1. Start Sealing
 
2. Vent med sealing
 
Q Quit.
 
Select a task by number or Q to quit
“@
 
#Keep looping and running the menu until the user selects Q (or q).
 Do {
 #use a Switch construct to take action depending on what menu choice
 #is selected.
 Switch (Show-Menu $menu ” XenMaster er klar for å seales ” ){

"1" {Powershell -executionpolicy bypass -file "\\lordxorg\dfsroot\sealing\sealing.ps1"}

"2" {Write-Host 'Trykk på 1 når du er klar'  -ForegroundColor Red}

"Q" {Write-Host “Terminating Script” -ForegroundColor Yellow
 Return
 }
 Default {Write-Warning “Invalid Choice. Try again.”
sleep -milliseconds 750}
 } #switch
 }While ($True)
 
