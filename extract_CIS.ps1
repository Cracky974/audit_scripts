param (
[string]$path_to_script = "",
[string]$path_to_xls = ""
)

$countArg = 0
ForEach($a in $args)
{
if($a -eq "-h" -or "--help" -or "help")
{
    displayUsage
}

if ($a -eq "path_to_xls") 
{
    $countArg++
}

if ($a -eq "path_to_script") 
{
    $countArg++
}

}
if ($countArg -eq 2)
{
    writeScript
}
else
{
    displayUsage
}


Function writeScript(){

    #variables "globales"
    $path = $path_to_script
    $script = ''

    #objet excel
    $excel = new-object -comobject Excel.Application
    $excel.visible = $false
    $excel.DisplayAlerts = $False
    $excel_file_path = $path_to_xls
    $workbook = $excel.Workbooks.open($excel_file_path)

    #######################################
    #Propriété Excel CIS sheet Level 1
    $sheet = $workbook.Sheets.Item(2)
    $title_col = 3
    $audit_col = 9
    $end_row = 48

    ############Formation du script ##########

    for($row=1; $row -le $end_row;$row++){

    $audit_proc = $sheet.Cells.Item($row,$audit_col).Value2
    if ($audit_proc -match 'PowerShell(.+)\n\n(.+)\n(.+)')
    {   
        $title = $sheet.Cells.Item($row,$title_col).Value2
    
        #$cmd_ps = $Matches.3
        $audit_proc = $audit_proc -split '```'

        ForEach($line in $audit_proc)
         {
          if($w -eq 1)
          {
                $cmd_ps = $line
                $w = 0
          }

           if($line -match 'PowerShell(.+)\n\n')
           {
               $w=1
           }

          }

        $script = $script+"
        "+'echo "'+$title+'"'+"
        "+$cmd_ps

    }


    }

    #Ecriture du fichier#
    if (!(Test-Path $path -PathType Leaf)){
    New-Item C:\Users\pbegin\Documents\package\outils\windows\script.ps1
    }


    Set-Content C:\Users\pbegin\Documents\package\outils\windows\script.ps1 $script
}


Function displayUsage()
{

echo 'Ce script permet d extraire un script afin de récupérer des preuves d audit depuis un fichier excel du CIS. 
La colonne audit procedure doit être de ce format là :
Ne fonctionne actuellement que sur du PowerShell.
Execute the following command to ensure no virtual directories are mapped to the system drive:

To verify using AppCmd.exe enter the following command:

```
%systemroot%\system32\inetsrv\appcmd list vdir
```
OR

To verify using PowerShell enter the following command:

```
Get-Website | Format-List Name, PhysicalPath```
'

echo 'Usage : extract_cis.ps1 -path_to_script "c:PATH\to\script" -path_to_xls "c:PATH\to\xls" '
}