write-host "`n...........................................`n"
write-host "@ACALARCH Convert .ETL to WEF subscribable log"
write-host '    Requires CSV in "C:\Windows\Temp\pathstopull.txt"' 
write-host '    ......CSV Format Example......' 
write-host "        C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Trace.etl, CUST_WMITRACE"
write-host '    ......END EXAMPLE......'
write-host "...........................................`n"
start-sleep -s 1

$logz = ""

function load-etl {
    try{
    write-host "Attempting to read CSV at "C:\Windows\Temp\pathstopull.txt"" 
    $filehash = get-filehash "C:\Windows\Temp\pathstopull.txt" -ErrorAction Stop
    $filehash = $filehash.Hash
    $b = import-csv "C:\Windows\Temp\pathstopull.txt" -header Path,Name -ErrorAction Stop 
    }
    catch 
    {
    write-host -foregroundcolor RED "Unable to load CSV at "C:\Windows\Temp\pathstopull.txt"" 
    write-host -foregroundcolor RED "EXITING"
    exit 
    }

    $logz = @()


    write-host -foregroundcolor cyan "Attempting to load etl sources and preparing destination logs"
    foreach($source in $b){
        $alive = "ALIVE"
        Try{
             get-winevent -Oldest -Path $source.Path -ErrorAction Stop | out-null
             Get-WinEvent -ListLog $source.Name -ErrorAction Stop | out-null
        }
        Catch
        {
        $pathexists = test-path $source.path
        write-host checking if path to log exists
            if(-Not $pathexists)
            {
                write-host -foregroundcolor RED "Following Log Does Not Exist or is Inaccessible, Logs Will Not Be Converted, Maybe Ensure The Log Is Enabled?:" $source.path
                $alive = "DEAD"
            }
            else{
            $exceptional = $_.Exception.Message.ToString()
            if($exceptional -like 'There is not an event log on the localhost computer that matches*')
            {
             try{
             new-eventlog -source $source.Name -logname $source.Name -erroraction Stop | out-null
             write-host "created event:" $source.Name
             }
             catch
             {
             write-host unable to create log $source.Name, windows looks at only the first 8 chars for custom logs, so please ensure name does not conflict
             write-host Logs Will Not Be Converted for: $source.Name
             $alive = "DEAD"
             }
            }
        }
        }

        $log = New-Object -TypeName PSObject
        $log | Add-Member -Type NoteProperty -Name Path -Value $source.Path
        $log | Add-Member -Type NoteProperty -Name Name -Value $source.Name
        if($alive -eq "DEAD"){
        $log | Add-Member -Type NoteProperty -Name Enabled -Value "false"
        }
        else{
        $log | Add-Member -Type NoteProperty -Name Enabled -Value "true"
        }
        $log | Add-Member -Type NoteProperty -Name LastUpdate -Value "No new logs"

        if($alive -eq "ALIVE"){
        $logz += $log
        }
    }
    $returns += $logz
    $returns += $filehash
    return $returns
}

$return = load-etl
$logz = @()
for($i=0; $i -lt ($return.Length - 1); $i++)
{
$logz += $return[$i]
}
$filehash = $return[$return.Length -1]


foreach($log in $logz){
    if($log.Enabled = "true"){
    write-host "Loaded Source:" $log.Path
    }
}

write-host "`n"

$lastlogtime = "No new logs"


$count = 0

while($true){
    if($count -eq 6){
      $count = 0
      write-host -foregroundcolor Gray "Checking for updates"
      try{
      $filehashnow = get-filehash "C:\Windows\Temp\pathstopull.txt" -erroraction STOP
      $filehashnow = $filehashnow.Hash
      }
      catch{
      $filehashnow = "NOPE"
      }
      if(($filehashnow -ne $filehash) -and ($filehashnow -ne "NOPE")){
                $return = load-etl
                $logz = @()
                for($i=0; $i -lt ($return.Length - 1); $i++)
                {
                    $logz += $return[$i]
                }
                $filehash = $return[$return.Length -1]
            }
    }
    $count = $count + 1
    $a = get-date
    write-host -foregroundcolor "cyan" "Checking Logs"
    foreach($log in $logz){
        write-host -foregroundcolor "green" "    Checking logs for:" $log.Path 
        $mylogs = $null
        if($log.LastUpdate -eq "No new logs")
        {
            $mylogs = get-winevent -Oldest -Path $log.Path | where-object {$_.TimeCreated -gt $a.AddMinutes(-1)}
        }
        else{
            $mylogs = get-winevent -Oldest -Path $log.Path | where-object {$_.TimeCreated -gt $log.LastUpdate}
        }

        if($mylogs -is [system.array]){
            $log.LastUpdate = $mylogs[$mylogs.Length - 1].TimeCreated
            write-host "    ...Converted" $mylogs.Length "logs"
            write-host "    ...Latest log was at:" $log.LastUpdate
            $mylogs | foreach-object {$message = $_.Message + ";`n`nTime = " + $_.TimeCreated + "`nLevel = " + $_.Level + "`nMachineName = " + $_.MachineName + "`nProcessId = " + $_.ProcessId + "`nThreadId = " + $_.ThreadId + "`nUserId = " + $_.UserId + "`nCount = " + $count; Write-EventLog -LogName $log.Name -Source $log.Name -EventId $_.Id -Message $message}; $count = $count + 1; Start-Sleep -m 5
        }
        else{
            write-host "    ...No new logs to convert"
            write-host "    ...Latest log was at:" $log.LastUpdate
        }
    }
    write-host -foregroundcolor "cyan" "Sleeping for 15 seconds`n"
    start-sleep -s 15
}
