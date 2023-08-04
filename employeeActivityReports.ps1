#This script is designed all of the usual reports on employee activity for supervisor.
#This kind of reporting requires that a ticket be submitted from the department heads. 
#If a ticket has not been submitted by a department head to run these reports, stop the script. 



#Region AuditReportFolder
#Creating variable for file and asking user to get connected to VPN
    $dateTime = Get-Date -UFormat "%Y%m%d_%H-%M-%S"
    Write-Warning "This script requires connections to ssazurefiles. Make sure that you are connected to the vpn" -WarningAction Inquire
    try {
        Test-Connection -ComputerName "***********************" -ErrorAction Stop
        $employeeEmail = Read-Host -Prompt "Please input the user's Email Address"
        $pos = $employeeEmail.IndexOf("@")
        $accountName = $employeeEmail.Substring(0,$pos)
        $accountName = $accountName.ToLower()
        $employeeEmail = $employeeEmail.ToLower()
    }
    catch {
        Write-Host "ERROR: You are not connected to the VPN. Please connect to the VPN and rerun the script" -ForegroundColor Red
        Write-Output $_.Exception.Message
        exit 
    }

#Creating variables for the year in YYYY and the date in YYYYMMDD
#Creating new folder in the Antivirus reports folder in audit drive, 
    $dateFolder = Get-Date -UFormat "%Y%m%d"
    $yearFolder = Get-Date -UFormat "%Y"
    $newFolderPath = '**********************************\EmployeeActivityReports\'+$yearFolder+'\'+$dateFolder+'\'+$accountName
    Write-Host "Reports will be sent to $newFolderPath" -ForegroundColor Yellow
    New-Item -Path $newFolderPath -ItemType Directory -ErrorAction Ignore
#EndRegion AuditReportFolder

#Region MicrosoftGraphConnection
#App Registration Information found in AAD certificate expires on 7/3/2024
    $tenantId = '**********************'
    $appId = '************************'
    $appSecret = '*****************'
    $appCertificate = "**************************"

#Uses App Registration Information to connect to the Microsoft Graph API
    Connect-MgGraph -ClientId $appId -TenantId $tenantId -CertificateThumbprint $appCertificate 
#EndRegion MicrosoftGraphRegistration

#Region DeviceLogonEvents
    Write-Host "Device Phase: Running report for $accountName's Device Logon Events" -BackgroundColor Blue -ForegroundColor White
    $queryFile = [IO.File]::ReadAllText("***********************\EmployeeActivityReports\KQLqueries\DeviceLogonEvents.txt");
    $query = $queryFile -replace '<emplUsername>', $accountName
    $body = @{Query = $query} | ConvertTo-Json
    $result = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body $body
    $table = $result.results | ForEach-Object {
        [PSCustomObject]@{
            Timestamp           = $_.Timestamp
            DeviceName          = $_.DeviceName
            ActionType          = $_.ActionType
            LogonType           = $_.LogonType
            AccountName         = $_.AccountName
        }
    }
    $table | Export-Csv -Path "**************************************\EmployeeActivityReports\$yearFolder\$dateFolder\$accountName\DeviceLogonEvents$datetime.csv" -NoTypeInformation
#EndRegion DeviceLogonEvents

#Region DeviceLogonCount
    Write-Host "Device Phase: Running report for $accountName's Device Logon Counts" -BackgroundColor Blue -ForegroundColor White
    $queryFile = [IO.File]::ReadAllText("************************\EmployeeActivityReports\KQLqueries\DeviceLogonCount.txt");
    $query = $queryFile -replace '<emplUsername>', $accountName
    $body = @{Query = $query} | ConvertTo-Json

    $body
    $result = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body $body
    $table = $result.results | ForEach-Object {
        [PSCustomObject]@{
            AccountName     = $_.AccountName
            DeviceName      = $_.DeviceName
            DeviceId        = $_.DeviceId
            LogOnCount      = $_.LogonCount
        }
    }
    $table | Export-Csv -Path "*******************************\EmployeeActivityReports\$yearFolder\$dateFolder\$accountName\DeviceLogonCount$datetime.csv" -NoTypeInformation
#EndRegion DeviceLogonCount

#Region DeviceInfo
    $tmpFile = Import-Csv -Path "******************************************\EmployeeActivityReports\$yearFolder\$dateFolder\$accountName\DeviceLogonCount$datetime.csv"
    $eDeviceName = $tmpFile[0].psobject.Properties.value[1]
    $eDeviceId = $tmpFile[0].psobject.Properties.value[2]
#EndRegion DeviceInfo



















#Disconnects the MgGraph Session
Disconnect-MgGraph
