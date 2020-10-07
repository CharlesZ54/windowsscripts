@echo off
:: https://privacy.sexy — v0.7.5 — Wed, 07 Oct 2020 01:18:44 GMT

:: ----------------------------------------------------------
:: -----------------Ensure admin privileges------------------
:: ----------------------------------------------------------
echo --- Ensure admin privileges
fltmc >nul 2>&1 || (
   echo Administrator privileges are required.
   PowerShell Start -Verb RunAs '%0' 2> nul || (
       echo Right-click on the script and select "Run as administrator".
       pause & exit 1
   )
   exit 0
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Customer Experience Improvement (CEIP/SQM)----
:: ----------------------------------------------------------
echo --- Disable Customer Experience Improvement (CEIP/SQM)
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Application Impact Telemetry (AIT)--------
:: ----------------------------------------------------------
echo --- Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable diagnostics telemetry---------------
:: ----------------------------------------------------------
echo --- Disable diagnostics telemetry
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f
sc stop "DiagTrack" & sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
sc stop "diagnosticshub.standardcollector.service" & sc config "diagnosticshub.standardcollector.service" start=disabled
sc stop "diagsvc" & sc config "diagsvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Customer Experience Improvement Program------
:: ----------------------------------------------------------
echo --- Disable Customer Experience Improvement Program
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Webcam Telemetry (devicecensus.exe)--------
:: ----------------------------------------------------------
echo --- Disable Webcam Telemetry (devicecensus.exe)
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Application Experience (Compatibility Telemetry)-
:: ----------------------------------------------------------
echo --- Disable Application Experience (Compatibility Telemetry)
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /DISABLE
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable telemetry in data collection policy--------
:: ----------------------------------------------------------
echo --- Disable telemetry in data collection policy
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable license telemetry-----------------
:: ----------------------------------------------------------
echo --- Disable license telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable error reporting------------------
:: ----------------------------------------------------------
echo --- Disable error reporting
:: Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
:: DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
:: Disable WER sending second-level data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
:: Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
:: Disable Windows Error Reporting Service
sc stop "WerSvc" & sc config "WerSvc" start=disabled
sc stop "wercplsupport" & sc config "wercplsupport" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Deny app access to location----------------
:: ----------------------------------------------------------
echo --- Deny app access to location
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /d "Deny" /f
:: For older Windows (before 1903)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /d "0" /t REG_DWORD /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Deny app accesss to account info, name and picture----
:: ----------------------------------------------------------
echo --- Deny app accesss to account info, name and picture
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /d "Deny" /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Deny app access to motion data--------------
:: ----------------------------------------------------------
echo --- Deny app access to motion data
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Deny app access to phone-----------------
:: ----------------------------------------------------------
echo --- Deny app access to phone
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Deny app access to trusted devices------------
:: ----------------------------------------------------------
echo --- Deny app access to trusted devices
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Deny app sync with devices (unpaired, beacons, TVs etc.)-
:: ----------------------------------------------------------
echo --- Deny app sync with devices (unpaired, beacons, TVs etc.)
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Deny app access to camera-----------------
:: ----------------------------------------------------------
echo --- Deny app access to camera
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Deny app access to microphone---------------
:: ----------------------------------------------------------
echo --- Deny app access to microphone
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: Deny apps share and sync non-explicitly paired wireless devices over uPnP
echo --- Deny apps share and sync non-explicitly paired wireless devices over uPnP
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /t REG_SZ /v "Value" /d "Deny" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Deny app access to diagnostics info about your other apps-
:: ----------------------------------------------------------
echo --- Deny app access to diagnostics info about your other apps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /d "Deny" /t REG_SZ /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to your contacts-------------
:: ----------------------------------------------------------
echo --- Deny app access to your contacts
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to Notifications-------------
:: ----------------------------------------------------------
echo --- Deny app access to Notifications
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Deny app access to Calendar----------------
:: ----------------------------------------------------------
echo --- Deny app access to Calendar
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to call history--------------
:: ----------------------------------------------------------
echo --- Deny app access to call history
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Deny app access to email-----------------
:: ----------------------------------------------------------
echo --- Deny app access to email
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /t REG_SZ /v "Value" /d DENY /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Deny app access to tasks-----------------
:: ----------------------------------------------------------
echo --- Deny app access to tasks
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /d "Deny" /t REG_SZ /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Deny app access to messaging (SMS / MMS)---------
:: ----------------------------------------------------------
echo --- Deny app access to messaging (SMS / MMS)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Deny app access to radios-----------------
:: ----------------------------------------------------------
echo --- Deny app access to radios
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /t REG_SZ /v "Value" /d DENY /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Deny app access to bluetooth devices-----------
:: ----------------------------------------------------------
echo --- Deny app access to bluetooth devices
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Deny app access to Document folder------------
:: ----------------------------------------------------------
echo --- Deny app access to Document folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Deny app access to Pictures folder------------
:: ----------------------------------------------------------
echo --- Deny app access to Pictures folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to Videos folder-------------
:: ----------------------------------------------------------
echo --- Deny app access to Videos folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Deny app access to other filesystem------------
:: ----------------------------------------------------------
echo --- Deny app access to other filesystem
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Turn off Windows Location Provider------------
:: ----------------------------------------------------------
echo --- Turn off Windows Location Provider
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Turn off location scripting----------------
:: ----------------------------------------------------------
echo --- Turn off location scripting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Turn off location---------------------
:: ----------------------------------------------------------
echo --- Turn off location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f
:: For older Windows (before 1903)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable cortana----------------------
:: ----------------------------------------------------------
echo --- Disable cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent"  /d 0 /t REG_DWORD /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable web search in search bar-------------
:: ----------------------------------------------------------
echo --- Disable web search in search bar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /d 0 /t REG_DWORD /f                   
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable search web when searching pc-----------
:: ----------------------------------------------------------
echo --- Disable search web when searching pc
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable search indexing encrypted items / stores-----
:: ----------------------------------------------------------
echo --- Disable search indexing encrypted items / stores
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable location based info in searches----------
:: ----------------------------------------------------------
echo --- Disable location based info in searches
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable language detection----------------
:: ----------------------------------------------------------
echo --- Disable language detection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AlwaysUseAutoLangDetection /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable ad customization with Advertising ID-------
:: ----------------------------------------------------------
echo --- Disable ad customization with Advertising ID
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable targeted tips-------------------
:: ----------------------------------------------------------
echo --- Disable targeted tips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn Off Suggested Content in Settings app--------
:: ----------------------------------------------------------
echo --- Turn Off Suggested Content in Settings app
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable all settings sync-----------------
:: ----------------------------------------------------------
echo --- Disable all settings sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Application Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Application Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable App Sync Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable App Sync Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Credentials Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Credentials Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Desktop Theme Setting Sync------------
:: ----------------------------------------------------------
echo --- Disable Desktop Theme Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Personalization Setting Sync-----------
:: ----------------------------------------------------------
echo --- Disable Personalization Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Start Layout Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Start Layout Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Web Browser Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Web Browser Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Windows Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable Windows Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Language Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable Language Setting Sync
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /t REG_DWORD /v Enabled /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable online device metadata collection---------
:: ----------------------------------------------------------
echo --- Disable online device metadata collection
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable cloud speech recognation-------------
:: ----------------------------------------------------------
echo --- Disable cloud speech recognation
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t "REG_DWORD" /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Disable active prompting (pings to MSFT NCSI server)---
:: ----------------------------------------------------------
echo --- Disable active prompting (pings to MSFT NCSI server)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Opt out from Windows privacy consent-----------
:: ----------------------------------------------------------
echo --- Opt out from Windows privacy consent
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable Windows feedback-----------------
:: ----------------------------------------------------------
echo --- Disable Windows feedback
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable text and handwriting collection----------
:: ----------------------------------------------------------
echo --- Disable text and handwriting collection
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Turn off sensors---------------------
:: ----------------------------------------------------------
echo --- Turn off sensors
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable Wi-Fi sense--------------------
:: ----------------------------------------------------------
echo --- Disable Wi-Fi sense
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable App Launch Tracking----------------
:: ----------------------------------------------------------
echo --- Disable App Launch Tracking
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /d 0 /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Inventory Collector----------------
:: ----------------------------------------------------------
echo --- Disable Inventory Collector
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Website Access of Language List----------
:: ----------------------------------------------------------
echo --- Disable Website Access of Language List
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Auto Downloading Maps---------------
:: ----------------------------------------------------------
echo --- Disable Auto Downloading Maps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable steps recorder------------------
:: ----------------------------------------------------------
echo --- Disable steps recorder
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable game screen recording---------------
:: ----------------------------------------------------------
echo --- Disable game screen recording
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Windows DRM internet access------------
:: ----------------------------------------------------------
echo --- Disable Windows DRM internet access
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable feedback on write (sending typing info)------
:: ----------------------------------------------------------
echo --- Disable feedback on write (sending typing info)
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable Activity Feed-------------------
:: ----------------------------------------------------------
echo --- Disable Activity Feed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Windows Insider Program--------------
:: ----------------------------------------------------------
echo --- Disable Windows Insider Program
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t "REG_DWORD" /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t "REG_DWORD" /d "1" /f
sc stop "wisvc" & sc config "wisvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable visual studio telemetry--------------
:: ----------------------------------------------------------
echo --- Disable visual studio telemetry
reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v TurnOffSwitch /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Visual Studio feedback--------------
:: ----------------------------------------------------------
echo --- Disable Visual Studio feedback
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableFeedbackDialog /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableEmailInput /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableScreenshotCapture /t REG_DWORD /d 1 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Stop and disable Visual Studio Standard Collector Service-
:: ----------------------------------------------------------
echo --- Stop and disable Visual Studio Standard Collector Service
sc stop "VSStandardCollectorService150" 
net stop VSStandardCollectorService150 2>nul
sc config "VSStandardCollectorService150" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Disable SQM OS key--------------------
:: ----------------------------------------------------------
echo --- Disable SQM OS key
if %PROCESSOR_ARCHITECTURE%==x86 ( REM is 32 bit?
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
) else (
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable SQM group policy-----------------
:: ----------------------------------------------------------
echo --- Disable SQM group policy
reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Do not send Watson events-----------------
:: ----------------------------------------------------------
echo --- Do not send Watson events
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericReports" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable Malicious Software Reporting tool diagnostic data-
:: ----------------------------------------------------------
echo --- Disable Malicious Software Reporting tool diagnostic data
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable local setting override for reporting to Microsoft MAPS
echo --- Disable local setting override for reporting to Microsoft MAPS
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn off Windows Defender SpyNet reporting--------
:: ----------------------------------------------------------
echo --- Turn off Windows Defender SpyNet reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Do not send file samples for further analysis-------
:: ----------------------------------------------------------
echo --- Do not send file samples for further analysis
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Uninstall NVIDIA telemetry tasks-------------
:: ----------------------------------------------------------
echo --- Uninstall NVIDIA telemetry tasks
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Delete NVIDIA residual telemetry files----------
:: ----------------------------------------------------------
echo --- Delete NVIDIA residual telemetry files
del /s %systemdrive%\System32\DriverStore\FileRepository\NvTelemetry*.dll
rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2>nul
rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Opt out from NVIDIA telemetry---------------
:: ----------------------------------------------------------
echo --- Opt out from NVIDIA telemetry
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" /v "Start" /t REG_DWORD /d 4 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable NVIDIA telemetry services-------------
:: ----------------------------------------------------------
echo --- Disable NVIDIA telemetry services
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Visual Studio Code telemetry-----------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code telemetry
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableTelemetry' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Visual Studio Code crash reporting--------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code crash reporting
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableCrashReporter' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Do not run Microsoft online experiments----------
:: ----------------------------------------------------------
echo --- Do not run Microsoft online experiments
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'workbench.enableExperiments' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Choose manual updates over automatic updates-------
:: ----------------------------------------------------------
echo --- Choose manual updates over automatic updates
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.mode' -Value \"manual\" -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: Show Release Notes from Microsoft online service after an update
echo --- Show Release Notes from Microsoft online service after an update
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.showReleaseNotes' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: Automatically check extensions from Microsoft online service
echo --- Automatically check extensions from Microsoft online service
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.autoCheckUpdates' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Fetch recommendations from a Microsoft online service---
:: ----------------------------------------------------------
echo --- Fetch recommendations from a Microsoft online service
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.showRecommendationsOnlyOnDemand' -Value $true -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Automatically fetch git commits from remote repository--
:: ----------------------------------------------------------
echo --- Automatically fetch git commits from remote repository
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'git.autofetch' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Fetch package information from NPM and Bower-------
:: ----------------------------------------------------------
echo --- Fetch package information from NPM and Bower
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'npm.fetchOnlinePackageInfo' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Microsoft Office logging-------------
:: ----------------------------------------------------------
echo --- Disable Microsoft Office logging
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable client telemetry-----------------
:: ----------------------------------------------------------
echo --- Disable client telemetry
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Customer Experience Improvement Program----------
:: ----------------------------------------------------------
echo --- Customer Experience Improvement Program
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable feedback---------------------
:: ----------------------------------------------------------
echo --- Disable feedback
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable telemetry agent------------------
:: ----------------------------------------------------------
echo --- Disable telemetry agent
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Subscription Heartbeat--------------
:: ----------------------------------------------------------
echo --- Disable Subscription Heartbeat
schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Do not send Windows Media Player statistics--------
:: ----------------------------------------------------------
echo --- Do not send Windows Media Player statistics
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable meta data retrieval----------------
:: ----------------------------------------------------------
echo --- Disable meta data retrieval
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable dows Media Player Network Sharing Service-----
:: ----------------------------------------------------------
echo --- Disable dows Media Player Network Sharing Service
sc stop "WMPNetworkSvc" & sc config "WMPNetworkSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable NET Core CLI telemetry--------------
:: ----------------------------------------------------------
echo --- Disable NET Core CLI telemetry
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable PowerShell 7+ telemetry--------------
:: ----------------------------------------------------------
echo --- Disable PowerShell 7+ telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Spectre variant 2 and meltdown (own OS)----------
:: ----------------------------------------------------------
echo --- Spectre variant 2 and meltdown (own OS)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
wmic cpu get name | findstr "Intel" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 0 /f
)
wmic cpu get name | findstr "AMD" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 64 /f
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Spectre variant 2 and meltdown (HyperV)----------
:: ----------------------------------------------------------
echo --- Spectre variant 2 and meltdown (HyperV)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable unsafe SMBv1 protocol---------------
:: ----------------------------------------------------------
echo --- Disable unsafe SMBv1 protocol
dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Client" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Server" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable PowerShell 2.0 against downgrade attacks-----
:: ----------------------------------------------------------
echo --- Disable PowerShell 2.0 against downgrade attacks
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /NoRestart
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Force enable data execution prevention (DEP)-------
:: ----------------------------------------------------------
echo --- Force enable data execution prevention (DEP)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable AutoPlay and AutoRun---------------
:: ----------------------------------------------------------
echo --- Disable AutoPlay and AutoRun
:: 255 (0xff) means all drives
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable remote Assistance-----------------
:: ----------------------------------------------------------
echo --- Disable remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable lock screen camera----------------
:: ----------------------------------------------------------
echo --- Disable lock screen camera
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Prevent the storage of the LAN Manager hash of passwords-
:: ----------------------------------------------------------
echo --- Prevent the storage of the LAN Manager hash of passwords
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable Windows Installer Always install with elevated privileges
echo --- Disable Windows Installer Always install with elevated privileges
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Prevent WinRM from using Basic Authentication-------
:: ----------------------------------------------------------
echo --- Prevent WinRM from using Basic Authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowBasic" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Restrict anonymous enumeration of shares---------
:: ----------------------------------------------------------
echo --- Restrict anonymous enumeration of shares
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Refuse less secure authentication-------------
:: ----------------------------------------------------------
echo --- Refuse less secure authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f
:: ----------------------------------------------------------


:: Enable Structured Exception Handling Overwrite Protection (SEHOP)
echo --- Enable Structured Exception Handling Overwrite Protection (SEHOP)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Block Anonymous enumeration of SAM accounts--------
:: ----------------------------------------------------------
echo --- Block Anonymous enumeration of SAM accounts
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Restrict anonymous access to Named Pipes and Shares----
:: ----------------------------------------------------------
echo --- Restrict anonymous access to Named Pipes and Shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable the Windows Connect Now wizard----------
:: ----------------------------------------------------------
echo --- Disable the Windows Connect Now wizard
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\UI" /v "DisableWcnUi" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableFlashConfigRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableInBand802DOT11Registrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableUPnPRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableWPDRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "EnableRegistrars" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Do not keep history of recently opened documents-----
:: ----------------------------------------------------------
echo --- Do not keep history of recently opened documents
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Clear history of recently opened documents on exit----
:: ----------------------------------------------------------
echo --- Clear history of recently opened documents on exit
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable online tips--------------------
:: ----------------------------------------------------------
echo --- Disable online tips
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn off Internet File Association service--------
:: ----------------------------------------------------------
echo --- Turn off Internet File Association service
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Turn off the "Order Prints" picture task---------
:: ----------------------------------------------------------
echo --- Turn off the "Order Prints" picture task
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable the file and folder Publish to Web option-----
:: ----------------------------------------------------------
echo --- Disable the file and folder Publish to Web option
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Prevent downloading a list of providers for wizards----
:: ----------------------------------------------------------
echo --- Prevent downloading a list of providers for wizards
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------3D Objects------------------------
:: ----------------------------------------------------------
echo --- 3D Objects
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable lock screen app notifications-----------
:: ----------------------------------------------------------
echo --- Disable lock screen app notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Live Tiles push notifications-----------
:: ----------------------------------------------------------
echo --- Disable Live Tiles push notifications
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Turn off "Look For An App In The Store" option------
:: ----------------------------------------------------------
echo --- Turn off "Look For An App In The Store" option
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Sync Provider Notifications------------
:: ----------------------------------------------------------
echo --- Disable Sync Provider Notifications
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /d 0 /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Xbox Live Auth Manager------------------
:: ----------------------------------------------------------
echo --- Xbox Live Auth Manager
sc stop "XblAuthManager" & sc config "XblAuthManager" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Xbox Live Game Save--------------------
:: ----------------------------------------------------------
echo --- Xbox Live Game Save
sc stop "XblGameSave" & sc config "XblGameSave" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Xbox Live Networking Service---------------
:: ----------------------------------------------------------
echo --- Xbox Live Networking Service
sc stop "XboxNetApiSvc" & sc config "XboxNetApiSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Delivery Optimization (P2P Windows Updates)--------
:: ----------------------------------------------------------
echo --- Delivery Optimization (P2P Windows Updates)
sc stop "DoSvc" & sc config "DoSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Microsoft Windows Live ID Service-------------
:: ----------------------------------------------------------
echo --- Microsoft Windows Live ID Service
sc stop "wlidsvc" & sc config "wlidsvc" start=demand
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Program Compatibility Assistant Service----------
:: ----------------------------------------------------------
echo --- Program Compatibility Assistant Service
sc stop "PcaSvc" & sc config "PcaSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Downloaded Maps Manager------------------
:: ----------------------------------------------------------
echo --- Downloaded Maps Manager
sc stop "MapsBroker" & sc config "MapsBroker" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Microsoft Retail Demo experience-------------
:: ----------------------------------------------------------
echo --- Microsoft Retail Demo experience
sc stop "RetailDemo" & sc config "RetailDemo" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Mail, contact, calendar and user data synchronization.--
:: ----------------------------------------------------------
echo --- Mail, contact, calendar and user data synchronization.
sc stop "OneSyncSvc" & sc config "OneSyncSvc" start=disabled
sc stop "UnistoreSvc" & sc config "UnistoreSvc" start=disabled
reg add HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc /V Start /t REG_DWORD /d "0x4" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Contact data indexing-------------------
:: ----------------------------------------------------------
echo --- Contact data indexing
sc stop "PimIndexMaintenanceSvc" & sc config "PimIndexMaintenanceSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------App user data access-------------------
:: ----------------------------------------------------------
echo --- App user data access
sc stop "UserDataSvc" & sc config "UserDataSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Text messaging----------------------
:: ----------------------------------------------------------
echo --- Text messaging
sc stop "MessagingService" & sc config "MessagingService" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------App Connector app---------------------
:: ----------------------------------------------------------
echo --- App Connector app
PowerShell -Command "Get-AppxPackage "Microsoft.Appconnector" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Microsoft 3D Builder-------------------
:: ----------------------------------------------------------
echo --- Microsoft 3D Builder
PowerShell -Command "Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------App Installer app---------------------
:: ----------------------------------------------------------
echo --- App Installer app
PowerShell -Command "Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Get Help app-----------------------
:: ----------------------------------------------------------
echo --- Get Help app
PowerShell -Command "Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Microsoft Tips app--------------------
:: ----------------------------------------------------------
echo --- Microsoft Tips app
PowerShell -Command "Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Microsoft Messaging app------------------
:: ----------------------------------------------------------
echo --- Microsoft Messaging app
PowerShell -Command "Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Feedback Hub app---------------------
:: ----------------------------------------------------------
echo --- Feedback Hub app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Windows Alarms and Clock app---------------
:: ----------------------------------------------------------
echo --- Windows Alarms and Clock app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Windows Camera app--------------------
:: ----------------------------------------------------------
echo --- Windows Camera app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Paint 3D app-----------------------
:: ----------------------------------------------------------
echo --- Paint 3D app
PowerShell -Command "Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Windows Maps app---------------------
:: ----------------------------------------------------------
echo --- Windows Maps app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Minecraft app-----------------------
:: ----------------------------------------------------------
echo --- Minecraft app
PowerShell -Command "Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Microsoft People app-------------------
:: ----------------------------------------------------------
echo --- Microsoft People app
PowerShell -Command "Get-AppxPackage "Microsoft.People" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Microsoft Pay app---------------------
:: ----------------------------------------------------------
echo --- Microsoft Pay app
PowerShell -Command "Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Store Purchase app--------------------
:: ----------------------------------------------------------
echo --- Store Purchase app
PowerShell -Command "Get-AppxPackage "Microsoft.StorePurchaseApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Snip and Sketch app--------------------
:: ----------------------------------------------------------
echo --- Snip and Sketch app
PowerShell -Command "Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Print3D app------------------------
:: ----------------------------------------------------------
echo --- Print3D app
PowerShell -Command "Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Paid Wi-Fi and Cellular app----------------
:: ----------------------------------------------------------
echo --- Paid Wi-Fi and Cellular app
PowerShell -Command "Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Microsoft Solitaire Collection app------------
:: ----------------------------------------------------------
echo --- Microsoft Solitaire Collection app
PowerShell -Command "Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Microsoft Sticky Notes app----------------
:: ----------------------------------------------------------
echo --- Microsoft Sticky Notes app
PowerShell -Command "Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Windows Calculator app------------------
:: ----------------------------------------------------------
echo --- Windows Calculator app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsCalculator" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Microsoft Photos app-------------------
:: ----------------------------------------------------------
echo --- Microsoft Photos app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Skype app-------------------------
:: ----------------------------------------------------------
echo --- Skype app
PowerShell -Command "Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Windows Voice Recorder app----------------
:: ----------------------------------------------------------
echo --- Windows Voice Recorder app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------MSN Weather app----------------------
:: ----------------------------------------------------------
echo --- MSN Weather app
PowerShell -Command "Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------MSN Sports app----------------------
:: ----------------------------------------------------------
echo --- MSN Sports app
PowerShell -Command "Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------MSN News app-----------------------
:: ----------------------------------------------------------
echo --- MSN News app
PowerShell -Command "Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------MSN Money app-----------------------
:: ----------------------------------------------------------
echo --- MSN Money app
PowerShell -Command "Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------HEIF Image Extensions app-----------------
:: ----------------------------------------------------------
echo --- HEIF Image Extensions app
PowerShell -Command "Get-AppxPackage "Microsoft.HEIFImageExtension" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------VP9 Video Extensions app-----------------
:: ----------------------------------------------------------
echo --- VP9 Video Extensions app
PowerShell -Command "Get-AppxPackage "Microsoft.VP9VideoExtensions" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Web Media Extensions app-----------------
:: ----------------------------------------------------------
echo --- Web Media Extensions app
PowerShell -Command "Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Webp Image Extension app-----------------
:: ----------------------------------------------------------
echo --- Webp Image Extension app
PowerShell -Command "Get-AppxPackage "Microsoft.WebpImageExtension" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------My Office app-----------------------
:: ----------------------------------------------------------
echo --- My Office app
PowerShell -Command "Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------OneNote app------------------------
:: ----------------------------------------------------------
echo --- OneNote app
PowerShell -Command "Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------------Sway app-------------------------
:: ----------------------------------------------------------
echo --- Sway app
PowerShell -Command "Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------------Xbox app-------------------------
:: ----------------------------------------------------------
echo --- Xbox app
PowerShell -Command "Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Xbox TCUI app-----------------------
:: ----------------------------------------------------------
echo --- Xbox TCUI app
PowerShell -Command "Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Xbox Game Bar app---------------------
:: ----------------------------------------------------------
echo --- Xbox Game Bar app
PowerShell -Command "Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Xbox Gaming Overlay app------------------
:: ----------------------------------------------------------
echo --- Xbox Gaming Overlay app
PowerShell -Command "Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Xbox Identity Provider app----------------
:: ----------------------------------------------------------
echo --- Xbox Identity Provider app
PowerShell -Command "Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Xbox Speech To Text Overlay app--------------
:: ----------------------------------------------------------
echo --- Xbox Speech To Text Overlay app
PowerShell -Command "Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Zune Music app----------------------
:: ----------------------------------------------------------
echo --- Zune Music app
PowerShell -Command "Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Zune Video app----------------------
:: ----------------------------------------------------------
echo --- Zune Video app
PowerShell -Command "Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Windows Phone app---------------------
:: ----------------------------------------------------------
echo --- Windows Phone app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.Phone" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Comms Phone app----------------------
:: ----------------------------------------------------------
echo --- Comms Phone app
PowerShell -Command "Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Your Phone app----------------------
:: ----------------------------------------------------------
echo --- Your Phone app
PowerShell -Command "Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Microsoft Advertising app-----------------
:: ----------------------------------------------------------
echo --- Microsoft Advertising app
PowerShell -Command "Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Remote Desktop app--------------------
:: ----------------------------------------------------------
echo --- Remote Desktop app
PowerShell -Command "Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Network Speed Test app------------------
:: ----------------------------------------------------------
echo --- Network Speed Test app
PowerShell -Command "Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Shazam app------------------------
:: ----------------------------------------------------------
echo --- Shazam app
PowerShell -Command "Get-AppxPackage "ShazamEntertainmentLtd.Shazam" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Candy Crush Saga app-------------------
:: ----------------------------------------------------------
echo --- Candy Crush Saga app
PowerShell -Command "Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Flipboard app-----------------------
:: ----------------------------------------------------------
echo --- Flipboard app
PowerShell -Command "Get-AppxPackage "Flipboard.Flipboard" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Twitter app------------------------
:: ----------------------------------------------------------
echo --- Twitter app
PowerShell -Command "Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------iHeartRadio app----------------------
:: ----------------------------------------------------------
echo --- iHeartRadio app
PowerShell -Command "Get-AppxPackage "ClearChannelRadioDigital.iHeartRadio" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Duolingo app-----------------------
:: ----------------------------------------------------------
echo --- Duolingo app
PowerShell -Command "Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Photoshop Express app-------------------
:: ----------------------------------------------------------
echo --- Photoshop Express app
PowerShell -Command "Get-AppxPackage "AdobeSystemIncorporated.AdobePhotoshop" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Pandora app------------------------
:: ----------------------------------------------------------
echo --- Pandora app
PowerShell -Command "Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Eclipse Manager app--------------------
:: ----------------------------------------------------------
echo --- Eclipse Manager app
PowerShell -Command "Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Code Writer app----------------------
:: ----------------------------------------------------------
echo --- Code Writer app
PowerShell -Command "Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------File Picker app----------------------
:: ----------------------------------------------------------
echo --- File Picker app
PowerShell -Command "Get-AppxPackage "1527c705-839a-4832-9118-54d4Bd6a0c89" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------File Explorer app---------------------
:: ----------------------------------------------------------
echo --- File Explorer app
PowerShell -Command "Get-AppxPackage "c5e2524a-ea46-4f67-841f-6a9465d9d515" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------App Resolver UX app--------------------
:: ----------------------------------------------------------
echo --- App Resolver UX app
PowerShell -Command "Get-AppxPackage "E2A4F912-2574-4A75-9BB0-0D023378592B" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Add Suggested Folders To Library app-----------
:: ----------------------------------------------------------
echo --- Add Suggested Folders To Library app
PowerShell -Command "Get-AppxPackage "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE" | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage "InputApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Microsoft AAD Broker Plugin app--------------
:: ----------------------------------------------------------
echo --- Microsoft AAD Broker Plugin app
PowerShell -Command "Get-AppxPackage "Microsoft.AAD.Broker.Plugin" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Microsoft Accounts Control app--------------
:: ----------------------------------------------------------
echo --- Microsoft Accounts Control app
PowerShell -Command "Get-AppxPackage "Microsoft.AccountsControl" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Microsoft Async Text Service app-------------
:: ----------------------------------------------------------
echo --- Microsoft Async Text Service app
PowerShell -Command "Get-AppxPackage "Microsoft.AsyncTextService" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Start app-------------------------
:: ----------------------------------------------------------
echo --- Start app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.ShellExperienceHost" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Contact Support app--------------------
:: ----------------------------------------------------------
echo --- Contact Support app
PowerShell -Command "Get-AppxPackage "Windows.ContactSupport" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Settings app-----------------------
:: ----------------------------------------------------------
echo --- Settings app
PowerShell -Command "Get-AppxPackage "Windows.immersivecontrolpanel" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Windows Print 3D app-------------------
:: ----------------------------------------------------------
echo --- Windows Print 3D app
PowerShell -Command "Get-AppxPackage "Windows.Print3D" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Print UI app-----------------------
:: ----------------------------------------------------------
echo --- Print UI app
PowerShell -Command "Get-AppxPackage "Windows.PrintDialog" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Bio enrollment app--------------------
:: ----------------------------------------------------------
echo --- Bio enrollment app
PowerShell -Command "Get-AppxPackage "Microsoft.BioEnrollment" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Cred Dialog Host app-------------------
:: ----------------------------------------------------------
echo --- Cred Dialog Host app
PowerShell -Command "Get-AppxPackage "Microsoft.CredDialogHost" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------------EC App--------------------------
:: ----------------------------------------------------------
echo --- EC App
PowerShell -Command "Get-AppxPackage "Microsoft.ECApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------------Lock App-------------------------
:: ----------------------------------------------------------
echo --- Lock App
PowerShell -Command "Get-AppxPackage "Microsoft.LockApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Microsoft Edge app--------------------
:: ----------------------------------------------------------
echo --- Microsoft Edge app
PowerShell -Command "Get-AppxPackage "Microsoft.MicrosoftEdge" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Microsoft Edge Dev Tools Client app------------
:: ----------------------------------------------------------
echo --- Microsoft Edge Dev Tools Client app
PowerShell -Command "Get-AppxPackage "Microsoft.MicrosoftEdgeDevToolsClient" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Microsoft PPI Projection app---------------
:: ----------------------------------------------------------
echo --- Microsoft PPI Projection app
PowerShell -Command "Get-AppxPackage "Microsoft.PPIProjection" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Win32 Web View Host app------------------
:: ----------------------------------------------------------
echo --- Win32 Web View Host app
PowerShell -Command "Get-AppxPackage "Microsoft.Win32WebViewHost" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------ChxApp app------------------------
:: ----------------------------------------------------------
echo --- ChxApp app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.Apprep.ChxApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Assigned Access Lock App app---------------
:: ----------------------------------------------------------
echo --- Assigned Access Lock App app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.AssignedAccessLockApp" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Capture Picker app--------------------
:: ----------------------------------------------------------
echo --- Capture Picker app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.CapturePicker" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Cloud Experience Host app-----------------
:: ----------------------------------------------------------
echo --- Cloud Experience Host app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.CloudExperienceHost" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Content Delivery Manager app---------------
:: ----------------------------------------------------------
echo --- Content Delivery Manager app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.ContentDeliveryManager" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Cortana app------------------------
:: ----------------------------------------------------------
echo --- Cortana app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.Cortana" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Holographic First Run app-----------------
:: ----------------------------------------------------------
echo --- Holographic First Run app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.Holographic.FirstRun" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------OOBE Network Captive Port app---------------
:: ----------------------------------------------------------
echo --- OOBE Network Captive Port app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.OOBENetworkCaptivePort" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------OOBE Network Connection Flow app-------------
:: ----------------------------------------------------------
echo --- OOBE Network Connection Flow app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.OOBENetworkConnectionFlow" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Parental Controls app-------------------
:: ----------------------------------------------------------
echo --- Parental Controls app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.ParentalControls" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------People Experience Host app----------------
:: ----------------------------------------------------------
echo --- People Experience Host app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.PeopleExperienceHost" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Pinning Confirmation Dialog app--------------
:: ----------------------------------------------------------
echo --- Pinning Confirmation Dialog app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.PinningConfirmationDialog" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Sec Health UI app---------------------
:: ----------------------------------------------------------
echo --- Sec Health UI app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.SecHealthUI" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Secondary Tile Experience app---------------
:: ----------------------------------------------------------
echo --- Secondary Tile Experience app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.SecondaryTileExperience" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Secure Assessment Browser app---------------
:: ----------------------------------------------------------
echo --- Secure Assessment Browser app
PowerShell -Command "Get-AppxPackage "Microsoft.Windows.SecureAssessmentBrowser" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Windows Feedback app-------------------
:: ----------------------------------------------------------
echo --- Windows Feedback app
PowerShell -Command "Get-AppxPackage "Microsoft.WindowsFeedback" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Xbox Game Callable UI app-----------------
:: ----------------------------------------------------------
echo --- Xbox Game Callable UI app
PowerShell -Command "Get-AppxPackage "Microsoft.XboxGameCallableUI" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------CBS Preview app----------------------
:: ----------------------------------------------------------
echo --- CBS Preview app
PowerShell -Command "Get-AppxPackage "Windows.CBSPreview" | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Kill OneDrive process-------------------
:: ----------------------------------------------------------
echo --- Kill OneDrive process
taskkill /f /im OneDrive.exe
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Uninstall OneDrive--------------------
:: ----------------------------------------------------------
echo --- Uninstall OneDrive
if %PROCESSOR_ARCHITECTURE%==x86 (
    %SystemRoot%\System32\OneDriveSetup.exe /uninstall 2>null
) else (
    %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall 2>null
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Remove OneDrive leftovers-----------------
:: ----------------------------------------------------------
echo --- Remove OneDrive leftovers
rd "%UserProfile%\OneDrive" /q /s
rd "%LocalAppData%\Microsoft\OneDrive" /q /s
rd "%ProgramData%\Microsoft OneDrive" /q /s
rd "%SystemDrive%\OneDriveTemp" /q /s
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Delete OneDrive shortcuts-----------------
:: ----------------------------------------------------------
echo --- Delete OneDrive shortcuts
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /s /f /q
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
del "%USERPROFILE%\Links\OneDrive.lnk" /s /f /q
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable usage of OneDrive-----------------
:: ----------------------------------------------------------
echo --- Disable usage of OneDrive
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSyncNGSC" /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSync" /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Prevent automatic OneDrive install for current user----
:: ----------------------------------------------------------
echo --- Prevent automatic OneDrive install for current user
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Prevent automatic OneDrive install for new users-----
:: ----------------------------------------------------------
echo --- Prevent automatic OneDrive install for new users
reg load "HKU\Default" "%SystemDrive%\Users\Default\NTUSER.DAT" 
reg delete "HKU\Default\software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "HKU\Default"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Remove OneDrive from explorer menu------------
:: ----------------------------------------------------------
echo --- Remove OneDrive from explorer menu
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
reg add "HKCR\Wow6432Node\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Delete all OneDrive related Services-----------
:: ----------------------------------------------------------
echo --- Delete all OneDrive related Services
for /f "tokens=1 delims=," %%x in ('schtasks /query /fo csv ^| find "OneDrive"') do schtasks /Delete /TN %%x /F
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Delete OneDrive path from registry------------
:: ----------------------------------------------------------
echo --- Delete OneDrive path from registry
reg delete "HKCU\Environment" /v "OneDrive" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Telnet Client feature-------------------
:: ----------------------------------------------------------
echo --- Telnet Client feature
dism /Online /Disable-Feature /FeatureName:"TelnetClient" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Net.TCP Port Sharing feature---------------
:: ----------------------------------------------------------
echo --- Net.TCP Port Sharing feature
dism /Online /Disable-Feature /FeatureName:"WCF-TCP-PortSharing45" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------SMB Direct feature--------------------
:: ----------------------------------------------------------
echo --- SMB Direct feature
dism /Online /Disable-Feature /FeatureName:"SmbDirect" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------TFTP Client feature--------------------
:: ----------------------------------------------------------
echo --- TFTP Client feature
dism /Online /Disable-Feature /FeatureName:"TFTP" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Hyper-V feature----------------------
:: ----------------------------------------------------------
echo --- Hyper-V feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-All" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Hyper-V GUI Management Tools feature-----------
:: ----------------------------------------------------------
echo --- Hyper-V GUI Management Tools feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-Clients" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Hyper-V Management Tools feature-------------
:: ----------------------------------------------------------
echo --- Hyper-V Management Tools feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Tools-All" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Hyper-V Module for Windows PowerShell feature-------
:: ----------------------------------------------------------
echo --- Hyper-V Module for Windows PowerShell feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-PowerShell" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------XPS Services feature-------------------
:: ----------------------------------------------------------
echo --- XPS Services feature
dism /Online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------XPS Viewer feature--------------------
:: ----------------------------------------------------------
echo --- XPS Viewer feature
dism /Online /Disable-Feature /FeatureName:"Xps-Foundation-Xps-Viewer" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Work Folders Client feature----------------
:: ----------------------------------------------------------
echo --- Work Folders Client feature
dism /Online /Disable-Feature /FeatureName:"WorkFolders-Client" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Internet Explorer feature-----------------
:: ----------------------------------------------------------
echo --- Internet Explorer feature
dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-x64" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-x84" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-amd64" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Legacy Components feature-----------------
:: ----------------------------------------------------------
echo --- Legacy Components feature
dism /Online /Disable-Feature /FeatureName:"LegacyComponents" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Media Features feature------------------
:: ----------------------------------------------------------
echo --- Media Features feature
dism /Online /Disable-Feature /FeatureName:"MediaPlayback" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Windows Fax and Scan feature---------------
:: ----------------------------------------------------------
echo --- Windows Fax and Scan feature
dism /Online /Disable-Feature /FeatureName:"FaxServicesClientPackage" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Windows Media Player feature---------------
:: ----------------------------------------------------------
echo --- Windows Media Player feature
dism /Online /Disable-Feature /FeatureName:"WindowsMediaPlayer" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Windows Search feature------------------
:: ----------------------------------------------------------
echo --- Windows Search feature
dism /Online /Disable-Feature /FeatureName:"SearchEngine-Client-Package" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Internet Explorer 11 capability--------------
:: ----------------------------------------------------------
echo --- Internet Explorer 11 capability
Powershell -Command "Get-WindowsCapability -Online -Name "Browser.InternetExplorer*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Math Recognizer capability----------------
:: ----------------------------------------------------------
echo --- Math Recognizer capability
Powershell -Command "Get-WindowsCapability -Online -Name "MathRecognizer*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --OneSync capability (breaks Mail, People, and Calendar)--
:: ----------------------------------------------------------
echo --- OneSync capability (breaks Mail, People, and Calendar)
Powershell -Command "Get-WindowsCapability -Online -Name "OneCoreUAP.OneSync*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Quick Assist capability------------------
:: ----------------------------------------------------------
echo --- Quick Assist capability
Powershell -Command "Get-WindowsCapability -Online -Name "App.Support.QuickAssist*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Steps Recorder capability-----------------
:: ----------------------------------------------------------
echo --- Steps Recorder capability
Powershell -Command "Get-WindowsCapability -Online -Name "App.StepsRecorder*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Windows Fax and Scan capability--------------
:: ----------------------------------------------------------
echo --- Windows Fax and Scan capability
Powershell -Command "Get-WindowsCapability -Online -Name "Print.Fax.Scan*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Change NTP (time) server to pool.ntp.org---------
:: ----------------------------------------------------------
echo --- Change NTP (time) server to pool.ntp.org
:: Configure time source
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
:: Restart time service if running
SC queryex "w32time"|Find "STATE"|Find /v "RUNNING">Nul||(
    net stop w32time
    net start w32time
)
:: Sync now
w32tm /config /update
w32tm /resync
:: ----------------------------------------------------------


pause
exit /b 0