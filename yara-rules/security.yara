rule ServicingStackLoaded {
    meta:
        author = "Areeb Ahmed"
        description = "Detect when the Servicing Stack is loaded"

    strings:
        $loaded = "Loaded Servicing Stack"

    condition:
        $loaded
}

rule WcpInitialize {
    meta:
        author = "Areeb Ahmed"
        description = "Detect WcpInitialize calls"

    strings:
        $initialize = "WcpInitialize (wcp.dll version"
        $stack = "called (stack"

    condition:
        $initialize and $stack
}

rule TrustedInstallerEvents {
    meta:
        author = "Areeb Ahmed"
        description = "Detect TrustedInstaller events"

    strings:
        $init_end = "Ending TrustedInstaller initialization"
        $main_loop_start = "Starting the TrustedInstaller main loop"
        $service_start = "TrustedInstaller service starts successfully"

    condition:
        any of them
}

rule SQMEvents {
    meta:
        author = "Avantika Kesarwani"
        description = "Detect SQM events"

    strings:
        $sqm_init = "SQM: Initializing online"
        $sqm_cleanup = "SQM: Cleaning up report files"
        $sqm_upload_request = "SQM: Requesting upload"
        $sqm_failed_upload = "SQM: Failed to start upload"
        $sqm_queued_files = "SQM: Queued"

    condition:
        any of them
}

rule CBSLoaded {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS loaded events"

    strings:
        $loaded = "CBS Loaded"

    condition:
        $loaded
}

rule CBSStarting {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS starting events"

    strings:
        $starting = "CBS Starting"

    condition:
        $starting
}

rule CBSInitialization {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS initialization events"

    strings:
        $initialization = "CBS Initialization"

    condition:
        $initialization
}

rule CSIMetadata {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI metadata events"

    strings:
        $metadata = "CSI metadata"

    condition:
        $metadata
}

rule CSIWarning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI warnings"

    strings:
        $warning = "CSI warning"

    condition:
        $warning
}

rule CSIError {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI errors"

    strings:
        $error = "CSI error"

    condition:
        $error
}

rule CSICleanup {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI cleanup events"

    strings:
        $cleanup = "CSI cleanup"

    condition:
        $cleanup
}

rule CSIVersionInfo {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI version information"

    strings:
        $version_info = "CSI version"

    condition:
        $version_info
}

rule CBSShutdown {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS shutdown events"

    strings:
        $shutdown = "CBS shutdown"

    condition:
        $shutdown
}

rule CBSUnloading {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS unloading events"

    strings:
        $unloading = "CBS unloading"

    condition:
        $unloading
}

rule CBSReboot {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS reboot events"

    strings:
        $reboot = "CBS reboot"

    condition:
        $reboot
}

rule CBSRestart {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS restart events"

    strings:
        $restart = "CBS restart"

    condition:
        $restart
}

rule CBSFailure {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS failure events"

    strings:
        $failure = "CBS failure"

    condition:
        $failure
}

rule CBSLogError {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log errors"

    strings:
        $log_error = "CBS log error"

    condition:
        $log_error
}

rule CBSLogWarning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log warnings"

    strings:
        $log_warning = "CBS log warning"

    condition:
        $log_warning
}

rule CBSLogInfo {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log information"

    strings:
        $log_info = "CBS log info"

    condition:
        $log_info
}

rule CBSLogVerbose {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log verbose messages"

    strings:
        $log_verbose = "CBS log verbose"

    condition:
        $log_verbose
}

rule CBSCommit {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS commit events"

    strings:
        $commit = "CBS commit"

    condition:
        $commit
}

rule CBSCancel {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS cancel events"

    strings:
        $cancel = "CBS cancel"

    condition:
        $cancel
}

rule CBSExecution {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS execution events"

    strings:
        $execution = "CBS execution"

    condition:
        $execution
}

rule CBSDependency {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS dependency events"

    strings:
        $dependency = "CBS dependency"

    condition:
        $dependency
}

rule CBSResolution {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS resolution events"

    strings:
        $resolution = "CBS resolution"

    condition:
        $resolution
}

rule CBSDeployment {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS deployment events"

    strings:
        $deployment = "CBS deployment"

    condition:
        $deployment
}

rule CBSInstallation {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS installation events"

    strings:
        $installation = "CBS installation"

    condition:
        $installation
}

rule CBSUpdate {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS update events"

    strings:
        $update = "CBS update"

    condition:
        $update
}

rule ThunderboltEvent {
    meta:
        author = "Areeb Ahmed"
        description = "Detect Thunderbolt events"

    strings:
        $thunderbolt = "Thunderbolt"
        $hpd_packet = "HPD packet"
        $unplug = "unplug"

    condition:
        $thunderbolt and $hpd_packet and $unplug
}

rule ThermalPressureState {
    meta:
        author = "Areeb Ahmed"
        description = "Detect thermal pressure state changes"

    strings:
        $thermal_pressure = "Thermal pressure state"

    condition:
        $thermal_pressure
}

rule MemoryPressureState {
    meta:
        author = "Areeb Ahmed"
        description = "Detect memory pressure state changes"

    strings:
        $memory_pressure = "Memory pressure state"

    condition:
        $memory_pressure
}

rule URLTaskDealloc {
    meta:
        author = "Areeb Ahmed"
        description = "Detect URL task deallocation events"

    strings:
        $url_task = "Url||taskID"
        $dealloc = "dealloc"

    condition:
        $url_task and $dealloc
}

rule AirPortSyncPowerState {
    meta:
        author = "Areeb Ahmed"
        description = "Detect AirPort sync power state changes"

    strings:
        $airport_sync = "AirPort_Brcm43xx::syncPowerState"
        $wwen_enabled = "WWEN[enabled]"

    condition:
        $airport_sync and $wwen_enabled
}

rule AirPortPlatformWoW {
    meta:
        author = "Areeb Ahmed"
        description = "Detect AirPort platform WoW enable/disable events"

    strings:
        $airport_platform = "AirPort_Brcm43xx::platformWoWEnable"
        $wwen_disable = "WWEN[disable]"

    condition:
        $airport_platform and $wwen_disable
}

rule FrequentTransitions {
    meta:
        author = "Areeb Ahmed"
        description = "Detect frequent interface transitions in mDNSResponder"

    strings:
        $frequent_transitions = "Frequent transitions for interface"

    condition:
        $frequent_transitions
}

rule SleepInformation {
    meta:
        author = "Areeb Ahmed"
        description = "Detect sleep-related power source information"

    strings:
        $sleep_info = "IOPMPowerSource Information: onSleep"
        $sleep_type = "SleepType: Normal Sleep"

    condition:
        $sleep_info and $sleep_type
}

rule TCPKeepAlive {
    meta:
        author = "Areeb Ahmed"
        description = "Detect TCP keep-alive sequence updates"

    strings:
        $tcp_keepalive = "wl_update_tcpkeep_seq: Original Seq"

    condition:
        $tcp_keepalive
}

rule WakeReason {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system wake reasons"

    strings:
        $wake_reason = "Wake Reason"

    condition:
        $wake_reason
}

rule NetworkAnalyticsSwitch {
    meta:
        author = "Areeb Ahmed"
        description = "Detect unexpected switch values in Network Analytics Engine"

    strings:
        $network_analytics = "NetworkAnalyticsEngine"
        $unexpected_switch = "unexpected switch value"

    condition:
        $network_analytics and $unexpected_switch
}

rule AWDLPeerManager {
    meta:
        author = "Areeb Ahmed"
        description = "Detect AWDL peer manager events"

    strings:
        $awdl_peer_manager = "IO80211AWDLPeerManager::setAwdlAutoMode"

    condition:
        $awdl_peer_manager
}

rule MDNSRecords {
    meta:
        author = "Areeb Ahmed"
        description = "Detect mDNS records"

    strings:
        $mdns_records = "MDNS: 0 SRV Recs, 0 TXT Recs"

    condition:
        $mdns_records
}

rule CameraWakeCall {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system wake calls for the camera"

    strings:
        $camera_wake = "AppleCamIn::systemWakeCall"
        $message_type = "messageType"

    condition:
        $camera_wake and $message_type
}

rule HostnameSetting {
    meta:
        author = "Areeb Ahmed"
        description = "Detect hostname setting events"

    strings:
        $hostname_setting = "setting hostname to"

    condition:
        $hostname_setting
}

rule KernelError {
    meta:
        author = "Areeb Ahmed"
        description = "Detect kernel errors"

    strings:
        $kernel_error = "kernel: error"

    condition:
        $kernel_error
}

rule KernelPanic {
    meta:
        author = "Areeb Ahmed"
        description = "Detect kernel panic events"

    strings:
        $kernel_panic = "kernel: panic"

    condition:
        $kernel_panic
}

rule SystemSleep {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system sleep events"

    strings:
        $system_sleep = "system sleep"

    condition:
        $system_sleep
}

rule SystemWake {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system wake events"

    strings:
        $system_wake = "system wake"

    condition:
        $system_wake
}

rule NetworkChange {
    meta:
        author = "Areeb Ahmed"
        description = "Detect network change events"

    strings:
        $network_change = "network change detected"

    condition:
        $network_change
}

rule PowerStateChange {
    meta:
        author = "Areeb Ahmed"
        description = "Detect power state change events"

    strings:
        $power_state_change = "power state change"

    condition:
        $power_state_change
}

rule ThermalStateChange {
    meta:
        author = "Areeb Ahmed"
        description = "Detect thermal state change events"

    strings:
        $thermal_state_change = "thermal state change"

    condition:
        $thermal_state_change
}

rule BatteryLevel {
    meta:
        author = "Areeb Ahmed"
        description = "Detect battery level events"

    strings:
        $battery_level = "battery level"

    condition:
        $battery_level
}

rule DiskUsage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect disk usage events"

    strings:
        $disk_usage = "disk usage"

    condition:
        $disk_usage
}

rule MemoryUsage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect memory usage events"

    strings:
        $memory_usage = "memory usage"

    condition:
        $memory_usage
}

rule ApplicationCrash {
    meta:
        author = "Areeb Ahmed"
        description = "Detect application crash events"

    strings:
        $app_crash = "application crash"

    condition:
        $app_crash
}

rule ServiceStart {
    meta:
        author = "Areeb Ahmed"
        description = "Detect service start events"

    strings:
        $service_start = "service start"

    condition:
        $service_start
}

rule SSHAuthFailure {
    meta:
        author = "Areeb Ahmed"
        description = "Detect SSH authentication failures"

    strings:
        $auth_failure = "authentication failure"
        $sshd = "sshd"

    condition:
        $auth_failure and $sshd
}

rule SSHUserUnknown {
    meta:
        author = "Areeb Ahmed"
        description = "Detect unknown user in SSH"

    strings:
        $check_pass = "check pass"
        $user_unknown = "user unknown"

    condition:
        $check_pass and $user_unknown
}

rule SSHRootAttempt {
    meta:
        author = "Areeb Ahmed"
        description = "Detect root login attempts via SSH"

    strings:
        $ssh_root = "user=root"
        $sshd = "sshd"

    condition:
        $ssh_root and $sshd
}

rule PAMSessionOpened {
    meta:
        author = "Areeb Ahmed"
        description = "Detect PAM session openings"

    strings:
        $pam_unix = "pam_unix"
        $session_opened = "session opened"

    condition:
        $pam_unix and $session_opened
}

rule PAMSessionClosed {
    meta:
        author = "Areeb Ahmed"
        description = "Detect PAM session closures"

    strings:
        $pam_unix = "pam_unix"
        $session_closed = "session closed"

    condition:
        $pam_unix and $session_closed
}

rule PAMAuthError {
    meta:
        author = "Areeb Ahmed"
        description = "Detect PAM authentication errors"

    strings:
        $pam_unix = "pam_unix"
        $auth_error = "authentication failure"

    condition:
        $pam_unix and $auth_error
}

rule KernelWarning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect kernel warnings"

    strings:
        $kernel_warning = "kernel: warning"

    condition:
        $kernel_warning
}

rule UserLogin {
    meta:
        author = "Areeb Ahmed"
        description = "Detect user login events"

    strings:
        $user_login = "session opened for user"

    condition:
        $user_login
}

rule UserLogout {
    meta:
        author = "Areeb Ahmed"
        description = "Detect user logout events"

    strings:
        $user_logout = "session closed for user"

    condition:
        $user_logout
}

rule SystemReboot {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system reboot events"

    strings:
        $system_reboot = "system reboot"

    condition:
        $system_reboot
}

rule SystemShutdown {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system shutdown events"

    strings:
        $system_shutdown = "system shutdown"

    condition:
        $system_shutdown
}

rule ServiceStop {
    meta:
        author = "Areeb Ahmed"
        description = "Detect service stop events"

    strings:
        $service_stop = "Stopping service"

    condition:
        $service_stop
}

rule DiskSpaceWarning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect disk space warnings"

    strings:
        $disk_space_warning = "disk space low"

    condition:
        $disk_space_warning
}

rule HighMemoryUsage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect high memory usage"

    strings:
        $high_memory_usage = "memory usage high"

    condition:
        $high_memory_usage
}

rule HighCPUUsage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect high CPU usage"

    strings:
        $high_cpu_usage = "CPU usage high"

    condition:
        $high_cpu_usage
}

rule NetworkIssue {
    meta:
        author = "Areeb Ahmed"
        description = "Detect network issues"

    strings:
        $network_issue = "network issue detected"

    condition:
        $network_issue
}

rule CronJobStart {
    meta:
        author = "Areeb Ahmed"
        description = "Detect cron job start events"

    strings:
        $cron_job_start = "Starting cron job"

    condition:
        $cron_job_start
}

rule CronJobEnd {
    meta:
        author = "Areeb Ahmed"
        description = "Detect cron job end events"

    strings:
        $cron_job_end = "Ending cron job"

    condition:
        $cron_job_end
}

rule FileSystemError {
    meta:
        author = "Areeb Ahmed"
        description = "Detect filesystem errors"

    strings:
        $filesystem_error = "filesystem error"

    condition:
        $filesystem_error
}

rule HardwareError {
    meta:
        author = "Areeb Ahmed"
        description = "Detect hardware errors"

    strings:
        $hardware_error = "hardware error"

    condition:
        $hardware_error
}

rule SoftwareUpdate {
    meta:
        author = "Areeb Ahmed"
        description = "Detect software update events"

    strings:
        $software_update = "software update"

    condition:
        $software_update
}

rule PackageInstallation {
    meta:
        author = "Areeb Ahmed"
        description = "Detect package installation events"

    strings:
        $package_installation = "installing package"

    condition:
        $package_installation
}

rule PackageRemoval {
    meta:
        author = "Areeb Ahmed"
        description = "Detect package removal events"

    strings:
        $package_removal = "removing package"

    condition:
        $package_removal
}

rule FirewallEvent {
    meta:
        author = "Areeb Ahmed"
        description = "Detect firewall events"

    strings:
        $firewall_event = "firewall event"

    condition:
        $firewall_event
}

rule SSHConnection {
    meta:
        author = "Areeb Ahmed"
        description = "Detect SSH connection events"

    strings:
        $ssh_connection = "sshd: connection from"

    condition:
        $ssh_connection
}

rule RootAccess {
    meta:
        author = "Areeb Ahmed"
        description = "Detect root access events"

    strings:
        $root_access = "root access granted"

    condition:
        $root_access
}

rule UnauthorizedAccess {
    meta:
        author = "Areeb Ahmed"
        description = "Detect unauthorized access attempts"

    strings:
        $unauthorized_access = "unauthorized access attempt"

    condition:
        $unauthorized_access
}

rule Detect_Window_Manager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to Window Manager activities across various logs"

    strings:
        $wm_issues = /WindowManager:\s*(error|fail|issue|problem)/i

    condition:
        $wm_issues
}

rule Detect_Lock_Acquisition_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to lock acquisition in different services"

    strings:
        $lock_issues = /acquire.*(lock|mutex|semaphore)/i

    condition:
        $lock_issues
}

rule Detect_App_Window_Token_Problems {
    meta:
        author = "Areeb Ahmed"
        description = "Detects problems related to AppWindowToken or similar entities"

    strings:
        $app_window_token = /AppWindowToken.*(hide|close|relaunch|issue|error)/i

    condition:
        $app_window_token
}

rule Detect_Visibility_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to visibility changes in UI components"

    strings:
        $visibility = /(visible|visibility).*(error|problem|issue|change)/i

    condition:
        $visibility
}

rule Detect_Wakefulness_Problems {
    meta:
        author = "Areeb Ahmed"
        description = "Detects problems related to wakefulness state in power management or other systems"

    strings:
        $wakefulness = /wakefulness.*(error|problem|issue|change)/i

    condition:
        $wakefulness
}

rule Detect_Battery_State_Changes {
    meta:
        author = "Areeb Ahmed"
        description = "Detects significant battery state changes or related issues"

    strings:
        $battery_state = /battery.*(state|level|error|issue|change)/i

    condition:
        $battery_state
}

rule Detect_Relaunching_Activities {
    meta:
        author = "Areeb Ahmed"
        description = "Detects relaunching activities in applications or services"

    strings:
        $relaunch = /(isRelaunching|restart|reinitialize|reboot).*(true|yes|failed|error)/i

    condition:
        $relaunch
}

rule Detect_Hide_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects events where components are hidden unexpectedly"

    strings:
        $hide_event = /(hide|disappear|vanish|close).*(error|problem|issue|unexpected)/i

    condition:
        $hide_event
}

rule Detect_Keyguard_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to Keyguard or similar security features"

    strings:
        $keyguard = /Keyguard.*(error|fail|issue|problem)/i

    condition:
        $keyguard
}

rule Detect_Network_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects network-related errors or issues"

    strings:
        $network_error = /Network.*(error|fail|disconnect|timeout|issue|problem)/i

    condition:
        $network_error
}

rule Detect_GPS_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects GPS-related issues or status updates"

    strings:
        $gps_issues = /(GPS|location).*(fail|issue|problem|error|update)/i

    condition:
        $gps_issues
}

rule Detect_Bluetooth_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues with Bluetooth connections or status"

    strings:
        $bluetooth = /Bluetooth.*(error|fail|issue|disconnect|problem)/i

    condition:
        $bluetooth
}

rule Detect_Media_Playback_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to media playback across various logs"

    strings:
        $media_playback = /Media.*(playback|start|pause|stop|fail|error|issue|problem)/i

    condition:
        $media_playback
}

rule Detect_App_Crash {
    meta:
        author = "Areeb Ahmed"
        description = "Detects application crash events in logs"

    strings:
        $app_crash = /Application.*(crash|fail|terminate|unexpected|exit|error)/i

    condition:
        $app_crash
}

rule Detect_System_UI_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects System UI errors or issues"

    strings:
        $system_ui = /SystemUI.*(error|crash|issue|problem)/i

    condition:
        $system_ui
}

rule Detect_Camera_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to CameraService or similar components"

    strings:
        $camera_service = /CameraService.*(error|fail|issue|problem)/i

    condition:
        $camera_service
}

rule Detect_Display_Orientation_Changes {
    meta:
        author = "Areeb Ahmed"
        description = "Detects display orientation changes or related issues"

    strings:
        $orientation_change = /display.*(orientation|rotate|angle).*(change|error|issue)/i

    condition:
        $orientation_change
}

rule Detect_Package_Installation_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects package installation events or issues"

    strings:
        $package_install = /(install|installation|package).*(error|fail|success|issue)/i

    condition:
        $package_install
}

rule Detect_Sensor_Service_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues or events related to sensor services"

    strings:
        $sensor_service = /Sensor.*(Service|error|issue|fail|problem)/i

    condition:
        $sensor_service
}

rule Detect_Wifi_Connection_Changes {
    meta:
        author = "Areeb Ahmed"
        description = "Detects Wi-Fi connection changes or issues"

    strings:
        $wifi_connection = /(WiFi|wireless|network).*(connect|disconnect|error|fail|issue)/i

    condition:
        $wifi_connection
}

rule Detect_Thermal_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to thermal services"

    strings:
        $thermal_service = /Thermal.*(Service|error|overheat|fail|issue|problem)/i

    condition:
        $thermal_service
}

rule Detect_Input_Method_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to input methods or services"

    strings:
        $input_method = /(InputMethod|keyboard|IME).*(error|fail|issue|problem)/i

    condition:
        $input_method
}

rule Detect_Job_Scheduler_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to job scheduling services"

    strings:
        $job_scheduler = /JobScheduler.*(error|fail|issue|problem)/i

    condition:
        $job_scheduler
}

rule Detect_Notification_Manager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to NotificationManagerService"

    strings:
        $notification_manager = /Notification.*(error|fail|issue|problem)/i

    condition:
        $notification_manager
}

rule Detect_Screen_Off_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects screen off events or issues in logs"

    strings:
        $screen_off = /(screen|display).*(off|shutdown|power down|sleep).*(error|issue|unexpected)/i

    condition:
        $screen_off
}

rule Detect_Vibrator_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to vibrator services"

    strings:
        $vibrator_service = /Vibrator.*(Service|error|fail|issue|problem)/i

    condition:
        $vibrator_service
}

rule Detect_Media_Scanner_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to MediaScannerService"

    strings:
        $media_scanner = /MediaScanner.*(Service|error|fail|issue|problem)/i

    condition:
        $media_scanner
}

rule Detect_Telephony_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to TelephonyService"

    strings:
        $telephony_service = /Telephony.*(Service|error|fail|issue|problem)/i

    condition:
        $telephony_service
}

rule Detect_App_Focus_Change {
    meta:
        author = "Areeb Ahmed"
        description = "Detects app focus change events or issues"

    strings:
        $app_focus_change = /app.*(focus|foreground|background).*(change|issue|error)/i

    condition:
        $app_focus_change
}

rule Detect_System_Update_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to system updates"

    strings:
        $system_update = /SystemUpdate.*(error|fail|issue|problem)/i

    condition:
        $system_update
}

rule Detect_SSH_Break_In_Attempt {
    meta:
        author = "Areeb Ahmed"
        description = "Detects potential break-in attempts in SSH logs"

    strings:
        $break_in_attempt = /POSSIBLE\s+BREAK-IN\s+ATTEMPT/i

    condition:
        $break_in_attempt
}

rule Detect_Invalid_User_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects invalid user attempts in SSH logs"

    strings:
        $invalid_user = /Invalid\s+user\s+\S+/i

    condition:
        $invalid_user
}

rule Detect_Failed_Authentication {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failed authentication attempts"

    strings:
        $failed_auth = /authentication\s+failure/i
        $failed_password = /Failed\s+password/i

    condition:
        $failed_auth or $failed_password
}

rule Detect_Reverse_Mapping_Failure {
    meta:
        author = "Areeb Ahmed"
        description = "Detects reverse mapping failures that may indicate DNS issues or security risks"

    strings:
        $reverse_mapping = /reverse\s+mapping\s+checking.*failed/i

    condition:
        $reverse_mapping
}

rule Detect_SSH_Connection_Closed {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH connection closure events"

    strings:
        $connection_closed = /Connection\s+closed\s+by\s+\S+/i

    condition:
        $connection_closed
}

rule Detect_PAM_Authentication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to PAM authentication in SSH"

    strings:
        $pam_auth = /pam_unix.*authentication\s+failure/i

    condition:
        $pam_auth
}

rule Detect_SSH_Protocol_Version {
    meta:
        author = "Areeb Ahmed"
        description = "Detects specific SSH protocol versions being used in connections"

    strings:
        $protocol_version = /ssh\d+/i

    condition:
        $protocol_version
}

rule Detect_Preauthentication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues occurring before authentication (preauth) in SSH logs"

    strings:
        $preauth_issue = /preauth/i

    condition:
        $preauth_issue
}

rule Detect_Port_Scanning_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects potential port scanning attempts by looking for multiple failed attempts from the same IP"

    strings:
        $failed_attempt = /Failed\s+password/i

    condition:
        $failed_attempt
}

rule Detect_SSH_Access_From_Known_Hosts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from known or specific IP addresses"

    strings:
        $known_ip = /from\s+(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))\.\d+\.\d+/i

    condition:
        $known_ip
}

rule Detect_Root_Login_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects root login attempts via SSH"

    strings:
        $root_login = /user\s+root/i

    condition:
        $root_login
}

rule Detect_Invalid_Credentials_Use {
    meta:
        author = "Areeb Ahmed"
        description = "Detects use of invalid or unauthorized credentials"

    strings:
        $invalid_credentials = /invalid\s+(password|user|credentials)/i

    condition:
        $invalid_credentials
}

rule Detect_Excessive_Login_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects multiple login attempts that may indicate a brute-force attack"

    strings:
        $login_attempt = /Failed\s+password/i

    condition:
        $login_attempt
}

rule Detect_SSH_Timeouts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH connection timeouts"

    strings:
        $timeout = /timeout/i

    condition:
        $timeout
}

rule Detect_Access_From_Blacklisted_IP {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from blacklisted or suspicious IP addresses"

    strings:
        $blacklisted_ip = /from\s+\b(\d{1,3}\.){3}\d{1,3}\b/i

    condition:
        $blacklisted_ip
}

rule Detect_Public_Key_Access {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts using public key authentication"

    strings:
        $public_key = /public\s+key/i

    condition:
        $public_key
}

rule Detect_Password_Access {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts using password authentication"

    strings:
        $password_auth = /password/i

    condition:
        $password_auth
}

rule Detect_Possible_SSH_Exploit {
    meta:
        author = "Areeb Ahmed"
        description = "Detects patterns that may indicate an SSH exploit attempt"

    strings:
        $exploit_pattern = /(exploit|vulnerability|shellshock|heartbleed)/i

    condition:
        $exploit_pattern
}

rule Detect_Botnet_Attack_Patterns {
    meta:
        author = "Areeb Ahmed"
        description = "Detects patterns that might indicate botnet attacks on SSH servers"

    strings:
        $botnet_pattern = /from\s+(\d{1,3}\.){3}\d{1,3}\s+ssh/i

    condition:
        $botnet_pattern
}

rule Detect_Suspicious_Activity_From_Unknown_Hosts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects suspicious activities originating from unknown or unusual hosts"

    strings:
        $unknown_host = /from\s+\S+\.\S+\s+ssh/i

    condition:
        $unknown_host
}

rule Detect_Large_Number_Of_Failed_Logins {
    meta:
        author = "Areeb Ahmed"
        description = "Detects a large number of failed login attempts from a single IP"

    strings:
        $failed_login = /Failed\s+password/i

    condition:
        $failed_login
}

rule Detect_Unexpected_SSH_Disconnections {
    meta:
        author = "Areeb Ahmed"
        description = "Detects unexpected SSH disconnections that may indicate an issue"

    strings:
        $unexpected_disconnect = /Connection\s+closed\s+by\s+\S+/i

    condition:
        $unexpected_disconnect
}

rule Detect_Failed_Public_Key_Authentication {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failed attempts at public key authentication"

    strings:
        $failed_key_auth = /Failed\s+publickey/i

    condition:
        $failed_key_auth
}

rule Detect_SSH_Access_From_Multiple_IPs {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from multiple IP addresses, which may indicate an attack"

    strings:
        $access_from_multiple_ips = /from\s+\b(\d{1,3}\.){3}\d{1,3}\b/i

    condition:
        $access_from_multiple_ips
}

rule Detect_Use_Of_Weak_Encryption {
    meta:
        author = "Areeb Ahmed"
        description = "Detects the use of weak encryption protocols or ciphers in SSH"

    strings:
        $weak_encryption = /cipher\s+(3des|blowfish|arc4)/i

    condition:
        $weak_encryption
}

rule Detect_Password_Access_By_Root {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts to the root user via password authentication"

    strings:
        $root_password_access = /user\s+root.*password/i

    condition:
        $root_password_access
}

rule Detect_SSH_DDoS_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects possible SSH Distributed Denial of Service (DDoS) attack patterns"

    strings:
        $ddos_pattern = /Connection\s+closed.*by\s+\S+/i

    condition:
        $ddos_pattern
}

rule Detect_Unusual_PAM_Activity {
    meta:
        author = "Areeb Ahmed"
        description = "Detects unusual activity related to PAM in SSH logs"

    strings:
        $pam_unusual = /pam_unix.*(\bunknown\b|\btimeout\b|\bfailure\b)/i

    condition:
        $pam_unusual
}

rule Detect_Automated_Attack_Patterns {
    meta:
        author = "Areeb Ahmed"
        description = "Detects patterns that may indicate automated attack tools"

    strings:
        $automated_attack = /(hydra|medusa|ncrack)/i

    condition:
        $automated_attack
}

rule Detect_SSH_Access_From_Abroad {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from foreign or unusual geographical locations"

    strings:
        $foreign_access = /from\s+\b(\d{1,3}\.){3}\d{1,3}\b\s+(cn|ru|br|in|ng)/i

    condition:
        $foreign_access
}

rule Detect_SSH_Connection_Reset {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH connection reset events"

    strings:
        $connection_reset = /Connection\s+reset\s+by\s+\S+/i

    condition:
        $connection_reset
}
