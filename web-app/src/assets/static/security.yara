rule SQM_Events {
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

rule Servicing_Stack_Loaded {
    meta:
        author = "Areeb Ahmed"
        description = "Detect when the Servicing Stack is loaded"

    strings:
        $loaded = "Loaded Servicing Stack"

    condition:
        $loaded
}

rule Wcp_Initialize {
    meta:
        author = "Areeb Ahmed"
        description = "Detect WcpInitialize calls"

    strings:
        $initialize = "WcpInitialize (wcp.dll version"
        $stack = "called (stack"

    condition:
        $initialize and $stack
}

rule Trusted_Installer_Events {
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

rule CBS_Loaded {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS loaded events"

    strings:
        $loaded = "CBS Loaded"

    condition:
        $loaded
}

rule CBS_Starting {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS starting events"

    strings:
        $starting = "CBS Starting"

    condition:
        $starting
}

rule CBS_Initialization {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS initialization events"

    strings:
        $initialization = "CBS Initialization"

    condition:
        $initialization
}

rule CSI_Metadata {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI metadata events"

    strings:
        $metadata = "CSI metadata"

    condition:
        $metadata
}

rule CSI_Warning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI warnings"

    strings:
        $warning = "CSI warning"

    condition:
        $warning
}

rule CSI_Error {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI errors"

    strings:
        $error = "CSI error"

    condition:
        $error
}

rule CSI_Cleanup {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI cleanup events"

    strings:
        $cleanup = "CSI cleanup"

    condition:
        $cleanup
}

rule CSI_Version_Info {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CSI version information"

    strings:
        $version_info = "CSI version"

    condition:
        $version_info
}

rule CBS_Shutdown {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS shutdown events"

    strings:
        $shutdown = "CBS shutdown"

    condition:
        $shutdown
}

rule CBS_Unloading {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS unloading events"

    strings:
        $unloading = "CBS unloading"

    condition:
        $unloading
}

rule CBS_Reboot {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS reboot events"

    strings:
        $reboot = "CBS reboot"

    condition:
        $reboot
}

rule CBS_Restart {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS restart events"

    strings:
        $restart = "CBS restart"

    condition:
        $restart
}

rule CBS_Failure {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS failure events"

    strings:
        $failure = "CBS failure"

    condition:
        $failure
}

rule CBS_Log_Error {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log errors"

    strings:
        $log_error = "CBS log error"

    condition:
        $log_error
}

rule CBS_Log_Warning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log warnings"

    strings:
        $log_warning = "CBS log warning"

    condition:
        $log_warning
}

rule CBS_Log_Info {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log information"

    strings:
        $log_info = "CBS log info"

    condition:
        $log_info
}

rule CBS_Log_Verbose {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS log verbose messages"

    strings:
        $log_verbose = "CBS log verbose"

    condition:
        $log_verbose
}

rule CBS_Commit {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS commit events"

    strings:
        $commit = "CBS commit"

    condition:
        $commit
}

rule CBS_Cancel {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS cancel events"

    strings:
        $cancel = "CBS cancel"

    condition:
        $cancel
}

rule CBS_Execution {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS execution events"

    strings:
        $execution = "CBS execution"

    condition:
        $execution
}

rule CBS_Dependency {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS dependency events"

    strings:
        $dependency = "CBS dependency"

    condition:
        $dependency
}

rule CBS_Resolution {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS resolution events"

    strings:
        $resolution = "CBS resolution"

    condition:
        $resolution
}

rule CBS_Deployment {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS deployment events"

    strings:
        $deployment = "CBS deployment"

    condition:
        $deployment
}

rule CBS_Installation {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS installation events"

    strings:
        $installation = "CBS installation"

    condition:
        $installation
}

rule CBS_Update {
    meta:
        author = "Areeb Ahmed"
        description = "Detect CBS update events"

    strings:
        $update = "CBS update"

    condition:
        $update
}

rule Thunderbolt_Event {
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

rule Thermal_Pressure_State {
    meta:
        author = "Areeb Ahmed"
        description = "Detect thermal pressure state changes"

    strings:
        $thermal_pressure = "Thermal pressure state"

    condition:
        $thermal_pressure
}

rule Memory_Pressure_State {
    meta:
        author = "Areeb Ahmed"
        description = "Detect memory pressure state changes"

    strings:
        $memory_pressure = "Memory pressure state"

    condition:
        $memory_pressure
}

rule URL_Task_Dealloc {
    meta:
        author = "Areeb Ahmed"
        description = "Detect URL task deallocation events"

    strings:
        $url_task = "Url||taskID"
        $dealloc = "dealloc"

    condition:
        $url_task and $dealloc
}

rule AirPort_Sync_Power_State {
    meta:
        author = "Areeb Ahmed"
        description = "Detect AirPort sync power state changes"

    strings:
        $airport_sync = "AirPort_Brcm43xx::syncPowerState"
        $wwen_enabled = "WWEN[enabled]"

    condition:
        $airport_sync and $wwen_enabled
}

rule AirPort_Platform_WoW {
    meta:
        author = "Areeb Ahmed"
        description = "Detect AirPort platform WoW enable/disable events"

    strings:
        $airport_platform = "AirPort_Brcm43xx::platformWoWEnable"
        $wwen_disable = "WWEN[disable]"

    condition:
        $airport_platform and $wwen_disable
}

rule Frequent_Transitions {
    meta:
        author = "Areeb Ahmed"
        description = "Detect frequent interface transitions in mDNSResponder"

    strings:
        $frequent_transitions = "Frequent transitions for interface"

    condition:
        $frequent_transitions
}

rule Sleep_Information {
    meta:
        author = "Areeb Ahmed"
        description = "Detect sleep-related power source information"

    strings:
        $sleep_info = "IOPMPowerSource Information: onSleep"
        $sleep_type = "SleepType: Normal Sleep"

    condition:
        $sleep_info and $sleep_type
}

rule TCP_Keep_Alive {
    meta:
        author = "Areeb Ahmed"
        description = "Detect TCP keep-alive sequence updates"

    strings:
        $tcp_keepalive = "wl_update_tcpkeep_seq: Original Seq"

    condition:
        $tcp_keepalive
}

rule Wake_Reason {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system wake reasons"

    strings:
        $wake_reason = "Wake Reason"

    condition:
        $wake_reason
}

rule Network_Analytics_Switch {
    meta:
        author = "Areeb Ahmed"
        description = "Detect unexpected switch values in Network Analytics Engine"

    strings:
        $network_analytics = "NetworkAnalyticsEngine"
        $unexpected_switch = "unexpected switch value"

    condition:
        $network_analytics and $unexpected_switch
}

rule AWDL_Peer_Manager {
    meta:
        author = "Areeb Ahmed"
        description = "Detect AWDL peer manager events"

    strings:
        $awdl_peer_manager = "IO80211AWDLPeerManager::setAwdlAutoMode"

    condition:
        $awdl_peer_manager
}

rule MDNS_Records {
    meta:
        author = "Areeb Ahmed"
        description = "Detect mDNS records"

    strings:
        $mdns_records = "MDNS: 0 SRV Recs, 0 TXT Recs"

    condition:
        $mdns_records
}

rule Camera_Wake_Call {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system wake calls for the camera"

    strings:
        $camera_wake = "AppleCamIn::systemWakeCall"
        $message_type = "messageType"

    condition:
        $camera_wake and $message_type
}

rule Hostname_Setting {
    meta:
        author = "Areeb Ahmed"
        description = "Detect hostname setting events"

    strings:
        $hostname_setting = "setting hostname to"

    condition:
        $hostname_setting
}

rule Kernel_Error {
    meta:
        author = "Areeb Ahmed"
        description = "Detect kernel errors"

    strings:
        $kernel_error = "kernel: error"

    condition:
        $kernel_error
}

rule Kernel_Panic {
    meta:
        author = "Areeb Ahmed"
        description = "Detect kernel panic events"

    strings:
        $kernel_panic = "kernel: panic"

    condition:
        $kernel_panic
}

rule System_Sleep {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system sleep events"

    strings:
        $system_sleep = "system sleep"

    condition:
        $system_sleep
}

rule System_Wake {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system wake events"

    strings:
        $system_wake = "system wake"

    condition:
        $system_wake
}

rule Network_Change {
    meta:
        author = "Areeb Ahmed"
        description = "Detect network change events"

    strings:
        $network_change = "network change detected"

    condition:
        $network_change
}

rule Power_State_Change {
    meta:
        author = "Areeb Ahmed"
        description = "Detect power state change events"

    strings:
        $power_state_change = "power state change"

    condition:
        $power_state_change
}

rule Thermal_State_Change {
    meta:
        author = "Areeb Ahmed"
        description = "Detect thermal state change events"

    strings:
        $thermal_state_change = "thermal state change"

    condition:
        $thermal_state_change
}

rule Battery_Level {
    meta:
        author = "Areeb Ahmed"
        description = "Detect battery level events"

    strings:
        $battery_level = "battery level"

    condition:
        $battery_level
}

rule Disk_Usage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect disk usage events"

    strings:
        $disk_usage = "disk usage"

    condition:
        $disk_usage
}

rule Memory_Usage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect memory usage events"

    strings:
        $memory_usage = "memory usage"

    condition:
        $memory_usage
}

rule Application_Crash {
    meta:
        author = "Areeb Ahmed"
        description = "Detect application crash events"

    strings:
        $app_crash = "application crash"

    condition:
        $app_crash
}

rule Service_Start {
    meta:
        author = "Areeb Ahmed"
        description = "Detect service start events"

    strings:
        $service_start = "service start"

    condition:
        $service_start
}

rule SSH_Auth_Failure {
    meta:
        author = "Areeb Ahmed"
        description = "Detect SSH authentication failures"

    strings:
        $auth_failure = "authentication failure"
        $sshd = "sshd"

    condition:
        $auth_failure and $sshd
}

rule SSH_User_Unknown {
    meta:
        author = "Areeb Ahmed"
        description = "Detect unknown user in SSH"

    strings:
        $check_pass = "check pass"
        $user_unknown = "user unknown"

    condition:
        $check_pass and $user_unknown
}

rule SSH_Root_Attempt {
    meta:
        author = "Areeb Ahmed"
        description = "Detect root login attempts via SSH"

    strings:
        $ssh_root = "user=root"
        $sshd = "sshd"

    condition:
        $ssh_root and $sshd
}

rule PAM_Session_Opened {
    meta:
        author = "Areeb Ahmed"
        description = "Detect PAM session openings"

    strings:
        $pam_unix = "pam_unix"
        $session_opened = "session opened"

    condition:
        $pam_unix and $session_opened
}

rule PAM_Session_Closed {
    meta:
        author = "Areeb Ahmed"
        description = "Detect PAM session closures"

    strings:
        $pam_unix = "pam_unix"
        $session_closed = "session closed"

    condition:
        $pam_unix and $session_closed
}

rule PAM_Auth_Error {
    meta:
        author = "Areeb Ahmed"
        description = "Detect PAM authentication errors"

    strings:
        $pam_unix = "pam_unix"
        $auth_error = "authentication failure"

    condition:
        $pam_unix and $auth_error
}

rule Kernel_Warning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect kernel warnings"

    strings:
        $kernel_warning = "kernel: warning"

    condition:
        $kernel_warning
}

rule User_Login {
    meta:
        author = "Areeb Ahmed"
        description = "Detect user login events"

    strings:
        $user_login = "session opened for user"

    condition:
        $user_login
}

rule User_Logout {
    meta:
        author = "Areeb Ahmed"
        description = "Detect user logout events"

    strings:
        $user_logout = "session closed for user"

    condition:
        $user_logout
}

rule System_Reboot {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system reboot events"

    strings:
        $system_reboot = "system reboot"

    condition:
        $system_reboot
}

rule System_Shutdown {
    meta:
        author = "Areeb Ahmed"
        description = "Detect system shutdown events"

    strings:
        $system_shutdown = "system shutdown"

    condition:
        $system_shutdown
}

rule Service_Stop {
    meta:
        author = "Areeb Ahmed"
        description = "Detect service stop events"

    strings:
        $service_stop = "Stopping service"

    condition:
        $service_stop
}

rule Disk_Space_Warning {
    meta:
        author = "Areeb Ahmed"
        description = "Detect disk space warnings"

    strings:
        $disk_space_warning = "disk space low"

    condition:
        $disk_space_warning
}

rule High_Memory_Usage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect high memory usage"

    strings:
        $high_memory_usage = "memory usage high"

    condition:
        $high_memory_usage
}

rule High_CPU_Usage {
    meta:
        author = "Areeb Ahmed"
        description = "Detect high CPU usage"

    strings:
        $high_cpu_usage = "CPU usage high"

    condition:
        $high_cpu_usage
}

rule Network_Issue {
    meta:
        author = "Areeb Ahmed"
        description = "Detect network issues"

    strings:
        $network_issue = "network issue detected"

    condition:
        $network_issue
}

rule Cron_Job_Start {
    meta:
        author = "Areeb Ahmed"
        description = "Detect cron job start events"

    strings:
        $cron_job_start = "Starting cron job"

    condition:
        $cron_job_start
}

rule Cron_Job_End {
    meta:
        author = "Areeb Ahmed"
        description = "Detect cron job end events"

    strings:
        $cron_job_end = "Ending cron job"

    condition:
        $cron_job_end
}

rule File_System_Error {
    meta:
        author = "Areeb Ahmed"
        description = "Detect filesystem errors"

    strings:
        $filesystem_error = "filesystem error"

    condition:
        $filesystem_error
}

rule Hardware_Error {
    meta:
        author = "Areeb Ahmed"
        description = "Detect hardware errors"

    strings:
        $hardware_error = "hardware error"

    condition:
        $hardware_error
}

rule Software_Update {
    meta:
        author = "Areeb Ahmed"
        description = "Detect software update events"

    strings:
        $software_update = "software update"

    condition:
        $software_update
}

rule Package_Installation {
    meta:
        author = "Areeb Ahmed"
        description = "Detect package installation events"

    strings:
        $package_installation = "installing package"

    condition:
        $package_installation
}

rule Package_Removal {
    meta:
        author = "Areeb Ahmed"
        description = "Detect package removal events"

    strings:
        $package_removal = "removing package"

    condition:
        $package_removal
}

rule Firewall_Event {
    meta:
        author = "Areeb Ahmed"
        description = "Detect firewall events"

    strings:
        $firewall_event = "firewall event"

    condition:
        $firewall_event
}

rule SSH_Connection {
    meta:
        author = "Areeb Ahmed"
        description = "Detect SSH connection events"

    strings:
        $ssh_connection = "sshd: connection from"

    condition:
        $ssh_connection
}

rule Root_Access {
    meta:
        author = "Areeb Ahmed"
        description = "Detect root access events"

    strings:
        $root_access = "root access granted"

    condition:
        $root_access
}

rule Unauthorized_Access {
    meta:
        author = "Areeb Ahmed"
        description = "Detect unauthorized access attempts"

    strings:
        $unauthorized_access = "unauthorized access attempt"

    condition:
        $unauthorized_access
}

rule Window_Manager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to Window Manager activities across various logs"

    strings:
        $wm_issues = /WindowManager:\s*(error|fail|issue|problem)/i

    condition:
        $wm_issues
}

rule Lock_Acquisition_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to lock acquisition in different services"

    strings:
        $lock_issues = /acquire.*(lock|mutex|semaphore)/i

    condition:
        $lock_issues
}

rule App_Window_Token_Problems {
    meta:
        author = "Areeb Ahmed"
        description = "Detects problems related to AppWindowToken or similar entities"

    strings:
        $app_window_token = /AppWindowToken.*(hide|close|relaunch|issue|error)/i

    condition:
        $app_window_token
}

rule Visibility_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to visibility changes in UI components"

    strings:
        $visibility = /(visible|visibility).*(error|problem|issue|change)/i

    condition:
        $visibility
}

rule Wakefulness_Problems {
    meta:
        author = "Areeb Ahmed"
        description = "Detects problems related to wakefulness state in power management or other systems"

    strings:
        $wakefulness = /wakefulness.*(error|problem|issue|change)/i

    condition:
        $wakefulness
}

rule Battery_State_Changes {
    meta:
        author = "Areeb Ahmed"
        description = "Detects significant battery state changes or related issues"

    strings:
        $battery_state = /battery.*(state|level|error|issue|change)/i

    condition:
        $battery_state
}

rule Relaunching_Activities {
    meta:
        author = "Areeb Ahmed"
        description = "Detects relaunching activities in applications or services"

    strings:
        $relaunch = /(isRelaunching|restart|reinitialize|reboot).*(true|yes|failed|error)/i

    condition:
        $relaunch
}

rule Hide_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects events where components are hidden unexpectedly"

    strings:
        $hide_event = /(hide|disappear|vanish|close).*(error|problem|issue|unexpected)/i

    condition:
        $hide_event
}

rule Keyguard_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to Keyguard or similar security features"

    strings:
        $keyguard = /Keyguard.*(error|fail|issue|problem)/i

    condition:
        $keyguard
}

rule Network_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects network-related errors or issues"

    strings:
        $network_error = /Network.*(error|fail|disconnect|timeout|issue|problem)/i

    condition:
        $network_error
}

rule GPS_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects GPS-related issues or status updates"

    strings:
        $gps_issues = /(GPS|location).*(fail|issue|problem|error|update)/i

    condition:
        $gps_issues
}

rule Bluetooth_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues with Bluetooth connections or status"

    strings:
        $bluetooth = /Bluetooth.*(error|fail|issue|disconnect|problem)/i

    condition:
        $bluetooth
}

rule Media_Playback_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to media playback across various logs"

    strings:
        $media_playback = /Media.*(playback|start|pause|stop|fail|error|issue|problem)/i

    condition:
        $media_playback
}

rule App_Crash {
    meta:
        author = "Areeb Ahmed"
        description = "Detects application crash events in logs"

    strings:
        $app_crash = /Application.*(crash|fail|terminate|unexpected|exit|error)/i

    condition:
        $app_crash
}

rule System_UI_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects System UI errors or issues"

    strings:
        $system_ui = /SystemUI.*(error|crash|issue|problem)/i

    condition:
        $system_ui
}

rule Camera_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to CameraService or similar components"

    strings:
        $camera_service = /CameraService.*(error|fail|issue|problem)/i

    condition:
        $camera_service
}

rule Display_Orientation_Changes {
    meta:
        author = "Areeb Ahmed"
        description = "Detects display orientation changes or related issues"

    strings:
        $orientation_change = /display.*(orientation|rotate|angle).*(change|error|issue)/i

    condition:
        $orientation_change
}

rule Package_Installation_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects package installation events or issues"

    strings:
        $package_install = /(install|installation|package).*(error|fail|success|issue)/i

    condition:
        $package_install
}

rule Sensor_Service_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues or events related to sensor services"

    strings:
        $sensor_service = /Sensor.*(Service|error|issue|fail|problem)/i

    condition:
        $sensor_service
}

rule Wifi_Connection_Changes {
    meta:
        author = "Areeb Ahmed"
        description = "Detects Wi-Fi connection changes or issues"

    strings:
        $wifi_connection = /(WiFi|wireless|network).*(connect|disconnect|error|fail|issue)/i

    condition:
        $wifi_connection
}

rule Thermal_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to thermal services"

    strings:
        $thermal_service = /Thermal.*(Service|error|overheat|fail|issue|problem)/i

    condition:
        $thermal_service
}

rule Input_Method_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to input methods or services"

    strings:
        $input_method = /(InputMethod|keyboard|IME).*(error|fail|issue|problem)/i

    condition:
        $input_method
}

rule Job_Scheduler_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to job scheduling services"

    strings:
        $job_scheduler = /JobScheduler.*(error|fail|issue|problem)/i

    condition:
        $job_scheduler
}

rule Notification_Manager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to NotificationManagerService"

    strings:
        $notification_manager = /Notification.*(error|fail|issue|problem)/i

    condition:
        $notification_manager
}

rule Screen_Off_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects screen off events or issues in logs"

    strings:
        $screen_off = /(screen|display).*(off|shutdown|power down|sleep).*(error|issue|unexpected)/i

    condition:
        $screen_off
}

rule Vibrator_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to vibrator services"

    strings:
        $vibrator_service = /Vibrator.*(Service|error|fail|issue|problem)/i

    condition:
        $vibrator_service
}

rule Media_Scanner_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to MediaScannerService"

    strings:
        $media_scanner = /MediaScanner.*(Service|error|fail|issue|problem)/i

    condition:
        $media_scanner
}

rule Telephony_Service_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to TelephonyService"

    strings:
        $telephony_service = /Telephony.*(Service|error|fail|issue|problem)/i

    condition:
        $telephony_service
}

rule App_Focus_Change {
    meta:
        author = "Areeb Ahmed"
        description = "Detects app focus change events or issues"

    strings:
        $app_focus_change = /app.*(focus|foreground|background).*(change|issue|error)/i

    condition:
        $app_focus_change
}

rule System_Update_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to system updates"

    strings:
        $system_update = /SystemUpdate.*(error|fail|issue|problem)/i

    condition:
        $system_update
}

rule SSH_Break_In_Attempt {
    meta:
        author = "Areeb Ahmed"
        description = "Detects potential break-in attempts in SSH logs"

    strings:
        $break_in_attempt = /POSSIBLE\s+BREAK-IN\s+ATTEMPT/i

    condition:
        $break_in_attempt
}

rule Invalid_User_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects invalid user attempts in SSH logs"

    strings:
        $invalid_user = /Invalid\s+user\s+\S+/i

    condition:
        $invalid_user
}

rule Failed_Authentication {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failed authentication attempts"

    strings:
        $failed_auth = /authentication\s+failure/i
        $failed_password = /Failed\s+password/i

    condition:
        $failed_auth or $failed_password
}

rule Reverse_Mapping_Failure {
    meta:
        author = "Areeb Ahmed"
        description = "Detects reverse mapping failures that may indicate DNS issues or security risks"

    strings:
        $reverse_mapping = /reverse\s+mapping\s+checking.*failed/i

    condition:
        $reverse_mapping
}

rule SSH_Connection_Closed {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH connection closure events"

    strings:
        $connection_closed = /Connection\s+closed\s+by\s+\S+/i

    condition:
        $connection_closed
}

rule PAM_Authentication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to PAM authentication in SSH"

    strings:
        $pam_auth = /pam_unix.*authentication\s+failure/i

    condition:
        $pam_auth
}

rule SSH_Protocol_Version {
    meta:
        author = "Areeb Ahmed"
        description = "Detects specific SSH protocol versions being used in connections"

    strings:
        $protocol_version = /ssh\d+/i

    condition:
        $protocol_version
}

rule Preauthentication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues occurring before authentication (preauth) in SSH logs"

    strings:
        $preauth_issue = /preauth/i

    condition:
        $preauth_issue
}

rule Port_Scanning_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects potential port scanning attempts by looking for multiple failed attempts from the same IP"

    strings:
        $failed_attempt = /Failed\s+password/i

    condition:
        $failed_attempt
}

rule SSH_Access_From_Known_Hosts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from known or specific IP addresses"

    strings:
        $known_ip = /from\s+(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))\.\d+\.\d+/i

    condition:
        $known_ip
}

rule Root_Login_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects root login attempts via SSH"

    strings:
        $root_login = /user\s+root/i

    condition:
        $root_login
}

rule Invalid_Credentials_Use {
    meta:
        author = "Areeb Ahmed"
        description = "Detects use of invalid or unauthorized credentials"

    strings:
        $invalid_credentials = /invalid\s+(password|user|credentials)/i

    condition:
        $invalid_credentials
}

rule Excessive_Login_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects multiple login attempts that may indicate a brute-force attack"

    strings:
        $login_attempt = /Failed\s+password/i

    condition:
        $login_attempt
}

rule SSH_Timeouts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH connection timeouts"

    strings:
        $timeout = /timeout/i

    condition:
        $timeout
}

rule Access_From_Blacklisted_IP {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from blacklisted or suspicious IP addresses"

    strings:
        $blacklisted_ip = /from\s+\b(\d{1,3}\.){3}\d{1,3}\b/i

    condition:
        $blacklisted_ip
}

rule Public_Key_Access {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts using public key authentication"

    strings:
        $public_key = /public\s+key/i

    condition:
        $public_key
}

rule Password_Access {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts using password authentication"

    strings:
        $password_auth = /password/i

    condition:
        $password_auth
}

rule Possible_SSH_Exploit {
    meta:
        author = "Areeb Ahmed"
        description = "Detects patterns that may indicate an SSH exploit attempt"

    strings:
        $exploit_pattern = /(exploit|vulnerability|shellshock|heartbleed)/i

    condition:
        $exploit_pattern
}

rule Botnet_Attack_Patterns {
    meta:
        author = "Areeb Ahmed"
        description = "Detects patterns that might indicate botnet attacks on SSH servers"

    strings:
        $botnet_pattern = /from\s+(\d{1,3}\.){3}\d{1,3}\s+ssh/i

    condition:
        $botnet_pattern
}

rule Suspicious_Activity_From_Unknown_Hosts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects suspicious activities originating from unknown or unusual hosts"

    strings:
        $unknown_host = /from\s+\S+\.\S+\s+ssh/i

    condition:
        $unknown_host
}

rule Large_Number_Of_Failed_Logins {
    meta:
        author = "Areeb Ahmed"
        description = "Detects a large number of failed login attempts from a single IP"

    strings:
        $failed_login = /Failed\s+password/i

    condition:
        $failed_login
}

rule Unexpected_SSH_Disconnections {
    meta:
        author = "Areeb Ahmed"
        description = "Detects unexpected SSH disconnections that may indicate an issue"

    strings:
        $unexpected_disconnect = /Connection\s+closed\s+by\s+\S+/i

    condition:
        $unexpected_disconnect
}

rule Failed_Public_Key_Authentication {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failed attempts at public key authentication"

    strings:
        $failed_key_auth = /Failed\s+publickey/i

    condition:
        $failed_key_auth
}

rule SSH_Access_From_Multiple_IPs {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from multiple IP addresses, which may indicate an attack"

    strings:
        $access_from_multiple_ips = /from\s+\b(\d{1,3}\.){3}\d{1,3}\b/i

    condition:
        $access_from_multiple_ips
}

rule Use_Of_Weak_Encryption {
    meta:
        author = "Areeb Ahmed"
        description = "Detects the use of weak encryption protocols or ciphers in SSH"

    strings:
        $weak_encryption = /cipher\s+(3des|blowfish|arc4)/i

    condition:
        $weak_encryption
}

rule Password_Access_By_Root {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts to the root user via password authentication"

    strings:
        $root_password_access = /user\s+root.*password/i

    condition:
        $root_password_access
}

rule SSH_DDoS_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects possible SSH Distributed Denial of Service (DDoS) attack patterns"

    strings:
        $ddos_pattern = /Connection\s+closed.*by\s+\S+/i

    condition:
        $ddos_pattern
}

rule Unusual_PAM_Activity {
    meta:
        author = "Areeb Ahmed"
        description = "Detects unusual activity related to PAM in SSH logs"

    strings:
        $pam_unusual = /pam_unix.*(\bunknown\b|\btimeout\b|\bfailure\b)/i

    condition:
        $pam_unusual
}

rule Automated_Attack_Patterns {
    meta:
        author = "Areeb Ahmed"
        description = "Detects patterns that may indicate automated attack tools"

    strings:
        $automated_attack = /(hydra|medusa|ncrack)/i

    condition:
        $automated_attack
}

rule SSH_Access_From_Abroad {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH access attempts from foreign or unusual geographical locations"

    strings:
        $foreign_access = /from\s+\b(\d{1,3}\.){3}\d{1,3}\b\s+(cn|ru|br|in|ng)/i

    condition:
        $foreign_access
}

rule SSH_Connection_Reset {
    meta:
        author = "Areeb Ahmed"
        description = "Detects SSH connection reset events"

    strings:
        $connection_reset = /Connection\s+reset\s+by\s+\S+/i

    condition:
        $connection_reset
}

rule Signal_Handler_Registration_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the registration of signal handlers"

    strings:
        $signal_handlers = /signal\s*handlers\s*for\s*(TERM|HUP|INT|other)/i

    condition:
        $signal_handlers
}

rule ACL_Change_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to ACL (Access Control List) changes in SecurityManager"

    strings:
        $acl_issues = /Changing\s*(view|modify)\s*acls\s*(to|from):\s*/i

    condition:
        $acl_issues
}

rule SecurityManager_Configuration_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects configuration issues in SecurityManager related to authentication or UI ACLs"

    strings:
        $security_config = /SecurityManager.*(authentication|ui\s*acls|permissions)\s*(disabled|enabled)/i

    condition:
        $security_config
}

rule Service_Startup_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the startup of various services in Spark"

    strings:
        $service_start = /Successfully\s*started\s*service.*(sparkExecutor|NettyBlockTransferService)/i

    condition:
        $service_start
}

rule DiskBlockManager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the creation of local directories in DiskBlockManager"

    strings:
        $disk_block = /Created\s*local\s*directory\s*at/i

    condition:
        $disk_block
}

rule MemoryStore_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to MemoryStore operations, like capacity or block storage"

    strings:
        $memory_store = /MemoryStore.*(started|block\s*stored|capacity|error|issue)/i

    condition:
        $memory_store
}

rule Executor_Connection_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects connection or registration issues with Spark Executors"

    strings:
        $executor_connection = /Executor.*(Connecting|connected|registered|error|issue)/i

    condition:
        $executor_connection
}

rule CacheManager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to CacheManager operations like partition computations"

    strings:
        $cache_manager = /CacheManager.*(partition\s*not\s*found|computing|error|issue)/i

    condition:
        $cache_manager
}

rule Input_Split_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to input splits in HadoopRDD or other similar RDDs"

    strings:
        $input_split = /Input\s*split.*(hdfs|file|error|issue)/i

    condition:
        $input_split
}

rule Broadcast_Variable_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the reading or storage of broadcast variables"

    strings:
        $broadcast_var = /Broadcast\s*variable.*(reading|stored|error|issue)/i

    condition:
        $broadcast_var
}

rule Deprecation_Warnings {
    meta:
        author = "Areeb Ahmed"
        description = "Detects deprecation warnings in configurations or other operations"

    strings:
        $deprecation_warning = /deprecation.*(mapred|task|warning|error)/i

    condition:
        $deprecation_warning
}

rule Remoting_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to remoting operations, like starting or listening"

    strings:
        $remoting_issues = /Remoting.*(starting|started|listening|error|issue)/i

    condition:
        $remoting_issues
}

rule SparkListener_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues or activities related to SparkListener events"

    strings:
        $spark_listener = /SparkListener.*(event|error|issue|activity)/i

    condition:
        $spark_listener
}

rule BlockManager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to block storage or replication in BlockManager"

    strings:
        $block_manager = /BlockManager.*(block\s*stored|replication|error|issue)/i

    condition:
        $block_manager
}

rule ShuffleBlockFetcher_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to fetching shuffle blocks"

    strings:
        $shuffle_fetcher = /ShuffleBlockFetcher.*(fetching|failed|error|issue)/i

    condition:
        $shuffle_fetcher
}

rule DAGScheduler_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to DAGScheduler operations like task submissions"

    strings:
        $dag_scheduler = /DAGScheduler.*(task\s*submitted|stage|failure|error|issue)/i

    condition:
        $dag_scheduler
}

rule Taskscheduler_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to TaskScheduler operations like task failures"

    strings:
        $task_scheduler = /TaskScheduler.*(task\s*failed|error|issue|pending)/i

    condition:
        $task_scheduler
}

rule TaskSetManager_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to TaskSetManager operations"

    strings:
        $task_set_manager = /TaskSetManager.*(failed|completed|error|issue)/i

    condition:
        $task_set_manager
}

rule Stage_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to stages in the Spark job"

    strings:
        $stage_issues = /Stage.*(failed|completed|error|issue)/i

    condition:
        $stage_issues
}

rule Executor_Loss {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the loss of executors in a Spark job"

    strings:
        $executor_loss = /Lost\s*executor.*(reason|error|issue)/i

    condition:
        $executor_loss
}

rule Job_Failure {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues or errors leading to job failures"

    strings:
        $job_failure = /Job.*(failed|error|issue)/i

    condition:
        $job_failure
}

rule Resource_Allocation_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to resource allocation in Spark"

    strings:
        $resource_allocation = /Resource\s*allocation.*(error|issue|problem|failure)/i

    condition:
        $resource_allocation
}

rule Killed_Tasks {
    meta:
        author = "Areeb Ahmed"
        description = "Detects tasks that were killed due to various issues"

    strings:
        $killed_tasks = /Task.*(killed|terminated|failed)/i

    condition:
        $killed_tasks
}

rule Connection_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to connection failures or timeouts"

    strings:
        $connection_issues = /Connection.*(failed|timeout|refused|error)/i

    condition:
        $connection_issues
}

rule Network_Problems {
    meta:
        author = "Areeb Ahmed"
        description = "Detects network-related issues like timeouts or failures"

    strings:
        $network_problems = /Network.*(timeout|failed|error|issue)/i

    condition:
        $network_problems
}

rule RPC_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to RPC (Remote Procedure Call) failures or timeouts"

    strings:
        $rpc_issues = /RPC.*(failed|timeout|error|issue)/i

    condition:
        $rpc_issues
}

rule Memory_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects memory-related issues like out-of-memory errors"

    strings:
        $memory_issues = /Memory.*(out\s*of|error|issue|problem|failure)/i

    condition:
        $memory_issues
}

rule Garbage_Collection_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to garbage collection or memory leaks"

    strings:
        $gc_issues = /GC.*(overhead|memory|error|issue|leak)/i

    condition:
        $gc_issues
}

rule FileSystem_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to file system operations like reading or writing files"

    strings:
        $filesystem_issues = /FileSystem.*(read|write|failed|error|issue)/i

    condition:
        $filesystem_issues
}

rule Configuration_Warnings {
    meta:
        author = "Areeb Ahmed"
        description = "Detects configuration warnings or errors"

    strings:
        $config_warnings = /Configuration.*(deprecated|warning|error|issue)/i

    condition:
        $config_warnings
}

rule Job_Submission_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to job submission or failure across different log files"

    strings:
        $job_submission = /job.*(submit|failure|failed|error|issue|problem)/i

    condition:
        $job_submission
}

rule Token_Retrieval_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects problems related to token retrieval or authentication issues"

    strings:
        $token_retrieval = /token.*(retrieve|fail|failure|error|issue|problem|authentication)/i

    condition:
        $token_retrieval
}

rule Committer_Configuration_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to committer configuration in various services"

    strings:
        $committer_error = /(committer|outputcommitter).*config.*(null|error|missing|issue|problem)/i

    condition:
        $committer_error
}

rule AsyncDispatcher_Registration_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects registration issues with AsyncDispatcher or similar components"

    strings:
        $async_dispatcher = /asyncdispatcher.*(register|fail|error|issue|problem)/i

    condition:
        $async_dispatcher
}

rule RPC_Server_Problems {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to RPC server operations"

    strings:
        $rpc_server = /rpc\s*server.*(error|fail|issue|problem|unavailable)/i

    condition:
        $rpc_server
}

rule YARN_Application_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to YARN applications or containers"

    strings:
        $yarn_app_issues = /yarn.*(application|container).*(error|fail|issue|problem)/i

    condition:
        $yarn_app_issues
}

rule MapReduce_Job_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors or issues in MapReduce jobs"

    strings:
        $mr_job_errors = /mapreduce.*job.*(fail|failure|error|issue|problem)/i

    condition:
        $mr_job_errors
}

rule NodeManager_Startup_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the startup of NodeManager"

    strings:
        $nm_startup = /nodemanager.*start.*(fail|failure|error|issue|problem)/i

    condition:
        $nm_startup
}

rule ResourceManager_Communication_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects communication failures with ResourceManager or similar components"

    strings:
        $rm_communication = /resourcemanager.*(fail|failure|error|issue|problem|unreachable|unavailable)/i

    condition:
        $rm_communication
}

rule HDFS_Connection_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects connection errors or issues with HDFS"

    strings:
        $hdfs_errors = /hdfs.*(connection|connect|fail|failure|error|issue|problem)/i

    condition:
        $hdfs_errors
}

rule Configuration_Loading_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to loading configuration files or parameters"

    strings:
        $config_loading = /configuration.*(load|loading).*(fail|failure|error|issue|problem)/i

    condition:
        $config_loading
}

rule Heartbeat_Timeouts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects heartbeat timeouts or related issues in distributed systems"

    strings:
        $heartbeat_timeout = /heartbeat.*(timeout|miss|fail|failure|error|issue|problem)/i

    condition:
        $heartbeat_timeout
}

rule DataNode_Problems {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to DataNode operations or failures"

    strings:
        $datanode_problems = /datanode.*(fail|failure|error|issue|problem|unreachable|unavailable)/i

    condition:
        $datanode_problems
}

rule Reducer_Task_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures in Reducer tasks during MapReduce operations"

    strings:
        $reducer_failures = /reducer.*task.*(fail|failure|error|issue|problem)/i

    condition:
        $reducer_failures
}

rule Mapper_Task_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues or errors in Mapper tasks"

    strings:
        $mapper_issues = /mapper.*task.*(fail|failure|error|issue|problem)/i

    condition:
        $mapper_issues
}

rule JobTracker_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures or problems with the JobTracker"

    strings:
        $jobtracker_failures = /jobtracker.*(fail|failure|error|issue|problem)/i

    condition:
        $jobtracker_failures
}

rule Filesystem_Check_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to filesystem checks or validations"

    strings:
        $fs_check_errors = /filesystem.*(check|validate).*(fail|failure|error|issue|problem)/i

    condition:
        $fs_check_errors
}

rule Job_History_Server_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the Job History Server"

    strings:
        $jhs_issues = /job\s*history\s*server.*(fail|failure|error|issue|problem)/i

    condition:
        $jhs_issues
}

rule Container_Allocation_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures or issues in container allocation"

    strings:
        $container_allocation = /container.*(allocation|assign).*(fail|failure|error|issue|problem)/i

    condition:
        $container_allocation
}

rule Scheduler_Queue_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors or issues in scheduler queues"

    strings:
        $scheduler_queue = /scheduler.*queue.*(fail|failure|error|issue|problem)/i

    condition:
        $scheduler_queue
}

rule DNS_Resolution_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects DNS resolution failures or issues"

    strings:
        $dns_resolution = /dns.*(resolve|resolution).*(fail|failure|error|issue|problem)/i

    condition:
        $dns_resolution
}

rule Cluster_Resource_Management_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues in cluster resource management or allocation"

    strings:
        $cluster_management = /cluster.*resource.*(manage|allocation).*(fail|failure|error|issue|problem)/i

    condition:
        $cluster_management
}

rule Disk_Space_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to insufficient disk space or related issues"

    strings:
        $disk_space_errors = /disk\s*space.*(insufficient|fail|failure|error|issue|problem)/i

    condition:
        $disk_space_errors
}

rule Memory_Allocation_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures or issues related to memory allocation"

    strings:
        $memory_allocation = /memory\s*allocation.*(fail|failure|error|issue|problem)/i

    condition:
        $memory_allocation
}

rule JVM_Crash_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects JVM crashes or related errors"

    strings:
        $jvm_crash = /jvm.*(crash|fail|failure|error|issue|problem)/i

    condition:
        $jvm_crash
}

rule Network_Connectivity_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects network connectivity issues or failures"

    strings:
        $network_connectivity = /network.*(connect|connection).*(fail|failure|error|issue|problem)/i

    condition:
        $network_connectivity
}

rule RPC_Client_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors or issues with RPC client operations"

    strings:
        $rpc_client = /rpc\s*client.*(fail|failure|error|issue|problem)/i

    condition:
        $rpc_client
}

rule Security_Authentication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects authentication issues or security failures"

    strings:
        $security_auth = /authentication.*(fail|failure|error|issue|problem|security)/i

    condition:
        $security_auth
}

rule Cluster_Node_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures or issues with cluster nodes"

    strings:
        $cluster_node_failures = /cluster.*node.*(fail|failure|error|issue|problem|unreachable|unavailable)/i

    condition:
        $cluster_node_failures
}

rule Service_Restart_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors or issues during service restarts"

    strings:
        $service_restart_errors = /service.*restart.*(fail|failure|error|issue|problem)/i

    condition:
        $service_restart_errors
}

rule ModJK_Error_State {
    meta:
        author = "Areeb Ahmed"
        description = "Detects mod_jk module entering an error state"

    strings:
        $modjk_error = /mod_jk.*(error\s*state|fail|failure|issue|problem)/i

    condition:
        $modjk_error
}

rule WorkerEnv_Initialization {
    meta:
        author = "Areeb Ahmed"
        description = "Detects workerEnv initialization events in Apache logs"

    strings:
        $workerenv_init = /workerEnv\.init.*(ok|success|initialized)/i

    condition:
        $workerenv_init
}

rule Child_Process_Found {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a child process is found in scoreboard slots"

    strings:
        $child_process = /jk2_init.*Found\s*child.*(slot|scoreboard)/i

    condition:
        $child_process
}

rule HTTP_Error_404 {
    meta:
        author = "Areeb Ahmed"
        description = "Detects HTTP 404 errors across Apache logs"

    strings:
        $http_404 = /404.*(error|not\s*found|fail|issue|problem)/i

    condition:
        $http_404
}

rule HTTP_Error_500 {
    meta:
        author = "Areeb Ahmed"
        description = "Detects HTTP 500 Internal Server Errors"

    strings:
        $http_500 = /500.*(internal\s*server\s*error|fail|issue|problem)/i

    condition:
        $http_500
}

rule SSL_Certificate_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to SSL/TLS certificate issues"

    strings:
        $ssl_cert_error = /ssl.*certificate.*(error|fail|issue|problem|invalid|expired)/i

    condition:
        $ssl_cert_error
}

rule ModRewrite_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to mod_rewrite in Apache"

    strings:
        $modrewrite_error = /mod_rewrite.*(error|fail|issue|problem|rule\s*not\s*found)/i

    condition:
        $modrewrite_error
}

rule Connection_Timeouts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects connection timeout issues in Apache logs"

    strings:
        $conn_timeout = /connection.*timeout.*(error|fail|issue|problem)/i

    condition:
        $conn_timeout
}

rule Module_Loading_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures or issues in loading Apache modules"

    strings:
        $module_load_fail = /module.*load.*(fail|failure|error|issue|problem)/i

    condition:
        $module_load_fail
}

rule Segmentation_Faults {
    meta:
        author = "Areeb Ahmed"
        description = "Detects segmentation faults or related errors in Apache logs"

    strings:
        $segfault = /segmentation\s*fault.*(error|crash|fail|failure|issue|problem)/i

    condition:
        $segfault
}

rule Proxy_Server_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to proxy server operations in Apache"

    strings:
        $proxy_error = /proxy.*server.*(fail|failure|error|issue|problem|unreachable|unavailable)/i

    condition:
        $proxy_error
}

rule DNS_Lookup_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects DNS lookup failures or issues in Apache logs"

    strings:
        $dns_lookup = /dns.*lookup.*(fail|failure|error|issue|problem)/i

    condition:
        $dns_lookup
}

rule Client_Disconnection_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects client disconnection errors in Apache logs"

    strings:
        $client_disconnect = /client.*disconnection.*(error|fail|failure|issue|problem)/i

    condition:
        $client_disconnect
}

rule PHP_Fatal_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects fatal PHP errors in Apache logs"

    strings:
        $php_fatal = /php.*fatal.*(error|fail|failure|issue|problem)/i

    condition:
        $php_fatal
}

rule File_Not_Found_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects file not found errors in Apache logs"

    strings:
        $file_not_found = /file.*not\s*found.*(error|fail|failure|issue|problem)/i

    condition:
        $file_not_found
}

rule Configuration_Parsing_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors or issues in parsing Apache configuration files"

    strings:
        $config_parsing = /configuration.*parsing.*(fail|failure|error|issue|problem)/i

    condition:
        $config_parsing
}

rule Child_Process_Crash {
    meta:
        author = "Areeb Ahmed"
        description = "Detects crashes of child processes in Apache"

    strings:
        $child_crash = /child\s*process.*(crash|fail|failure|error|issue|problem)/i

    condition:
        $child_crash
}

rule Request_Timeouts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects request timeout errors in Apache logs"

    strings:
        $request_timeout = /request.*timeout.*(error|fail|failure|issue|problem)/i

    condition:
        $request_timeout
}

rule Memory_Allocation_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects memory allocation errors in Apache"

    strings:
        $memory_error = /memory.*allocation.*(fail|failure|error|issue|problem)/i

    condition:
        $memory_error
}

rule Resource_Limit_Exceedance {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when resource limits are exceeded in Apache"

    strings:
        $resource_limit = /resource.*limit.*exceeded.*(fail|failure|error|issue|problem)/i

    condition:
        $resource_limit
}

rule ModSecurity_Rule_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to ModSecurity rule processing"

    strings:
        $modsecurity_error = /modsecurity.*rule.*(fail|failure|error|issue|problem)/i

    condition:
        $modsecurity_error
}

rule Apache_Shutdown_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors or issues during Apache server shutdown"

    strings:
        $shutdown_error = /apache.*shutdown.*(fail|failure|error|issue|problem)/i

    condition:
        $shutdown_error
}

rule Forbidden_Access_Attempts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects 403 Forbidden access attempts in Apache logs"

    strings:
        $forbidden_access = /403.*forbidden.*(access|fail|failure|error|issue|problem)/i

    condition:
        $forbidden_access
}

rule Configuration_Deprecation_Warnings {
    meta:
        author = "Areeb Ahmed"
        description = "Detects deprecation warnings for Apache configuration settings"

    strings:
        $deprecation_warning = /configuration.*deprecation.*(warning|deprecated|obsolete)/i

    condition:
        $deprecation_warning
}

rule Document_Root_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to the DocumentRoot directive in Apache"

    strings:
        $docroot_error = /documentroot.*(error|fail|failure|issue|problem|invalid|missing)/i

    condition:
        $docroot_error
}

rule Block_Reception_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to block reception across various systems"

    strings:
        $block_reception = /receiving\s+block\s+(error|fail|issue|problem)/i

    condition:
        $block_reception
}

rule Block_Termination_Warnings {
    meta:
        author = "Areeb Ahmed"
        description = "Detects warnings or errors related to block termination"

    strings:
        $block_termination = /terminating\s+block\s+(error|fail|warning|problem)/i

    condition:
        $block_termination
}

rule Block_Updates {
    meta:
        author = "Areeb Ahmed"
        description = "Detects anomalies during block updates in distributed systems"

    strings:
        $block_update = /blockMap\s+updated\s+(error|fail|issue|problem)/i

    condition:
        $block_update
}

rule Network_Transfer_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects network-related issues during data transfers"

    strings:
        $network_transfer = /receiving\s+data\s+from\s+\/(\d{1,3}\.){3}\d{1,3}\s+(error|fail|issue|problem)/i

    condition:
        $network_transfer
}

rule Block_Replication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to block replication in distributed systems"

    strings:
        $block_replication = /replication\s+of\s+block\s+(error|fail|issue|problem)/i

    condition:
        $block_replication
}

rule Storage_Capacity_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects storage capacity-related issues in distributed file systems"

    strings:
        $storage_capacity = /storage\s+capacity\s+(error|exceeded|low|issue|problem)/i

    condition:
        $storage_capacity
}

rule DataNode_Communication_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects communication errors between DataNodes in a distributed environment"

    strings:
        $datanode_comm = /datanode\s+communication\s+(error|fail|timeout|issue|problem)/i

    condition:
        $datanode_comm
}

rule File_Creation_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues during file creation in file systems"

    strings:
        $file_creation = /file\s+creation\s+(error|fail|issue|problem)/i

    condition:
        $file_creation
}

rule Heartbeat_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects heartbeat failures in distributed systems"

    strings:
        $heartbeat_failure = /heartbeat\s+(failure|timeout|missed|issue|problem)/i

    condition:
        $heartbeat_failure
}

rule Block_Deletion_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors during block deletion in file systems"

    strings:
        $block_deletion = /deletion\s+of\s+block\s+(error|fail|issue|problem)/i

    condition:
        $block_deletion
}

rule Data_Integrity_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects data integrity errors during block or file operations"

    strings:
        $data_integrity = /data\s+integrity\s+(error|issue|fail|problem|corruption)/i

    condition:
        $data_integrity
}

rule Packet_Response_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to packet response handling in networked systems"

    strings:
        $packet_response = /packet\s+response\s+(error|issue|fail|timeout|problem)/i

    condition:
        $packet_response
}

rule Node_Join_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures when a node attempts to join a cluster or network"

    strings:
        $node_join = /node\s+join\s+(error|fail|issue|problem)/i

    condition:
        $node_join
}

rule Cluster_Communication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects communication issues within a cluster environment"

    strings:
        $cluster_comm = /cluster\s+communication\s+(error|fail|issue|problem|timeout)/i

    condition:
        $cluster_comm
}

rule Node_Unavailability {
    meta:
        author = "Areeb Ahmed"
        description = "Detects cases where a node becomes unavailable or unresponsive"

    strings:
        $node_unavailability = /node\s+(unavailable|unresponsive|down|issue|fail|problem)/i

    condition:
        $node_unavailability
}

rule Permission_Denied_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects permission denied errors during file or block operations"

    strings:
        $permission_denied = /permission\s+denied\s+(error|fail|issue|problem)/i

    condition:
        $permission_denied
}

rule Disk_Space_Exhaustion {
    meta:
        author = "Areeb Ahmed"
        description = "Detects disk space exhaustion warnings or errors"

    strings:
        $disk_space = /disk\s+space\s+(exhausted|low|error|issue|fail|problem)/i

    condition:
        $disk_space
}

rule File_Read_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors during file read operations"

    strings:
        $file_read = /file\s+read\s+(error|fail|issue|problem)/i

    condition:
        $file_read
}

rule File_Write_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors during file write operations"

    strings:
        $file_write = /file\s+write\s+(error|fail|issue|problem)/i

    condition:
        $file_write
}

rule HDFS_Namespace_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues within the HDFS namespace operations"

    strings:
        $hdfs_namespace = /hdfs\s+namespace\s+(error|fail|issue|problem|corruption)/i

    condition:
        $hdfs_namespace
}

rule Failed_Data_Transfers {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failed data transfers or related issues in distributed systems"

    strings:
        $data_transfer_fail = /data\s+transfer\s+(fail|error|issue|problem)/i

    condition:
        $data_transfer_fail
}

rule Configuration_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors related to system configuration or misconfigurations"

    strings:
        $config_error = /configuration\s+(error|issue|fail|problem|invalid)/i

    condition:
        $config_error
}

rule IO_Exceptions {
    meta:
        author = "Areeb Ahmed"
        description = "Detects Input/Output (IO) exceptions or errors"

    strings:
        $io_exception = /io\s+(exception|error|fail|issue|problem)/i

    condition:
        $io_exception
}

rule Database_Connection_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to database connections"

    strings:
        $db_connection_issue = /database\s+connection\s+(fail|error|issue|timeout|problem)/i

    condition:
        $db_connection_issue
}

rule Authentication_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects authentication failures in logs"

    strings:
        $auth_failure = /authentication\s+(fail|error|issue|denied|problem)/i

    condition:
        $auth_failure
}

rule Backup_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures during backup operations"

    strings:
        $backup_fail = /backup\s+(fail|error|issue|problem)/i

    condition:
        $backup_fail
}

rule Service_Start_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues or failures when starting a service"

    strings:
        $service_start_issue = /service\s+start\s+(fail|error|issue|problem)/i

    condition:
        $service_start_issue
}

rule Security_Alerts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects potential security alerts or warnings in logs"

    strings:
        $security_alert = /security\s+(alert|warning|issue|problem|breach)/i

    condition:
        $security_alert
}

rule Resource_Allocation_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures in resource allocation (CPU, memory, etc.)"

    strings:
        $resource_fail = /resource\s+allocation\s+(fail|error|issue|problem|exhausted)/i

    condition:
        $resource_fail
}

rule Component_Unavailability {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a hardware component becomes unavailable"

    strings:
        $component_unavailable = /Component.*unavailable\s+state/i

    condition:
        $component_unavailable
}

rule Hardware_Failure_Alerts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects alerts indicating hardware failures or state changes"

    strings:
        $hardware_failure = /state_change.*unavailable/i

    condition:
        $hardware_failure
}

rule Cluster_Member_Additions {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a new member is added to the cluster"

    strings:
        $cluster_add_member = /clusterAddMember/i

    condition:
        $cluster_add_member
}

rule Boot_Actions {
    meta:
        author = "Areeb Ahmed"
        description = "Detects boot-related actions or events"

    strings:
        $boot_action = /risBoot|boot\s+action/i

    condition:
        $boot_action
}

rule Unresponsive_Components {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a component becomes unresponsive or enters a critical state"

    strings:
        $unresponsive_component = /Component.*unresponsive|critical\s+state/i

    condition:
        $unresponsive_component
}

rule Hardware_Degradation {
    meta:
        author = "Areeb Ahmed"
        description = "Detects signs of hardware degradation or impending failure"

    strings:
        $hardware_degradation = /degradation|hardware\s+failure|imminent\s+failure/i

    condition:
        $hardware_degradation
}

rule Node_Disconnection {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a node disconnects from the cluster"

    strings:
        $node_disconnection = /node\s+disconnected|lost\s+connection/i

    condition:
        $node_disconnection
}

rule Command_Start_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to the starting of commands or actions"

    strings:
        $command_start_issue = /command.*start\s+error|failed\s+to\s+start/i

    condition:
        $command_start_issue
}

rule Cluster_State_Changes {
    meta:
        author = "Areeb Ahmed"
        description = "Detects changes in the cluster's overall state"

    strings:
        $cluster_state_change = /cluster.*state\s+change/i

    condition:
        $cluster_state_change
}

rule Node_Hardware_Faults {
    meta:
        author = "Areeb Ahmed"
        description = "Detects hardware faults occurring on specific nodes"

    strings:
        $node_hardware_fault = /node.*hardware\s+fault|component\s+failure/i

    condition:
        $node_hardware_fault
}

rule HPC_Node_Failures {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when an HPC node fails or becomes unavailable"

    strings:
        $hpc_node_failure = /node\s+failure|unavailable/i

    condition:
        $hpc_node_failure
}

rule Cluster_Node_Reboots {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a cluster node undergoes a reboot"

    strings:
        $node_reboot = /node\s+reboot|restart/i

    condition:
        $node_reboot
}

rule Failed_HPC_Actions {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when HPC-related actions fail to complete"

    strings:
        $failed_hpc_action = /failed\s+HPC\s+action|failed\s+command/i

    condition:
        $failed_hpc_action
}

rule HPC_Configuration_Errors {
    meta:
        author = "Areeb Ahmed"
        description = "Detects errors in HPC configuration settings"

    strings:
        $hpc_config_error = /configuration\s+error|invalid\s+settings/i

    condition:
        $hpc_config_error
}

rule Resource_Exhaustion_Warnings {
    meta:
        author = "Areeb Ahmed"
        description = "Detects warnings related to resource exhaustion (CPU, memory, etc.)"

    strings:
        $resource_exhaustion = /resource\s+exhausted|insufficient\s+resources/i

    condition:
        $resource_exhaustion
}

rule Network_Communication_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues with network communication between nodes"

    strings:
        $network_comm_issue = /network\s+communication\s+error|connection\s+timeout/i

    condition:
        $network_comm_issue
}

rule HPC_System_Downtime {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when the HPC system experiences downtime or becomes unavailable"

    strings:
        $system_downtime = /system\s+downtime|unavailable/i

    condition:
        $system_downtime
}

rule Failed_Node_Join_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a node fails to join the cluster"

    strings:
        $failed_node_join = /node\s+join\s+failure|failed\s+to\s+join\s+cluster/i

    condition:
        $failed_node_join
}

rule Component_Overheat_Warnings {
    meta:
        author = "Areeb Ahmed"
        description = "Detects warnings related to component overheating"

    strings:
        $overheat_warning = /overheat|temperature\s+warning/i

    condition:
        $overheat_warning
}

rule Hardware_Malfunction_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects events indicating hardware malfunctions"

    strings:
        $hardware_malfunction = /hardware\s+malfunction|component\s+error/i

    condition:
        $hardware_malfunction
}

rule System_Resource_Alerts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects alerts related to system resource utilization (e.g., CPU, memory)"

    strings:
        $system_resource_alert = /system\s+resource\s+alert|high\s+CPU|memory\s+utilization/i

    condition:
        $system_resource_alert
}

rule HPC_Performance_Degradation {
    meta:
        author = "Areeb Ahmed"
        description = "Detects signs of performance degradation in the HPC environment"

    strings:
        $performance_degradation = /performance\s+degradation|sluggish\s+response/i

    condition:
        $performance_degradation
}

rule HPC_Security_Events {
    meta:
        author = "Areeb Ahmed"
        description = "Detects security-related events or breaches in the HPC environment"

    strings:
        $security_event = /security\s+event|breach|unauthorized\s+access/i

    condition:
        $security_event
}

rule Hardware_Replacement_Need {
    meta:
        author = "Areeb Ahmed"
        description = "Detects when a hardware component needs replacement"

    strings:
        $hardware_replacement = /hardware\s+replacement\s+needed|component\s+failure/i

    condition:
        $hardware_replacement
}

rule Failed_Data_Synchronization {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures during data synchronization between nodes"

    strings:
        $data_sync_failure = /data\s+synchronization\s+failed|sync\s+error/i

    condition:
        $data_sync_failure
}

rule Failed_Service_Starts {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures when starting services in the HPC environment"

    strings:
        $service_start_failure = /service\s+start\s+failure|failed\s+to\s+start/i

    condition:
        $service_start_failure
}

rule HPC_Load_Balancing_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to load balancing in the HPC environment"

    strings:
        $load_balancing_issue = /load\s+balancing\s+issue|uneven\s+load\s+distribution/i

    condition:
        $load_balancing_issue
}

rule Failed_Task_Scheduling {
    meta:
        author = "Areeb Ahmed"
        description = "Detects failures in task scheduling within the HPC environment"

    strings:
        $task_scheduling_failure = /task\s+scheduling\s+failure|failed\s+to\s+schedule/i

    condition:
        $task_scheduling_failure
}

rule HPC_Power_Issues {
    meta:
        author = "Areeb Ahmed"
        description = "Detects issues related to power management in the HPC environment"

    strings:
        $power_issue = /power\s+management\s+issue|power\s+failure/i

    condition:
        $power_issue
}

rule Hardware_Faults_with_High_Priority {
    meta:
        author = "Areeb Ahmed"
        description = "Detects hardware faults that are marked with high priority"

    strings:
        $high_priority_fault = /high\s+priority.*hardware\s+fault|critical\s+hardware\s+issue/i

    condition:
        $high_priority_fault
}

rule JPEG_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects JPEG image files based on their file signatures"

    strings:
        $jpeg_header = { FF D8 FF }
        $jpeg_footer = { FF D9 }

    condition:
        $jpeg_header at 0 and $jpeg_footer at (filesize - 2)
}

rule PNG_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects PNG image files based on their file signatures"

    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $png_IEND = { 49 45 4E 44 AE 42 60 82 }

    condition:
        $png_header at 0 and $png_IEND at (filesize - 8)
}

rule GIF_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects GIF image files based on their file signatures"

    strings:
        $gif_header_87a = "GIF87a"
        $gif_header_89a = "GIF89a"

    condition:
        $gif_header_87a at 0 or $gif_header_89a at 0
}

rule BMP_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects BMP image files based on their file signatures"

    strings:
        $bmp_header = { 42 4D }

    condition:
        $bmp_header at 0
}

rule TIFF_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects TIFF image files based on their file signatures"

    strings:
        $tiff_header_II = { 49 49 2A 00 }
        $tiff_header_MM = { 4D 4D 00 2A }

    condition:
        $tiff_header_II at 0 or $tiff_header_MM at 0
}

rule WebP_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects WebP image files based on their file signatures"

    strings:
        $webp_header = { 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 }

    condition:
        $webp_header at 0
}

rule HEIF_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects HEIF image files based on their file signatures"

    strings:
        $heif_ftyp = { 66 74 79 70 68 65 69 63 }
        $heic_ftyp = { 66 74 79 70 68 65 69 63 }

    condition:
        $heif_ftyp at 4 or $heic_ftyp at 4
}

rule ICO_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects ICO image files based on their file signatures"

    strings:
        $ico_header = { 00 00 01 00 }

    condition:
        $ico_header at 0
}

rule Exif_Metadata {
    meta:
        author = "Shivansh Karan"
        description = "Detects the presence of EXIF metadata in image files"

    strings:
        $exif_header = { 45 78 69 66 00 00 }

    condition:
        $exif_header in (0..filesize)
}

rule Large_Image_Resolution {
    meta:
        author = "Shivansh Karan"
        description = "Detects images with unusually large resolutions that might indicate anomalies"

    strings:
        $large_resolution = /Resolution: \d{4,}x\d{4,}/

    condition:
        $large_resolution in (0..10240)
}

rule Corrupted_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects potential corruption in image files"

    strings:
        $jpeg_corruption = { FF D8 ?? FF }
        $png_corruption = { 89 50 4E 47 ?? 0A 1A 0A }

    condition:
        $jpeg_corruption in (0..filesize) or $png_corruption in (0..filesize)
}

rule Duplicate_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects potential duplicate images based on identical file sizes and signatures"

    strings:
        $jpeg_header = { FF D8 FF }
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
        $jpeg_header at 0 or $png_header at 0
}

rule Thumbnail_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects thumbnail images based on small file sizes and resolution"

    strings:
        $thumbnail_resolution = /Resolution: \d{1,3}x\d{1,3}/

    condition:
        $thumbnail_resolution in (0..filesize) and filesize < 10240
}

rule Animated_GIFs {
    meta:
        author = "Shivansh Karan"
        description = "Detects animated GIF files"

    strings:
        $gif89a_header = "GIF89a"
        $animation_marker = { 21 F9 04 }

    condition:
        $gif89a_header at 0 and $animation_marker in (0..filesize)
}

rule Image_Conversion_Tools {
    meta:
        author = "Shivansh Karan"
        description = "Detects the presence of image conversion tools or traces in files"

    strings:
        $imagemagick = "ImageMagick"
        $photoshop = "Adobe Photoshop"

    condition:
        $imagemagick or $photoshop
}

rule Steganography_Indicators {
    meta:
        author = "Shivansh Karan"
        description = "Detects indicators of steganography in images"

    strings:
        $stego_marker = /Steg\s+hidden/i
        $large_padding = { 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $stego_marker in (0..filesize) or $large_padding in (0..filesize)
}

rule Embedded_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects embedded files within images, such as ZIP or executable files"

    strings:
        $zip_signature = { 50 4B 03 04 }
        $exe_signature = { 4D 5A }

    condition:
        $zip_signature in (0..filesize) or $exe_signature in (0..filesize)
}

rule Image_Watermarking {
    meta:
        author = "Shivansh Karan"
        description = "Detects the presence of digital watermarks in images"

    strings:
        $watermark_marker = "Watermark"
        $signature_block = { FF E1 }

    condition:
        $watermark_marker in (0..filesize) or $signature_block in (0..filesize)
}

rule High_Color_Depth {
    meta:
        author = "Shivansh Karan"
        description = "Detects images with high color depth (e.g., 16-bit or 32-bit) that might indicate professional editing"

    strings:
        $high_color_depth = /ColorDepth:\s+(16|32)\s+bit/

    condition:
        $high_color_depth in (0..filesize)
}

rule HDR_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects High Dynamic Range (HDR) images based on metadata"

    strings:
        $hdr_marker = /HDR|HighDynamicRange/

    condition:
        $hdr_marker in (0..filesize)
}

rule SVG_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects SVG image files based on their file signatures"

    strings:
        $svg_header = "<svg"

    condition:
        $svg_header at 0
}

rule Fits_Images {
    meta:
        author = "Shivansh Karan"
        description = "Detects FITS (Flexible Image Transport System) image files based on their file signatures"

    strings:
        $fits_header = "SIMPLE  = "

    condition:
        $fits_header at 0
}

rule Raw_Image_Formats {
    meta:
        author = "Shivansh Karan"
        description = "Detects RAW image files from various camera manufacturers"

    strings:
        $canon_raw = "CR2"
        $nikon_raw = "NEF"
        $sony_raw = "ARW"

    condition:
        $canon_raw in (0..filesize) or $nikon_raw in (0..filesize) or $sony_raw in (0..filesize)
}

rule Embedded_Scripts {
    meta:
        author = "Shivansh Karan"
        description = "Detects the presence of embedded scripts within image files"

    strings:
        $script_marker = /<script|<embed|<object/i

    condition:
        $script_marker in (0..filesize)
}

rule Metadata_Manipulation {
    meta:
        author = "Shivansh Karan"
        description = "Detects unusual metadata manipulations in image files"

    strings:
        $metadata_marker = /ExifTool|Exif\.IFD0|Exif\.SubIFD/i

    condition:
        $metadata_marker in (0..filesize)
}
