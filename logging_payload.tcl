when HTTP_REQUEST {
   set inspect_login 0
   set inspect_core 0
 
   set reqTime [clock format [clock seconds] -format "%d/%m/%Y %H:%M:%S"]
   
     if {[HTTP::uri] starts_with "/handler/CheckLogin.aspx"} {
		set inspect_login 1
		HTTP::collect 100
	 }
     if {[HTTP::uri] starts_with "/handler/core.vpbs"} {
		set inspect_core 1
		HTTP::collect 200
	 }
	 set logstring "<190>|$reqTime|F5_VE|[IP::client_addr]|[TCP::remote_port]|[IP::local_addr]|[TCP::local_port]|[HTTP::method]|[HTTP::uri]|[HTTP::header User-Agent]"
   if { ($inspect_core == 0) && ($inspect_login == 0) } {
        set hsl [HSL::open -proto UDP -pool splunk_pool]
        HSL::send $hsl $logstring
        #log local0.info $logstring
   }
}
when HTTP_REQUEST_DATA {
    if {$inspect_login == 1} {
        set payload [HTTP::payload 100]
        set paramlist [split $payload "&"]
        set userstring [lindex $paramlist 0]
        set channelstring [lindex $paramlist 2]
        set userlist [split $userstring "="]
        set user [lindex $userlist 1]
        set channellist [split $channelstring "="]
        set channel [lindex $channellist 1]      
        set logstring "$logstring|$user|$channel"
        set hsl [HSL::open -proto UDP -pool splunk_pool]
        HSL::send $hsl $logstring
        #log local0.info $logstring
    }
    
    if {$inspect_core == 1} {
        set payload [HTTP::payload 200]
        set sessionstr [findstr $payload session 10 \"]
        set userstr [findstr $payload user 7 \"]
        set cmdstr [findstr $payload cmd 6 \"]
        set cstr [findstr $payload \"c\": 5 \"]
        set logstring "$logstring|$userstr|$sessionstr|$cmdstr|$cstr|$payload"
        set hsl [HSL::open -proto UDP -pool splunk_pool]
        HSL::send $hsl $logstring
        #log local0.info $logstring
    }
    HTTP::release
}
