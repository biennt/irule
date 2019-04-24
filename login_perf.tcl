when RULE_INIT {
    # maxTimeout (milisecond)
    set static::maxTimeout 3000
    # maxPeak (time: 2,3.. 10)
    set static::maxPeak 5
}

when HTTP_REQUEST {
	if {[HTTP::uri] starts_with "/handler/CheckLogin.aspx"} {
		set inspect 1
		set reqTime [clock clicks -milliseconds]
	} else { set inspect 0 }
}

when HTTP_RESPONSE {
	if {$inspect == 1} {
	    set hsl [HSL::open -proto UDP -pool splunkpool]
	    set repTime [clock clicks -milliseconds]
	    set processedTime [expr $repTime - $reqTime]
	    set lastAvg [table lookup -notouch -subtable logintime avgTime]
	    if {$lastAvg eq ""} {
	        table set -subtable logintime avgTime $processedTime
	        set lastAvg $processedTime
	    } else {
	        table set -subtable logintime avgTime [expr ($processedTime + $lastAvg)/2]
	    }
	    if {$processedTime > $static::maxTimeout} {
	        log local0.info "LOGIN-REP-MAXTIMEOUT: $static::maxTimeout | ProTime: $processedTime | avgTime: $lastAvg | clientip: [IP::client_addr]"
	        HSL::send $hsl "LOGIN-REP-MAXTIMEOUT: $static::maxTimeout | ProTime: $processedTime | avgTime: $lastAvg | clientip: [IP::client_addr]\n"
	    } else {
	        if {[expr $processedTime / $lastAvg] > $static::maxPeak} {
   		        log local0.info "LOGIN-REP-PEAK: $static::maxPeak | ProTime: $processedTime | avgTime: $lastAvg | clientip: [IP::client_addr]"
   		        HSL::send $hsl "LOGIN-REP-PEAK: $static::maxPeak | ProTime: $processedTime | avgTime: $lastAvg | clientip: [IP::client_addr]\n"
	        } else {
	            log local0.info "LOGIN-REP-NORMAL: ProTime: $processedTime | avgTime: $lastAvg | clientip: [IP::client_addr]"
	            HSL::send $hsl "LOGIN-REP-NORMAL: ProTime: $processedTime | avgTime: $lastAvg | clientip: [IP::client_addr]\n"
	        }
	    }
    }
}
