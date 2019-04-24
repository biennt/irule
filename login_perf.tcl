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
	        log local0.info "LOGIN-REP-MAXTIMEOUT: $static::maxTimeout | $processedTime | Last avgTime: $lastAvg | clientip: [IP::client_addr]"
	    } else {
	        if {[expr $processedTime / $lastAvg] > $static::maxPeak} {
   		        log local0.info "LOGIN-REP-PEAK: process time: $processedTime | Last avgTime: $lastAvg | clientip: [IP::client_addr]"
	        } else {
	            log local0.info "LOGIN-REP-NORMAL: process time: $processedTime | Last avgTime: $lastAvg | clientip: [IP::client_addr]"
	        }
	    }
    }
}
