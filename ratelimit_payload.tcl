when RULE_INIT { 
    set static::maxRate 1
    set static::timeout 5
}
when HTTP_REQUEST {
	if {[HTTP::uri] starts_with "/mapi/g/"} {
		set inspect 1
		HTTP::collect 200
	}
}
when HTTP_REQUEST_DATA {
	if {$inspect == 1} {
	    set payload [HTTP::payload 200]
	    set search_type [findstr $payload SEARCH]
	    set sessionstr [findstr $payload session 10 \"]
	    if {[string length $search_type]} {
	        #log local0. "PAYLOAD|$payload"
	        #log local0. "SESSION|$sessionstr"
	        if { [set methodCount [table incr -mustexist "$sessionstr"]] ne "" } then {
                if { $methodCount > $static::maxRate } then {
                    log local0. "LIMIT too many search actions from $sessionstr"
                    HTTP::respond 200 content "{}"
                    return
                }   
                } else {
                    table set "$sessionstr" 1 indef $static::timeout
                }
	    }
	    HTTP::release
    }
}
