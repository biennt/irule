when RULE_INIT { 
    set static::maxRate 100
    set static::timeout 10
}

when HTTP_REQUEST {
    if {[HTTP::uri] starts_with "/mapi/login"} {
        set session_login "[IP::client_addr]|[HTTP::header User-Agent]"
        set hashval [b64encode [CRYPTO::hash -alg sha1 $session_login]]
        if { [set methodCount [table incr -mustexist "$hashval"]] ne "" } then {
                if { $methodCount > $static::maxRate } then {
                    log local0. "$session_login - $hashval exceeded max login requests per second"
                    HTTP::respond 200 content "{}"
                    return
                }   
                } else {
                    table set "$hashval" 1 indef $static::timeout
                }
                log local0. "$session_login - $hashval: methodCount=$methodCount"
            }
}
