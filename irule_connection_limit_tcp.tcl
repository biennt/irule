when RULE_INIT { 
    set static::maxcon 99
    set static::lifetime 2
    set static::blocktime 10
}
when CLIENT_ACCEPTED {
    set ipclient [IP::client_addr]
    if { [set conCount [table incr -mustexist "$ipclient"]] ne "" } {
        #log local0.info "clientip=$ipclient conCount=$conCount"
        if { $conCount > $static::maxcon } then {
            log local0. "too many connections from $ipclient"
            drop
        } 
    } else {
        table set "$ipclient" $static::lifetime indef $static::blocktime
    }
}
