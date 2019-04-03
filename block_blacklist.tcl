if { [class match [IP::remote_addr] equals ip_blacklist] } { 
    reject
    event disable all
    return
}
