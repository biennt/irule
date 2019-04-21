when HTTP_REQUEST {
    if { ([HTTP::method] eq "POST") } {
        HTTP::collect [HTTP::header Content-Length]
    }
}

when HTTP_REQUEST_DATA {
    set decoded [decode_uri [HTTP::payload]]
    set ini [string first "\"idTerminal\"" $decoded]
    if { $ini != -1 } {
        set end [string first "," $decoded $ini]
        set value [string range $decoded $ini [expr {$end-1}]]
        set idTerminal [lindex [split $value ":"] 1]

        switch -exact $idTerminal {
            678 -
            679 {
                pool terminal_67x_pool
            }
            default {
                pool default_pool
            }
        }
    }
}