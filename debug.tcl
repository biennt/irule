when CLIENT_ACCEPTED {
    set uid [createGuid]
}

when HTTP_REQUEST {
    if { [HTTP::method] eq "POST" } {
        HTTP::collect [HTTP::header "Content-Length"]
    }

    log local0. "{\"_TIMESTAMP\":\"[clock clicks -milliseconds]\",\"uid\":\"$uid\",\"HTTP_method\":\"[HTTP::method]\",\"HTTP_host\":\"[HTTP::host]\",\"TCP_local_port\":\"[TCP::local_port]\",\"HTTP_uri\":\"[HTTP::uri]\",\"IP_client_addr\":\"[IP::client_addr]\",\"HTTP_request\":\"[string map {{"} {\"} } [HTTP::request]]\",\"SSL_cipher_name\":\"[SSL::cipher name]\",\"SSL_cipher_version\":\"[SSL::cipher version]\",\"SSL_cipher_bits\":\"[SSL::cipher bits]\",\"SSL_secure_renegotiation\":\"[SSL::secure_renegotiation]\",\"virtual_name\":\"[virtual name]\",\"LB_server_addr\":\"[LB::server addr]\"}"
}

when HTTP_REQUEST_DATA {
    set HTTP_payload [string map {{"} {\"} } [HTTP::payload]]
    if { $HTTP_payload contains "Password=" } {
        regsub -- "(.*Password=).*?(&.*)" $HTTP_payload "\\1XXXXXXXX\\2" HTTP_payload_redacted
        set HTTP_payload $HTTP_payload_redacted
    }
    log local0. "{\"_TIMESTAMP\":\"[clock clicks -milliseconds]\",\"uid\":\"$uid\",\"HTTP_method\":\"[HTTP::method]\",\"HTTP_host\":\"[HTTP::host]\",\"TCP_local_port\":\"[TCP::local_port]\",\"HTTP_uri\":\"[HTTP::uri]\",\"HTTP_payload\":\"$HTTP_payload\"}"
}

when HTTP_RESPONSE {
    log local0. "{\"_TIMESTAMP\":\"[clock clicks -milliseconds]\",\"uid\":\"$uid\",\"HTTP_method\":\"[HTTP::method]\",\"HTTP_host\":\"[HTTP::host]\",\"TCP_local_port\":\"[TCP::local_port]\",\"HTTP_uri\":\"[HTTP::uri]\",\"IP_client_addr\":\"[IP::client_addr]\",\"selectedpoolMember\":\"[LB::server]\",\"HTTP_request\":\"[string map {{"} {\"} } [HTTP::request]]\",\"SSL_cipher_name\":\"[SSL::cipher name]\",\"SSL_cipher_version\":\"[SSL::cipher version]\",\"SSL_cipher_bits\":\"[SSL::cipher bits]\",\"SSL_secure_renegotiation\":\"[SSL::secure_renegotiation]\",\"virtual_name\":\"[virtual name]\",\"LB_server_addr\":\"[LB::server addr]\"}"
}

proc createGuid {} {
    set s [md5 [string cat [clock seconds] [IP::local_addr] [IP::client_addr] [expr { int(100000000 * rand()) }] [clock clicks]]]
    binary scan $s c* s
    lset s 8 [expr {([lindex $s 8] & 0x7F) | 0x40}]
    lset s 6 [expr {([lindex $s 6] & 0x0F) | 0x40}]
    binary scan $s H* s
    return [format "%s-%s-%s-%s-%s" [string range $s 0 7] [string range $s 8 11] [string range $s 12 15] [string range $s 16 19] [string range $s 20 31]]
}
