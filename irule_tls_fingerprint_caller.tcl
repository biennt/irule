when CLIENT_ACCEPTED {
    ## Collect the TCP payload
    TCP::collect
}
when CLIENT_DATA {
    ## Get the TLS packet type and versions
    if { ! [info exists rlen] } {
        binary scan [TCP::payload] cH4ScH6H4 rtype outer_sslver rlen hs_type rilen inner_sslver
        
        if { ( ${rtype} == 22 ) and ( ${hs_type} == 1 ) } {
            ## This is a TLS ClientHello message (22 = TLS handshake, 1 = ClientHello)
            
            ## Call the fingerprintTLS proc
            set fingerprint [call Library-Rule::fingerprintTLS [TCP::payload] ${rlen} ${outer_sslver} ${inner_sslver} [IP::client_addr] [IP::local_addr]]
    
            log local0. "fp = ${fingerprint}"

        }
    }
    
    # Collect the rest of the record if necessary
    if { [TCP::payload length] < $rlen } {
        TCP::collect $rlen
    }
    
    ## Release the paylaod
    TCP::release
}
