when RULE_INIT {
    set static::sni_routing_debug 0
}
 
when CLIENT_ACCEPTED {
    if { [PROFILE::exists clientssl] } {
        # We have a clientssl profile attached to this VIP but we need
        # to find an SNI record in the client handshake. To do so, we'll
        # disable SSL processing and collect the initial TCP payload.
        set ssldisable "SSL::disable"
        set sslenable "SSL::enable"
        eval $ssldisable
    }                
    TCP::collect
    set default_pool [LB::server pool]
    set tls_servername ""
    set tls_handshake_prefered_version "0000"
}
when CLIENT_DATA {
    # Store TCP Payload up to 2^14 + 5 bytes (Handshake length is up to 2^14)
    set payload [TCP::payload 16389]
    set payloadlen [TCP::payload length]
    
    # - Record layer content-type     (1 byte) --> variable tls_record_content_type
    #    Handshake value is 22 (required for CLIENT_HELLO packet)
    # - SSLv3 / TLS version. (2 byte)  --> variable tls_version
    #    SSLv3 value is 0x0300 (doesn't support SNI, not valid in first condition)
    #    TLS_1.0 value is 0x0301
    #    TLS_1.1 value is 0x0302, 0x0301 in CLIENT_HELLO handskake packet for backward compatibility (not specified in RFC, that's why the value 0x0302 is allowed in condition)
    #    TLS_1.2 value is 0x0303, 0x0301 in CLIENT_HELLO handskake packet for backward compatibility (not specified in RFC, that's why the value 0x0303 is allowed in condition)
    #    TLS_1.3 value is 0x0304, 0x0301 in CLIENT_HELLO handskake packet for backward compatibility (explicitly specified in RFC)
    #    TLS_1.3 drafts values are 0x7FXX (XX is the hexadecimal encoded draft version), 0x0301 in CLIENT_HELLO handskake packet for backward compatibility (explicitly specified in RFC)
    # - Record layer content length (2 bytes) : must match payload length --> variable tls_recordlen
    # - TLS Hanshake protocol (length defined by Record layer content length value)
    #       - Handshake action (1 byte) : CLIENT_HELLO = 1 --> variable tls_handshake_action
    #       - handshake length  (3 bytes)
    #       -  SSL / TLS handshake version (2 byte)
    #           In TLS 1.3 CLIENT_HELLO handskake packet, TLS hanshake version is sent whith 0303 (TLS 1.2) version for backward compatibility. a new TLS extension add version negociation.
    #       - hanshake random (32 bytes)
    #       - handshake sessionID length (1 byte) --> variable tls_handshake_sessidlen
    #       - handshake sessionID (length defined by sessionID length value, max 32-bit)
    #       - CipherSuites length (2 bytes) --> variable tls_ciphlen
    #       - CipherSuites (length defined by CipherSuites length value)
    #       - Compression length (2 bytes) --> variable tls_complen
    #       - Compression methods (length defined by Compression length value)
    #       - Extensions 
    #           - Extension length (2 bytes)  --> variable tls_extension_length
    #           - list of Extensions records (length defined by extension length value)
    #               - extension record type (2 bytes) : server_name = 0, supported_versions = 43--> variable tls_extension_type
    #               - extension record length (2 bytes) --> variable tls_extension_record_length
    #               - extension data (length defined by extension record length value)
    #
    #   TLS server_name extension data format:
    #       - SNI record length (2 bytes)
    #       - SNI record data (length defined by SNI record length value)
    #           - SNI record type (1 byte)
    #           - SNI record value length (2 bytes)
    #           - SNI record value (length defined by SNI record value length value) --> variable tls_servername
    #
    #   TLS supported_version extension data format (added in TLS 1.3):
    #       -  supported version length (1 bytes) --> variable tls_supported_versions_length
    #       - List of supported versions (2 bytes per version) --> variable tls_supported_versions
 
 
 
    # If valid TLS 1.X CLIENT_HELLO handshake packet
    if { [binary scan $payload cH4Scx3H4x32c tls_record_content_type tls_version tls_recordlen tls_handshake_action tls_handshake_version tls_handshake_sessidlen] == 6 && \
        ($tls_record_content_type == 22) && \
        ([string match {030[1-3]} $tls_version]) && \
        ($tls_handshake_action == 1) && \
        ($payloadlen == $tls_recordlen+5)} {
 
        # store in a variable the handshake version
        set tls_handshake_prefered_version $tls_handshake_version
 
        # skip past the session id
        set record_offset [expr {44 + $tls_handshake_sessidlen}]
 
        # skip past the cipher list
        binary scan $payload @${record_offset}S tls_ciphlen
        set record_offset [expr {$record_offset + 2 + $tls_ciphlen}]
 
        # skip past the compression list
        binary scan $payload @${record_offset}c tls_complen
        set record_offset [expr {$record_offset + 1 + $tls_complen}]
 
        # check for the existence of ssl extensions
        if { ($payloadlen > $record_offset) } {
            # skip to the start of the first extension
            binary scan $payload @${record_offset}S tls_extension_length
            set record_offset [expr {$record_offset + 2}]
            # Check if extension length + offset equals payload length
            if {$record_offset + $tls_extension_length == $payloadlen} {
                # for each extension
                while { $record_offset < $payloadlen } {
                    binary scan $payload @${record_offset}SS tls_extension_type tls_extension_record_length
                    if { $tls_extension_type == 0 } {
                        # if it's a servername extension read the servername
                        # SNI record value start after extension type (2 bytes), extension record length (2 bytes), record type (2 bytes), record type (1 byte), record value length (2 bytes) = 9 bytes
                        binary scan $payload @[expr {$record_offset + 9}]A[expr {$tls_extension_record_length - 5}] tls_servername
                        set record_offset [expr {$record_offset + $tls_extension_record_length + 4}]
                        
                    } elseif { $tls_extension_type == 43 } {
                        # if it's a supported_version extension (starting with TLS 1.3), extract supported version in a list
                        binary scan $payload @[expr {${record_offset} + 4}]cS[expr {($tls_extension_record_length -1)/2}] tls_supported_versions_length tls_supported_versions
                        set tls_handshake_prefered_version [list]
                        foreach version $tls_supported_versions {
                            lappend tls_handshake_prefered_version [format %04X [expr { $version & 0xffff }] ]
                        }
                        if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : prefered version list : $tls_handshake_prefered_version"}
                        set record_offset [expr {$record_offset + $tls_extension_record_length + 4}]
                    } else {
                        # skip over other extensions
                        set record_offset [expr {$record_offset + $tls_extension_record_length + 4}]
                    }
                }
            }
        }
    } elseif { [binary scan $payload cH4 ssl_record_content_type ssl_version] == 2 && \
        ($tls_record_content_type == 22) && \
        ($tls_version == 0300)} {
        # SSLv3 detected
        set tls_handshake_prefered_version "0300"
    } elseif { [binary scan $payload H2x1H2 ssl_version handshake_protocol_message] == 2 && \
        ($ssl_version == 80) && \
        ($handshake_protocol_message == 01)} {
            # SSLv2 detected
            set tls_handshake_prefered_version "0200"
        }
    unset -nocomplain payload payloadlen tls_record_content_type tls_recordlen tls_handshake_action tls_handshake_sessidlen record_offset tls_ciphlen tls_complen tls_extension_length tls_extension_type tls_extension_record_length tls_supported_versions_length tls_supported_versions
 
    foreach version $tls_handshake_prefered_version {
        switch -glob -- $version {
            "0200" {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : SSLv2 ; connection is rejected"}
                reject
                return
            }
            "0300" -
            "0301" {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : SSL/TLS ; connection is rejected (0x$version)"}
                    # Handshake Failure packet format:
                    #
                    # - Record layer content-type     (1 byte) --> variable tls_record_content_type
                    #    Alert value is 21 (required for Handshake Failure packet)
                    # - SSLv3 / TLS version. (2 bytes)  --> from variable tls_version
                    # - Record layer content length (2 bytes) : value is 2 for Alert message
                    # - TLS Message (length defined by Record layer content length value)
                    #       - Level (1 byte) : value is 2 (fatal)
                    #       - Description (1 bytes) : value is 40 (Handshake Failure)
                TCP::respond [binary format cH4Scc 21 $tls_version 2 2 40]
                after 10
                TCP::close
                #drop
                #reject
                return
            }
            "030[2-9]" -
            "7F[0-9A-F][0-9A-F]" {
                # TLS version allowed, do nothing
                break
            }
            "0000" {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : No SSL/TLS protocol detected ; connection is rejected (0x$version)"}
                reject
                return
            }
            default {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : Unknown CLIENT_HELLO TLS handshake prefered version : 0x$version"}
            }
        }
    }
 
    if { $tls_servername equals "" || ([set sni_dg_value [class match -value [string tolower $tls_servername] equals tls_servername_routing_dg]] equals "")} {
        set sni_dg_value [class match -value "default" equals tls_servername_routing_dg]
    }
 
    switch [lindex $sni_dg_value 0] {
        "virtual" {
            if {[catch {virtual [lindex $sni_dg_value 1]}]} {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; Virtual server [lindex $sni_dg_value 1] doesn't exist"}
            } else {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; forwarded to Virtual server [lindex $sni_dg_value 1]"}
            }
        }
        "pool" {
            if {[catch {pool [lindex $sni_dg_value 1]}]} {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; Pool [lindex $sni_dg_value 1] doesn't exist"}
            } else {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; forwarded to Pool [lindex $sni_dg_value 1]"}
            }
            if {[lindex $sni_dg_value 2] equals "ssl_offload" && [info exists sslenable]} {
                eval $sslenable
            }
        }
        "node" {
            if {[catch {node [lindex $sni_dg_value 1]}]} {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; Invalid Node value [lindex $sni_dg_value 1]"}
            } else {
                if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; forwarded to Node [lindex $sni_dg_value 1]"}
            }
        }
        "handshake_failure" {
            if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; connection is rejected (with Handshake Failure message)"}
            TCP::respond [binary format cH4Scc 21 $tls_handshake_prefered_version 2 2 40]
            after 10
            TCP::close
            return
        }
        "reject" {
            if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; connection is rejected"}
            reject
            return
        }
        "drop" {
            if {$static::sni_routing_debug} {log local0. "[IP::remote_addr] : TLS server_name value = ${tls_servername} ; TLS prefered version = 0x${tls_handshake_prefered_version} ; connection is dropped"}
            drop
            return
        }
    }
    TCP::release
}
