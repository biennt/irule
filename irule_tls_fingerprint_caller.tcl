when RULE_INIT { 
    set static::maxRate 10
    set static::timeout 5
}

when CLIENT_ACCEPTED {
    TCP::collect
}
when CLIENT_DATA {
    set fingerprint ""
    if { ! [info exists rlen] } {
        binary scan [TCP::payload] cH4ScH6H4 rtype outer_sslver rlen hs_type rilen inner_sslver
        if { ( ${rtype} == 22 ) and ( ${hs_type} == 1 ) } {
            set fingerprint [call Library-Rule::fingerprintTLS [TCP::payload] ${rlen} ${outer_sslver} ${inner_sslver} [IP::client_addr] [IP::local_addr]]
        }
    }
    if { [TCP::payload length] < $rlen } {
        TCP::collect $rlen
    }
    TCP::release
}

when HTTP_REQUEST {
  if { [set counter [table incr -mustexist "$fingerprint"]] ne "" } then {
    if { $counter > $static::maxRate } then {
      log local0. "too requests from $fingerprint"
      HTTP::respond 200 content ""
    }
  } 
  else 
  {
    table set "$fingerprint" 1 indef $static::timeout
  }
}
