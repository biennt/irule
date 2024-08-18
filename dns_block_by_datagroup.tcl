when DNS_REQUEST {
    set domainmatch [class lookup [string tolower [DNS::question name]] blocklistdg]
    if { $domainmatch ne "" } {
        set rr1 [getfield $domainmatch "|" 1]
        set rr2 [getfield $domainmatch "|" 2]
        if { $rr1 ne "" } {
            DNS::answer insert "[DNS::question name]. $rr1"
        }
        if { $rr2 ne "" } {
            DNS::answer insert "[DNS::question name]. $rr2"
        }
        DNS::header aa 1
        DNS::header rcode NOERROR
        DNS::return
    }
}
