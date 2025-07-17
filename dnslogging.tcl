when DNS_REQUEST {
  # data-group name is loggeddomains
  if {[class match [DNS::question name] ends_with loggeddomains]} {
    log local0.info "[IP::client_addr]|[DNS::question name]|[DNS::question type]"
  }
}
#
# list ltm data-group internal loggeddomains 
ltm data-group internal loggeddomains {
    records {
        vnexpress.net { }
        youtube.com { }
    }
    type string
}

##########################
when DNS_REQUEST {
  # data-group name is loggedsubnet
  if {[class match [IP::client_addr] equals loggedsubnet]} {
    log local0.info "[IP::client_addr]|[DNS::question name]|[DNS::question type]"
  }
}

#
# list ltm data-group internal loggedsubnet
ltm data-group internal loggedsubnet {
    records {
        10.1.10.0/24 { }
        10.1.20.0/24 { }
    }
    type ip
}
