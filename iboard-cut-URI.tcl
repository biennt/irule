when HTTP_REQUEST {
  switch -glob [string tolower [HTTP::path]]  {
      "/gateway*" {
        HTTP::uri [substr $uri 8]
        pool pool_gateway
        log local0.info "Sending to pool gateway [HTTP::uri] [IP::client_addr] [IP::local_addr]"
        }
      "/realtime/*" {
        HTTP::uri [substr $uri 9]
        pool pool_realtime
        log local0.info "Sending to pool realtime [HTTP::uri] [IP::client_addr] [IP::local_addr]"
        }
  }
}
