when CLIENT_ACCEPTED {
	# Generate a random ID for this session
   	set count 20
   	set letters [ list a b c d e f g h i j k l m n o p q r s t u v w x y z ]
   	set random ""
   	set logme 0
   	for { set i 1 } { $i < $count } { incr i } {
      		append random [lindex $letters [expr { int (rand() * 26) }]]
   	}
   	# Get time for start of TCP connection in milleseconds
	set tcp_start_time [clock clicks -milliseconds]
	# Log the start of a new TCP connection
	log local0. ">$random< New TCP connection from [IP::client_addr]:[TCP::client_port] to [IP::local_addr]:[TCP::local_port]"
}

when HTTP_REQUEST {
  set reqTime [clock format [clock seconds] -format "%d/%m/%Y %H:%M:%S"]
  set logstring "REQUEST_HEADER|$random|$reqTime|[IP::client_addr]|[HTTP::method]|[HTTP::uri]"
  foreach aHeader [HTTP::header names] {
      set logstring "$logstring|$aHeader: [HTTP::header value $aHeader]"
   }
  log local0.info $logstring
  HTTP::collect 200
}
when HTTP_REQUEST_DATA {
  set reqTime [clock format [clock seconds] -format "%d/%m/%Y %H:%M:%S"]
  set payload [HTTP::payload 200]
  HTTP::release
  set logstring "REQUEST_PAYLOAD|$random|$reqTime|$payload"
  log local0.info $logstring
}

when HTTP_RESPONSE {
  set respTime [clock format [clock seconds] -format "%d/%m/%Y %H:%M:%S"]
  set collectpayload 0
  if {[HTTP::header Content-Type] contains "text"} {
    HTTP::collect 200
    set collectpayload 1
  }
  set logstring "RESPONSE_HEADER|$random|$respTime|[HTTP::status]"
    foreach aHeader [HTTP::header names] {
      set logstring "$logstring|$aHeader: [HTTP::header value $aHeader]"
   }
  log local0.info $logstring
}

when HTTP_RESPONSE_DATA {
  if { $collectpayload == 1 } {
    set respTime [clock format [clock seconds] -format "%d/%m/%Y %H:%M:%S"]
    set responsepayload [HTTP::payload 200]
    set logstring "RESPONSE_PAYLOAD|$random|$respTime|$responsepayload"
    log local0.info $logstring
    HTTP::release
  }
}
