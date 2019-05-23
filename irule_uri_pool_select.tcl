when HTTP_REQUEST {
  	if {[HTTP::uri] starts_with "/abc"} {
  		pool abc_pool
  	}
     if {[HTTP::uri] starts_with "/xyz"} {
  		pool xyz_pool
  	}
}
