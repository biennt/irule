when HTTP_REQUEST { 
   switch -glob [string tolower[HTTP::uri] ] {
      "/api1*"  {
            pool api1_pool
       }
      "/api2*"  {
            pool api2_pool
       }
      "/api3/sub1"  {
            pool sub31_api_pool
       }
       default {
            pool default_api_pool
       }
    }
}
