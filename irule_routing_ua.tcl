when HTTP_REQUEST {
   switch [string tolower [HTTP::header User-Agent]] {
      "*Android*" {
         pool android_pool
      }
      "*iPhone*" {
         pool iphone_pool
      }
      default {
         pool other_pool
      }
   }
}
