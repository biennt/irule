when HTTP_RESPONSE priority 100 {
   if { [catch { set setckval [HTTP::header values "Set-Cookie"]
      HTTP::header remove "Set-Cookie"
      foreach value $setckval {
         if { "" != $value } {
            set testvalue [string tolower $value]
            set valuelen [string length $value]
            switch -glob $testvalue {
               "*;secure*" -
               "*; secure*" { }
               default { set value "$value; Secure"; }
            }
            switch -glob $testvalue {
               "*;httponly*" -
               "*; httponly*" { }
               default { set value "$value; HttpOnly"; }
            }

            HTTP::header insert "Set-Cookie" $value
         }
      }
   } ] } {
   }
}
