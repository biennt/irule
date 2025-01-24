when HTTP_REQUEST {
switch -glob -- [string tolower [HTTP::uri]]  {
  "/" { HTTP::redirect "https://cic.org.vn/webcenter/portal/CMSPortal" }
  "/acbbox-cic-external/*" { 
    if { [HTTP::cookie exists "CICORGVN"] } {
      pool new-ACBBox-2022
      persist uie [HTTP::cookie "CICORGVN"]
    } else { pool new-ACBBox-2022 }
  }
  default { 
    if { [HTTP::cookie exists "JSESSIONID"] } {
      pool new-webcenter-2022
      persist uie [HTTP::cookie "JSESSIONID"]
    } else { pool new-webcenter-2022 }
  }
  }
}

when HTTP_RESPONSE {
  # Persist session using cookies
  if { [HTTP::cookie exists "CICORGVN"] } {
      persist add uie [HTTP::cookie "CICORGVN"]
  } elseif { [HTTP::cookie exists "JSESSIONID"] } {
      persist add uie [HTTP::cookie "JSESSIONID"]
  }
}
