when HTTP_REQUEST {
switch -glob [HTTP::header Host] {
  "gateway.congdulieuyte.vn" {
  	pool HIS_Portal1
  }
  "congdulieuyte.vn" {
  	if {[HTTP::uri] starts_with "/hPortal/services"} {
  		pool HIS_Portal2
  	} elseif {[HTTP::uri] starts_with "/dreport"} {
  		pool HIS_Portal3
  		} else {
  				pool HIS_Portal4
  			}
  }
  "hanam.congdulieuyte.vn" {
  	pool HIS_Hanam
   
  }
  "hssk.congdulieuyte.vn" {
    pool HIS_Portal6
  }
  "quanlyduoc.congdulieuyte.vn" {
    pool HIS_Portal7
  }
}
}
