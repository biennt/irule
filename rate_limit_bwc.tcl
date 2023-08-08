when RULE_INIT {
  # đối đa mỗi user là 10 request per second
    set static::maxRate 10
# timeout cho session table, nghĩa là ngoài 1 giây, giá trị sẽ biến mất để đếm lại
    set static::timeout 1
}
 
when HTTP_REQUEST {
# đặt tiêu chí nhận diện user
  set mycookie [HTTP::host]
  BWC::policy attach bwpolicy $mycookie
# phần dưới này là hạn chế request per second
  if { [set methodCount [table incr -mustexist "$mycookie"]] ne "" } then {
    if { $methodCount > $static::maxRate } then {
      log local0. "$mycookie exceeded max HTTP requests per second"
 
      # trả lời gì cho client khi bị rate limit??
      HTTP::respond 429 content "Request blockedExceeded requests/sec limit."
      return
    }  
  } else {
    table set "$mycookie" 1 indef $static::timeout
  }
log local0. "$mycookie: methodCount=$methodCount"
 
}

when HTTP_REQUEST_SEND {
  set mycookie [HTTP::host]
  BWC::policy attach bwpolicy $mycookie
}
