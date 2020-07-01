when HTTP_REQUEST {
switch -glob [HTTP::header Host] {
  "abc.vn" {
    pool abcpool
  }
  "xyz.vn" {
    pool xyzpool
  }
}
}
