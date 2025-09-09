when HTTP_RESPONSE {
    HTTP::header insert "X-Frame-Options" "SAMEORIGIN"
    HTTP::header insert "X-XSS-Protection" "1; mode=block"
    HTTP::header insert "X-Content-Type-Options" "nosniff"
    HTTP::header replace "Strict-Transport-Security" "max-age=15552000; includeSubDomains"
    HTTP::header insert "Content-Security-Policy" "object-src *;script-src * 'unsafe-inline' 'unsafe-eval' data:"
}
