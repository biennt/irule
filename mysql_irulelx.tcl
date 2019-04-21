when RULE_INIT {  
    set static::mysql_debug 2  
}  
when HTTP_REQUEST {    
    if {$static::mysql_debug >= 2}{log local0. "New HTTP request. \[HTTP::username\]=[HTTP::username]"}  
    if {[HTTP::username] eq ""}{  
  
        HTTP::respond 401 content "Username was not included in your request.\nSend an HTTP basic auth username to test" WWW-Authenticate {Basic realm="iRulesLX example server"}  
        if {$static::mysql_debug >= 2}{log local0. "No basic auth username was supplied. Sending 401 to prompt client for username"}  
  
    } else {  
        set tmp_username [HTTP::username]  
        set username [URI::decode $tmp_username]  
        while { $username ne $tmp_username } {  
            set tmp_username $username  
            set username [URI::decode $tmp_username]  
        }  
        if {$username ne [set invalid_chars [scan $username {%[-a-zA-Z0-9_]}]]}{  
            HTTP::respond 401 content "\nA valid username was not included in your request.\nSend an HTTP basic auth username to test\n" WWW-Authenticate {Basic realm="iRulesLX example server"}  
            if {$static::mysql_debug >= 1}{log local0. "Invalid characters in $username. First invalid character was [string range $username [string length $invalid_chars] [string length $invalid_chars]]"}  
            return  
        }  
        set RPC_HANDLE [ILX::init mysql_extension]  
        if {$static::mysql_debug >= 2}{log local0. "\$RPC_HANDLE: $RPC_HANDLE"}  
        set rpc_response [ILX::call $RPC_HANDLE myql_nodejs $username]  
        if {$static::mysql_debug >= 2}{log local0. "\$rpc_response: $rpc_response"}  
        if {$rpc_response == -1}{  
            HTTP::respond 401 content "\nYour username was not found in MySQL.\nSend an HTTP basic auth username to test\n" WWW-Authenticate {Basic realm="iRulesLX example server"}  
            if {$static::mysql_debug >= 1}{log local0. "Username was not found in MySQL"}  
        } elseif {$rpc_response eq ""}{  
            HTTP::respond 401 content "\nDatabase connection failed.\nPlease try again\n" WWW-Authenticate {Basic realm="iRulesLX example server"}  
            if {$static::mysql_debug >= 1}{log local0. "MySQL query failed"}  
        } else {  
            HTTP::respond 200 content "\nGroup(s) for '$username' are '$rpc_response'\n"  
            if {$static::mysql_debug >= 1}{log local0. "Looked up \$username=$username and matched group(s): $rpc_response"}  
        }  
    }  
}  
