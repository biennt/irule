var debug = 2;  
if (debug >= 2) {console.log('Running extension1 index.js');}  
var f5 = require('f5-nodejs');  
var ilx = new f5.ILXServer();  
ilx.listen();  
ilx.addMethod('myql_nodejs', function(username, response) {  
    if (debug >= 1) {console.log('my_nodejs' + ' ' + typeof(username.params()) + ' = ' + username.params());}  
    var mysql = require('mysql');  
    var connection = mysql.createConnection({  
        host     : '10.0.0.110',  
        user     : 'bigip',  
        password : 'bigip'  
    });  
    connection.connect(function(err) {  
        if (err) {  
            if (debug >= 1) {console.error('Error connecting to MySQL: ' + err.stack);}  
            return;  
        }  
        if (debug >= 2) {console.log('Connected to MySQL as ID ' + connection.threadId);}  
    });    
    connection.query('SELECT * from users_db.users_table where name = ' + mysql.escape(username.params(0)), function(err, rows, fields) {  
        if (err) {  
            if (debug >= 1) {console.error('Error with query: ' + err.stack);}  
            response.reply('');  
            return;  
        } else {   
            if (rows < 1){  
                if (debug >= 1) {console.log('No matching records from MySQL');}  
                response.reply('-1');  
            } else {  
                if (debug >= 2) {console.log('First row from MySQL is: ', rows[0]);}  
                response.reply(rows.pop());  
            }  
        }  
    });  
    connection.end();  
});
