load("pgstar/http", http="exports")
load("pgstar/postgres", db="exports")

load("common.star", common="exports")

NOT_LOGGED_IN_MESSAGE = "Not logged in."

post = http.post()

rows, err = db.query("SELECT * FROM user_login_tokens WHERE id = $1", [ post["id"] ])
if err != None:
    http.write(403, { 'message': err})

user_token = db.first(rows)
if user_token == None:
    http.write(500, { 'message': NOT_LOGGED_IN_MESSAGE})

rows_affected, err = db.exec("DELETE FROM user_login_tokens WHERE id = $1 and token = $2", [ post["id"], post["token"]])
if err != None:
    http.write(500, { 'message': err})

http.write(200, { 'message': "Logout successful!"})
