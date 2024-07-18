load("pgstar/http", http="exports")

load("common.star", common="exports")

user = common.getUser()
if user == None:
    http.write(403, { 'message': 'Login required.'})

http.write(200, user)
