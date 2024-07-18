load("pgstar/http", http="exports")
load("pgstar/postgres", db="exports")

load("common.star", common="exports")

post = http.post()

# ensure post data was provided
if post == None:
    http.write(400, { 'message': 'failed to parse json data'})

# ensure all fields are provided
for required in [ "username", "email", "password" ]:
    if required not in post:
        http.write(400, { 'message': required + ' is required in the request'})


validationError = common.checkEmail(post["email"])
if validationError != None:
    http.write(400, { 'message': validationError})

validationError = common.checkPassword(post["password"])
if validationError != None:
    http.write(400, { 'message': validationError})

salthash, passhash = common.generateHashwords(post["password"])

rows_affected, err = db.exec("INSERT INTO users (username, email, salthash, passhash) VALUES ($1, $2, $3, $4)", [ post["username"], post["email"], salthash, passhash ])
if err != None:
    http.write(500, { 'message': err})
