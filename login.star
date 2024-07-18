load("pgstar/http", http="exports")
load("pgstar/postgres", db="exports")
load("pgstar/crypto/random", random="exports")
load("pgstar/crypto/sha2", sha2="exports")
load("pgstar/encoding/hex", hex="exports")

load("common.star", common="exports")

GENERIC_LOGIN_FAILURE_MESSAGE="login failed, please check your username and password"

post = http.post()

# ensure post data was provided
if post == None:
    http.write(400, { 'message': 'failed to parse json data'})

# ensure all fields are provided
for required in [ "email", "password" ]:
    if required not in post:
        http.write(400, { 'message': required + ' is required in the request'})

db.savepoints(True)

rows, err = db.query("SELECT * FROM users WHERE email = $1", [ post["email"] ])
if err != None:
    http.write(403, { 'message': err})

user = db.first(rows)
if user == None:
    http.write(500, { 'message': GENERIC_LOGIN_FAILURE_MESSAGE})

if common.validateHashwords(post["password"], user["salthash"], user["passhash"]) == False:
    http.write(403, { 'message': GENERIC_LOGIN_FAILURE_MESSAGE})


rows, err = db.query("INSERT INTO user_login_tokens (user_id, token) VALUES ($1, $2) RETURNING id, token",
                    [
                        user["id"],
                        hex.encode(sha2.sum256(random.bytes(32))),
                    ])
if err != None:
    http.write(500, { 'message': err})

login_token = db.first(rows)
if login_token == None:
    http.write(500, { 'message': GENERIC_LOGIN_FAILURE_MESSAGE})

http.write(200, {
    'message': "Login successful!",
    'id': login_token["id"],
    'token': login_token["token"],
    })
