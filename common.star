load("pgstar/crypto/sha2", sha2="exports")
load("pgstar/crypto/random", random="exports")
load("pgstar/regex", regex="exports")
load("pgstar/encoding/hex", hex="exports")
load("pgstar/postgres", db="exports")
load("pgstar/http", http="exports")

def checkPassword(password):
    if len(password) < 8:
        return "password must be at least 8 characters long"
    if regex.match('^[A-Za-z0-9]+$', password):
        return "password must contain a non-alphanumeric character"
    return None

def generateHashwords(password):
    salthash = sha2.sum256(random.bytes(32))
    passhash = sha2.sum256(salthash + password)
    return hex.encode(salthash), hex.encode(passhash)


def validateHashwords(password, salthash, passhash):
    salthash, err = hex.decode(salthash)
    passhash, err = hex.decode(passhash)
    return passhash == sha2.sum256(salthash + password)

def checkEmail(email):
    if regex.match('(?i)^[a-z0-9._%+\\-]+@[a-z0-9.\\-]+\\.[a-z]{2,}$', email) != True:
        return "email is not valid"

def getUser(protectCredentials=True):
    headers = http.headers()
    rows, err = db.query("SELECT * FROM user_login_tokens WHERE id = $1 and token = $2", [ headers["Id"][0], headers["Token"][0] ])
    if err != None:
        http.write(403, { 'message': 'Login required.'})

    user_token = db.first(rows)
    if user_token == None:
        http.write(403, { 'message': 'Login required.'})

    rows, err = db.query("SELECT * FROM users WHERE id = $1", [ user_token["user_id"] ])
    if err != None:
        http.write(403, { 'message': 'Login required.'})

    user = db.first(rows)
    if protectCredentials:
        user.pop("passhash")
        user.pop("salthash")
    return user

exports = Struct(
    "common.star",
    "checkPassword", checkPassword,
    "generateHashwords", generateHashwords,
    "validateHashwords", validateHashwords,
    "checkEmail", checkEmail,
    "getUser", getUser,
)
