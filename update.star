load("pgstar/http", http="exports")
load("pgstar/postgres", db="exports")

load("common.star", common="exports")

user = common.getUser(False)
if user == None:
    http.write(403, { 'message': 'Login required.'})

post = http.post()

fields = []
values = []

if "new_password" in post:
    if "old_password" not in post:
        http.write(400, { 'message': "old password is required for validation"})

    if common.validateHashwords(post["old_password"], user["salthash"], user["passhash"]) == False:
        http.write(400, { 'message': "Failed to validate old password."})

    if post["old_password"] == post["new_password"]:
        http.write(400, { 'message': "New and old passwords are the same."})

    validationError = common.checkPassword(post["new_password"])
    if validationError != None:
        http.write(400, { 'message': validationError})

    salthash, passhash = common.generateHashwords(post["new_password"])
    fields += ["salthash", "passhash"]
    values += [ salthash, passhash ]

if "email" in post:
    validationError = common.checkEmail(post["email"])
    if validationError != None:
        http.write(400, { 'message': validationError})

    fields += ["email"]
    values += [ post["email"] ]

if len(fields) == 0:
    http.write(400, { 'message': "update request is empty"})

setFragment = ""
fragmentCount = 1
for field in fields:
    fragmentCount += 1
    if setFragment != "":
        setFragment += ", "
    setFragment += field + " = $" + str(fragmentCount)

sqlStmt = "UPDATE users SET "+setFragment + " WHERE id = $1"
rows_affected, err = db.exec(sqlStmt, [ user["id"] ] + values)
if err != None:
    print(sqlStmt)
    http.write(500, { 'message': err})


http.write(200, { 'message': "Update successful."})
