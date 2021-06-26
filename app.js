const { json } = require('body-parser')
const express = require('express')
var cookieParser = require('cookie-parser')
var cors = require('cors')
var JWT = require('jsonwebtoken')
const bcrypt = require('bcrypt');
var uid = require('uid-safe')
const fs = require('fs');

const app = express()
const port = 3000
const saltRounds = 10;

async function get_hashed_password(plain_text_password) {

    let hashed_password = await bcrypt.hash(plain_text_password, saltRounds);

    return hashed_password;
}
async function check_password(plain_text_password, hashed_password) {

    let result = await bcrypt.compare(plain_text_password, hashed_password)

    return result;
}

// Add a list of allowed origins.
// If you have more origins you would like to add, you can add them to the array below.
const allowedOrigins = ['http://localhost:5000'];

const options = {
  origin: allowedOrigins
};



function logger(req, res, next) {
    console.log("\n \n" + req.method + " request at " + req.path + "\n Data: " + JSON.stringify(req.body) + "/n Cookies: " + JSON.stringify(req.cookies));
    next()
}


app.use(cors(options));
//JSON-ify's the body   -- req.body
app.use(express.json())
//Parses cookies        -- req.cookies  
app.use(cookieParser())
app.use(logger)

let rootPW
get_hashed_password("root").then((value) => rootPW = value)

let Database = {
    "root" : {
        "password" : rootPW,
        "accessLevel" : "root"
    }
}
let refreshTokens = [

]

app.get('/', (req, res) => {
    res.set('Set-Cookie', 'test=test')
    res.send('Hello World!')
})

app.post('/createUser', async (req, res) => {
    if(req.body["username"] == "" || req.body["password"] == "") {
        res.send("invalid password/username")
    }
    else if(req.body["username"] in Database) {
        res.send("account already exists")
    }
    else {
        Database[req.body["username"]] = {}
        Database[req.body["username"]]["password"] = await get_hashed_password(req.body["password"])
        Database[req.body["username"]]["accessLevel"] = "user"
        res.send("account successfully created")
        console.log(JSON.stringify(Database))
    }
})

app.post('/login', async (req, res) => {
    if(!(req.body["username"] in Database)) {
        res.send("Username and password do not match")
    }
    else {
        if(check_password(req.body["password"], Database[req.body["username"]]["password"])) {

            let payload = {
                "User": req.body["username"],
                "accessLevel" : Database[req.body["username"]]["accessLevel"],
                "exp" : Math.floor(Date.now() / 1000) + (60 * 60)
            }
            let secret = fs.readFileSync("./Keys/private-key.pem").toString()

            let accessToken = await JWT.sign(payload, secret, { algorithm: 'RS256'})
            res.cookie('JWT', accessToken, {httpOnly:true} )

            let refreshToken = await uid(19)
            res.cookie('refreshToken',refreshToken, { maxAge : 600 * 1000, httpOnly:true} )
            
            refreshTokens[refreshToken] = {}
            refreshTokens[refreshToken]["user"] = req.body["username"]
            refreshTokens[refreshToken]["tokenStatus"] = "active"

            res.send("successfull login")
        }
        else {
            res.send("Username and password do not match")
        }
    }
})

app.get('/key' , (req, res) => {
    res.send(fs.readFileSync("./Keys/public-key.pem").toString())
})

app.get('/refresh')

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})