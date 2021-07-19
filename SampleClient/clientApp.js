const { json } = require('body-parser')
const express = require('express')
var cookieParser = require('cookie-parser')
//var cors = require('cors')
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

/*const allowedOrigins = ['http://localhost:5000'];

const options = {
origin: allowedOrigins,
allowedHeaders: ["Access-Control-Allow-Credentials"]
}; */



function logger(req, res, next) {
    console.log("\n \n" + req.method + " request at " + req.path + "\n Data: " + JSON.stringify(req.body) + "/n Cookies: " + JSON.stringify(req.cookies));
    next()
}


//app.use(cors(options));
//JSON-ify's the body   -- req.body
app.use(express.json())
//Parses cookies        -- req.cookies  
app.use(cookieParser())
app.use(logger)

let Database = {
    "root" : {
        "password" : bcrypt.hashSync("root", saltRounds),
        "accessLevel" : "root"
    }
}
let refreshTokens = [

]

app.post('/auth/createUser', async (req, res) => {
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

app.post('/auth/login', async (req, res) => {
    if(!(req.body["username"] in Database) || !check_password(req.body["password"], Database[req.body["username"]]["password"])) {
        res.status(403).send("Username and/or password does not match")
    }
    else {

        let payload = {
            "User": req.body["username"],
            "accessLevel" : Database[req.body["username"]]["accessLevel"],
            "exp" : Math.floor(Date.now() / 1000) + (60 * 60)
        }
        let secret = fs.readFileSync("../Keys/private-key.pem").toString()

        let accessToken = await JWT.sign(payload, secret, { algorithm: 'RS256'})
        res.cookie('JWT', accessToken)

        let refreshToken = await uid(19)
        res.cookie('refreshToken',JSON.stringify({"refreshToken":refreshToken, "user":req.body["username"]}), { maxAge : 30 * 1000, httpOnly:true} )
        
        refreshTokens[req.body["username"]] = {}
        refreshTokens[req.body["username"]][refreshToken] = {}
        refreshTokens[req.body["username"]][refreshToken]["tokenStatus"] = "active"

        console.dir(refreshTokens)
        console.dir(Database)

        res.send("successfull login")
    }
})

app.post('/auth/modifyUser', async (req, res) => {

    console.dir(Database)

    let verifiedToken;
    let secret = fs.readFileSync("../Keys/public-key.pem").toString()

    try{
        verifiedToken = JWT.verify(req.cookies["JWT"], secret, { algorithms: 'RS256'})
        console.dir(verifiedToken)
    }
    catch(e) {
        res.status(403).send("unauthorized - expired probably")
        console.log(e)
        return
    }

    if((verifiedToken["accessLevel"] == "root" || verifiedToken["accessLevel"] == "admin") && (req.body["username"] in Database)) { 
        Database[req.body["username"]]["accessLevel"] = req.body["accessLevel"]
        res.send("Account modified")
    }
    else {
        res.status(403).send("unauthorized")
    }
})

app.get('/auth/key' , (req, res) => {
    res.send(fs.readFileSync("../Keys/public-key.pem").toString())
})

app.post('/auth/refresh' , async (req, res) => {

    let oldRefreshToken

    try {
        oldRefreshToken = JSON.parse(req.cookies['refreshToken']);
    }
    catch {
        res.status(403).send("no token")
        return
    }
    console.dir(oldRefreshToken)


    if(!(oldRefreshToken['user'] in refreshTokens)) {
        refreshTokens[oldRefreshToken['user']] = {}
    }

    if(oldRefreshToken['refreshToken'] in refreshTokens[oldRefreshToken['user']]) {
        
        if(refreshTokens[oldRefreshToken['user']][oldRefreshToken['refreshToken']]['tokenStatus'] == 'invalid') {
            console.log("INVALID TOKEN")
            Object.keys(refreshTokens[oldRefreshToken['user']]).forEach(key => {
                refreshTokens[oldRefreshToken['user']][key]['tokenStatus'] = 'invalid';
            
            });

            res.status(403).send("invalid token")
            return;
        }

        refreshTokens[oldRefreshToken['user']][oldRefreshToken['refreshToken']]['tokenStatus'] = 'invalid'

        let payload = {
            "User": oldRefreshToken['user'],
            "accessLevel" : Database[oldRefreshToken['user']]["accessLevel"],
            "exp" : Math.floor(Date.now() / 1000) + (60 * 60)
        }

        let secret = fs.readFileSync("../Keys/private-key.pem").toString()

        let accessToken = await JWT.sign(payload, secret, { algorithm: 'RS256'})
        res.cookie('JWT', accessToken)

        let refreshToken = await uid(32)
        res.cookie('refreshToken',JSON.stringify({"refreshToken":refreshToken, "user":oldRefreshToken['user']}), { maxAge : 600 * 1000, httpOnly:true} )

        refreshTokens[oldRefreshToken['user']][refreshToken] = {}
        refreshTokens[oldRefreshToken['user']][refreshToken]["tokenStatus"] = "active"

        console.dir(refreshTokens)
        console.dir(Database)

        res.send("successfull login")
    }
})

app.post("/auth/logout", (req, res) => {
    res.clearCookie("JWT")
    res.clearCookie("refreshToken")
    res.send()
})

app.get("/", (req, res) => {
    res.send(fs.readFileSync("./clientApp.html").toString())
})

app.get("/src/*", (req, res) => {
    res.send(fs.readFileSync("."+req.path).toString())
})

app.get("/snake", async (req, res) => {

    let verifiedToken;
    let key = fs.readFileSync("../Keys/public-key.pem").toString()

    try{
        verifiedToken = JWT.verify(req.cookies["JWT"], key, { algorithms: 'RS256'})
        console.dir(verifiedToken)
    }
    catch(e) {
        res.status(403).send("unauthorized")
        console.log(e)
        return
    }

    res.send("SNAKEZ")
})

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})