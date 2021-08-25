require("dotenv").config()
const express = require("express")
const massive = require("massive")
const session = require('express-session')
const bcrypt = require("bcryptjs")
const { CONNECTION_STRING, SESSION_SECRET } = process.env

const app = express()

app.use(express.json())
app.use(session({
    resave: false,
    saveUninitialized: true,
    secret: SESSION_SECRET,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 365,
    }
}))


massive({
  connectionString: CONNECTION_STRING,
  ssl: {
    rejectUnauthorized: false,
  },
}).then((dbInstance) => {
  app.set("db", dbInstance)
  console.log("DB Ready")
})

app.post("/api/register", (req, res) => {
  const { username, email, first_name, password, admin } = req.body

  if (username && password && email) {

    const db = req.app.get("db")

    db.auth.check_username(username).then((user) => {
      const existingUser = user[0]
      if (existingUser) {
          console.log(existingUser)
        res.status(400).send("Username Taken.")
      } else {   
        const newUser = user[0]     
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        db.auth
          .register_user(username, hash, email, first_name, admin)
          .then((newUser) => {
            delete newUser.password
            req.session.user = newUser   
            res.status(200).send(newUser)
        })
      }
    })
  } else {
    res.status(400).send("Please provide username, password and email.")
  }
})

app.post('/api/login', (req, res) => {
    const db = req.app.get("db")
    const { username, password } = req.body
    //check the database for the user
    db.auth.check_username(username).then((user) => {
        // const existingUser = user[0]
        if(!user[0]){
            return res.status(404).send('User does not exist')
        } else if (!bcrypt.compareSync(password, user[0].password)) {        
            return res.status(403).send('Password incorrect')
        } delete user[0].password
        req.session.user = user[0]
        console.log(req.session.user)
        res.status(200).send(user[0])
    })    
})

app.delete('/api/logout', (req, res) => {
    req.session.destroy()
    res.sendStatus(200)    
})


const isAuthenticated = ((req, res, next) => {
    if(req.session.user && req.session.user.admin) {
        next()
    } else {
        res.status(403).send('Admins only')
    }
})

app.get('/api/secrets', isAuthenticated, (req, res) => {
    res.status(200).send('Secrets!')
})

app.listen(5050, () => console.log("Listening on port 5050"))