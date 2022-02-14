require('dotenv').config()
const express = require('express')
const app = express()
const bcrypt = require('bcryptjs')
const session = require('express-session')
const { SERVER_PORT, SESSION_SECRET } = process.env

// can use fake db for scope of this project, or sequelize
// using fake db for sake of this example
const db = require('../fakeDb.json')

app.use(express.json());

// express-session stuff
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}))

// id for users (actual db would handle this with data type 'serial')
let id = 0

app.post('/auth/register', (req, res) => {
    const { name, email, password } = req.body;

    // handle username
    const foundUser = db.findIndex(userObj => userObj.email === email)

    if (foundUser >= 0) {
        return res.status(403).send('Username taken!')
    }

    // username good and handle password
    const salt = bcrypt.genSaltSync()
    const hash = bcrypt.hashSync(password, salt)

    // add user to "db"
    const newUser = {
        id, name, email, hash
    }

    db.push(newUser)

    // log in user
    req.session.user = {
        id, name, email
    }

    // set up id for next user for our fake db
    id++

    res.status(200).send(req.session.user);
})

app.post('/auth/login', (req, res) => {
    const { email, password } = req.body

    // handle finding user
    const userIndex = db.findIndex(userObj => userObj.email === email)

    if (userIndex === -1) {
        return res.status(400).send('User not found!')
    }

    // user email found? handle password auth
    const isMatch = bcrypt.compareSync(password, db[userIndex].hash)

    if (isMatch === false) {
        return res.status(403).send('Password incorrect!')
    }

    // password good? log in user
    req.session.user = { ...db[userIndex] }
    delete req.session.hash // no need to store hash on session object

    res.status(200).send(req.session.user)
})

app.post('/auth/logout', (req, res) => {
    // kills the session server side
    req.session.destroy();

    res.sendStatus(200)
})

app.get('/auth/getUser', (req, res) => {
    // if we need that a user is logged in, can always just have the front end send request for req.session.user
    if (req.session.user) {
        res.status(200).send(req.session.user)
    } else {
        res.sendStatus(403)
    }
})

app.listen(SERVER_PORT, () => console.log(`Server rocking and rolling on ${SERVER_PORT}`))