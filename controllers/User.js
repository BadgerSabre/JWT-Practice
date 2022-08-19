const router = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const { validateJWT } = require('../middleware/auth')

const User = require('../models/User')

router.post('/signup', async (req, res) => {
    const { username, password } = req.body

    const user = await new User({
        username,
        password: await bcrypt.hash(password, 12)
    }).save()

    const payload = {
        username
    }

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' })
    res.send(token)
})

router.get('/authenticated-route', validateJWT, (req, res) => {
    res.send('I sent you a message')
})

router.get('/profile', validateJWT, async (req, res) => {
    const { username } = req.user

    const user = await User.find({ username })

    res.send(user)
})

module.exports = router