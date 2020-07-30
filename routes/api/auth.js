const express = require ('express');
const router = express.Router();
const bcrypts = require('bcryptjs')
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const User = require('../../models/User')

// @roter GET api/auth
// @desc TEST router
// @access Public
router.get('/',auth, async(req, res)=> {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user)
    } catch (error) {
        console.error(err.message);
        res.status(500).send('Server Error')
    }
});

// Login
// @roter GET api/auth
// @desc Authenticate user & get token
// @access Public
router.post('/',
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required')
        .exists()
    ],
    async (res, req) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { email, password } = req.body;

        try {
            //See if user exists
            let user = await User.findOne({ email });

            if (!user) {
                return res
                    .status(400)
                    .json({ errors: [{ msg: 'Invalid Credentials' }] })
            }

            const isMatch = await bcrypts.compare(password, user.password);
            if(!isMatch){
                return res
                    .status(400)
                    .json({ errors: [{ msg: 'Invalid Credentials' }] })
            }

            //Return jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 36000 },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token });
                });
        } catch (err) {
            console.log(err.message)
            res.status(500).send('Server error')
        }
    }
);

module.exports = router