require('dotenv').config()
const express = require('express')
const User = require('../models/User')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const {body, validationResult} = require('express-validator')
const auth = require('../middleware/auth')
const router = express.Router()

const hashPassword = async(password) =>{
    const salt = await bcrypt.genSalt(15)
    return await bcrypt.hash(password,salt)
}

router.post('/register', 
    [
        body("username").trim().notEmpty().withMessage("Username is required"),
        body("email").matches(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/).withMessage("Invalid email format"),
        body("password").matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@#$%^&*!]{8,}$/).withMessage("Password must contain at least 8 characters, including 1 uppercase, 1 lowercase and 1 number"),
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ error: 'User already exists' });
        }

        const hashedPassword = await hashPassword(password)
    
        const newUser = new User({
            username,
            email,
            password: hashedPassword, 
        });
        await newUser.save();

        res.status(201).send({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).send({ error: error.message });
    }})


router.post('/login', 
    [
        body("email").isEmail().withMessage("Invalid email format"),
        body("password").notEmpty().withMessage("Password is required"),
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const user = await User.findOne({ email: req.body.email });
        if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
        }
    
        const isMatch = await bcrypt.compare(req.body.password, user.password);
        if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
        }

        user.password = undefined
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        
        res.send({ message: 'Login successful', accessToken:token});
    } catch (error) {
        res.status(400).send({ error: error.message });
    }
    })


    router.put('/reset-password', auth, 
        [
            body("oldPassword").notEmpty().withMessage("Old password is required"),
            body("newPassword").matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@#$%^&*!]{8,}$/).withMessage("Password must contain at least 8 characters, including 1 uppercase, 1 lowercase, and 1 number"),
            body("confirmPassword").notEmpty().withMessage("Confirm password is required"),
        ],
        async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { oldPassword, newPassword, confirmPassword } = req.body;

            const user = await User.findById(req.user._id);
            if (!user) {
                return res.status(404).send({ error: "User not found" });
            }
    
            const passwordMatch = await bcrypt.compare(oldPassword, user.password);
            if (!passwordMatch) {
                return res.status(400).send({ error: "Old password is incorrect" });
            }
    
            if (oldPassword === newPassword) {
                return res.status(400).send({ error: "New password must be different from old password" });
            }
    
            if (newPassword !== confirmPassword) {
                return res.status(400).send({ error: "New password and confirm password do not match" });
            }

        
            user.password = await hashPassword(newPassword);
            await user.save();
    
            res.send({ message: "Password reset successful" });
        } catch (error) {
            res.status(500).send({ error: error.message });
        }
    });
    
module.exports = router