const jwt = require('jsonwebtoken')
const User = require('../models/User')

const auth = async(req,res,next) =>{
    try{
        const token = req.headers['authorization'].split(" ")[1];
        if (!token) throw new Error('No token found');

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) throw new Error('User not found');

        req.user = user; 
        next();
    } catch (error) {
        console.error('Authentication error:', error.message);
        res.status(401).send({ error: 'Please authenticate.' });
    }
};

module.exports = auth