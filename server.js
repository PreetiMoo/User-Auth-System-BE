require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const app =express()
app.use(cors())
app.use(express.json())

app.use('/api/auth', require('./routes/userAuth'))

mongoose.connect(process.env.MONGO_URI,{})
.then(()=>console.log("MongoDB connected"))
.catch((error)=> console.error("Error connecting to mongoDB",error))

const PORT = process.env.PORT || 5000

app.listen(PORT,()=>{
    console.log(`Server started on ${PORT}`)
})