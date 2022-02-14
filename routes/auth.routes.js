const express = require('express');
const User = require('../models/User.model');
const router = express.Router();
const saltRounds = 5;
const bcrypt = require('bcrypt');


router
.route('/signup')
.get((req, res)=>{
    res.render("signup")
})
.post((req, res)=>{
    const username = req.body.username
    const password = req.body.password

    if(!username || !password) res.render('signup', {errorMessage: "All fields are required"})


    User.findOne({username})
    .then((user)=>{
        if(user && username){
            res.render('signup', {errorMessage: "User already exists"})
            throw new Error("Validation error")
        }
        
        const salt = bcrypt.genSaltSync(saltRounds)
        const hashedPwd = bcrypt.hashSync(password, salt)

        User.create({username, password : hashedPwd}).then(()=> res.redirect("/"))
    })
})

//////////// LOGIN

router
.route('/login')
.get((req, res)=>{
    res.render('login')
})

.post((req, res)=>{
    const username = req.body.username
    const password = req.body.password

    User.findOne({username})
    .then(user=>{
        if(!user){
            res.render("login", {errorMessage: "The user or password are incorrect"})
            throw new Error("Validation error")
        }

        const pwdCorrect = bcrypt.compareSync(password, user.password)
        if(pwdCorrect){
            req.session.currentUserId = user._id
            res.redirect("/auth/private")
        }else{
            res.render("login", {errorMessage: "Incorrect username or password"})
        }
    })
    .catch((err)=>console.log(err))
})

router
.get('/private', (req, res)=>{
    const id = req.session.currentUserId;
    if(!id) res.render("main")

    User.findById(id)
    .then((user)=> res.render("private", {user}))
    .catch(err=>console.log(err))
})

router
.get("/logout", (req, res)=>req.session.destroy(
	res.redirect("/")
))




module.exports = router;