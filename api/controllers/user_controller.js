const mongoose = require('mongoose');
const redis = require("redis");
const otpGenerator = require('otp-generator');
//const CryptoJS = require("crypto-js");
const fast2sms = require('fast-two-sms') ;
global.Buffer = global.Buffer || require('buffer').Buffer;
if (typeof btoa === 'undefined') {
  global.btoa = function (str) {
    return new Buffer(str, 'binary').toString('base64');
  };
}
if (typeof atob === 'undefined') {
  global.atob = function (b64Encoded) {
    return new Buffer(b64Encoded, 'base64').toString('binary');
  };
}

const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const User = require('../models/user_model.js');
const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
       user: process.env.EMAIL_USERNAME,
       pass: process.env.EMAIL_PASSWORD,
    },
});
//var key = "2e35f242a46d67eeb74aabc37d5e5d05";
/*
var key = "2e35f242a46d67eeb74aabc37d5e5d05";
var data = CryptoJS.AES.encrypt("Message", key); // Encryption Part
var decrypted = CryptoJS.AES.decrypt(data, key).toString(CryptoJS.enc.Utf8); // Message

*/

const client = redis.createClient();
 
client.on('error', (err) => console.log('Redis Client Error', err));
client.on('connect', function (err) {
      console.log('Connected to redis successfully');
});
client.connect();
 

exports.signup = async (req, res) => {
    const login_method = req.params.login_method;
    incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    const {mobile} = req.body;
    const { email } = req.body;
    const { firstname } = req.body;
    const {lastname} = req.body;
    const{password} = req.body;
    if (!incoming_user[login_method]) {
       return res.status(422).send({ message: `Missing ${login_method}` });
    }
    try{
       // Check if the email is in use
       const existingUser = await User.findOne(incoming_user).exec();
       if (existingUser) {
          return res.status(409).send({ 
                message: `${login_method} is already in use.`
          });
       }
       // Step 1 - Create and save the user
      const user = await new User({
          _id: new mongoose.Types.ObjectId,
          email: email,
          firstname:  firstname, 
          lastname: lastname,
          password: password,
          mobile: mobile

      }).save();
      //Cache the data
      try {
         await client.HSET(incoming_user[login_method],'id', user._id);
         await client.HSET(incoming_user[login_method], 'email', email);
         await client.HSET(incoming_user[login_method], 'firstname', firstname);
         await client.HSET(incoming_user[login_method], 'lastname', lastname);
         await client.HSET(incoming_user[login_method],'mobile',mobile);
         await client.HSET(incoming_user[login_method],'password',password);

      } catch (error) {
          console.log(error);
      }
   
      // Step 2 - Generate a verification token with the user's ID
      const verificationToken = user.generateVerificationToken();
      //console.log(verificationToken);
      // Step 3 - Email the user a unique verification link
      const url = `http://localhost:3000/api/verify/${verificationToken}/${login_method}`;
      console.log(url);
      if(login_method=="email"){
         transporter.sendMail({
            to: email,
            subject: 'Verify Account',
            html: `Click <a href = '${url}'>here</a> to confirm your email.`
         })
         return res.status(201).send({
            message: `Sent a verification email to ${email}`
         });
      }
      else if(login_method=="mobile"){
         var options = {authorization : "zRoW9QuKVcC5qhgIYnbDXrmPdZT36iajk8pJ4tFUL2xvNwESAybHQcfnlaOJ2DBqIVsg46F0ijUrzM38" , message : url,  numbers : [mobile]} ;
         fast2sms.sendMessage(options).then(response=>{
           res.status(201).send(response);
         })
      }
      
   } catch(err){
      return res.status(500).send(err);
   }
}
exports.verify = async (req, res) => {
    console.log("verify called");
    const { token } = req.params;
    const { user_varification_type } = req.params;
    // Check we have an id
    if (!token) {
        return res.status(422).send({ 
             message: "Missing Token" 
        });
    }
    // Step 1 -  Verify the token from the URL
    let payload = null
    try {
        payload = jwt.verify(
           token,
           process.env.USER_VERIFICATION_TOKEN_SECRET
        );
    } catch (err) {
        return res.status(500).send(err);
    }
    try{
        // Step 2 - Find user with matching ID
        const user = await User.findOne({ _id: payload.ID }).exec();
        if (!user) {
           return res.status(404).send({ 
              message: "User does not  exists" 
           });
        }
        // Step 3 - Update user verification status to true
        if(user_varification_type=="mobile"){
             user.mobile_verified = true;
        }
        else if(user_varification_type=="email"){
             user.mail_verified = true;
        }
        await user.save();
        return res.status(200).send({
              message: "Account Verified"
        });
     } catch (err) {
        return res.status(500).send(err);
     }
}
exports.login = async (req, res) => {
    const login_method = req.params.login_method;
    incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    //console.log(incoming_user[login_method])
    if (!incoming_user[login_method]) {
        return res.status(422).send({ 
             message: `Missing ${login_method}` 
        });
    }
    try{
        // Step 1 - Verify a user with the email exists
        const user = await User.findOne(incoming_user).exec();
        if (!user) {
             return res.status(404).send({ 
                   message: "User does not exists" 
             });
        }
        // Step 2 - Ensure the account has been verified
        if(login_method=="email"&&!user.mail_verified){
             return res.status(403).send({ 
                   message: "Verify your Account." 
             });
        }
        else if(login_method=="mobile"&&!user.mobile_verified){
         return res.status(403).send({ 
            message: "Verify your Account." 
         }); 

        }
        user.comparePassword(req.body.password, function(err, isMatch) {
         if (err) throw err;
         console.log('Password Matched', isMatch);
         if(isMatch){
                
            return res.status(200).send({
               message: "User logged in"
            });
         }
         else{
            return res.status(403).send({ 
               message: "Wrong Password" 
         });
         }
         
     });
     } catch(err) {
        console.log(err);
        return res.status(500).send(err);
     }
}
exports.forgotpassword= async (req, res) => {
      const login_method = req.params.login_method;
      incoming_user = {};
      incoming_user[login_method] = req.body[login_method];
      const user = await User.findOne(incoming_user).exec();
      const verificationToken = user.generateVerificationToken();
      const encodedData = btoa(req.body.newpassword.toString());
      const Password = encodedData;
      //console.log(verificationToken);
      // Step 3 - Email the user a unique verification link
      const url = `http://localhost:3000/api/reset/${verificationToken}/${Password}`;
      console.log(url);
      console.log(login_method);
      if(login_method=="mobile"){
         var options = {authorization : "zRoW9QuKVcC5qhgIYnbDXrmPdZT36iajk8pJ4tFUL2xvNwESAybHQcfnlaOJ2DBqIVsg46F0ijUrzM38" , 
                       message : "your reset link: "+url,  numbers : [incoming_user[login_method]]} ;
         fast2sms.sendMessage(options).then(response=>{
         console.log(response);
         })
         return res.status(201).send({
         message: `Sent a verification sms to ${login_method}`
         });

      }
      else if(login_method=="email"){
         transporter.sendMail({
            to: incoming_user[login_method],
            subject: 'Password Reset',
            html: `Click <a href = '${url}'>here</a> to confirm your email for password reset.`
         })
         return res.status(201).send({
            message: `Sent a verification email to ${login_method}`
         });
         
      }
}

exports.reset = async (req, res) => {
   console.log("reset called");
   const { token } = req.params
   // Check we have an id
   if (!token) {
       return res.status(422).send({ 
            message: "Missing Token" 
       });
   }
   // Step 1 -  Verify the token from the URL
   let payload = null
   try {
       payload = jwt.verify(
          token,
          process.env.USER_VERIFICATION_TOKEN_SECRET
       );
   } catch (err) {
       return res.status(500).send(err);
   }
   try{
       // Step 2 - Find user with matching ID
       const user = await User.findOne({ _id: payload.ID }).exec();
       if (!user) {
          return res.status(404).send({ 
             message: "User does not  exists" 
          });
       }
       // Step 3 - Update user verification status to true
       //console.log(req.params.Password);
       try{
         //var decrypted = CryptoJS.AES.decrypt(req.params.Password, key).toString(CryptoJS.enc.Utf8);
         const decodedData = atob(req.params.Password); 
         user.password = decodedData;
       }catch(err){
          console.log(error);
       }
       
       await user.save();
       return res.status(200).send({
             message: "Password Changed"
       });
    } catch (err) {
       return res.status(500).send(err);
    }
}

exports.getotp = async(req,res)=>{
   
      const { mobile } = req.body;
      // Check we have an email
      if (!mobile) {
          return res.status(422).send({ 
               message: "Missing mobile number." 
          });
      }
      try{
          // Step 1 - Verify a user with the email exists
          const user = await User.findOne({ mobile }).exec();
          if (!user) {
               return res.status(404).send({ 
                     message: "User does not exists" 
               });
          }
          // Step 2 - Ensure the account has been verified
          if(!user.mobile_verified){
               return res.status(403).send({ 
                     message: "Verify your Account." 
               });
          }
          const otp = otpGenerator.generate(8, { alphabets: false, upperCase: false, specialChars: false,lowerCaseAlphabets: false });
          var options = {authorization : "zRoW9QuKVcC5qhgIYnbDXrmPdZT36iajk8pJ4tFUL2xvNwESAybHQcfnlaOJ2DBqIVsg46F0ijUrzM38" , message : "your otp: "+otp,  numbers : [mobile]} ;
          fast2sms.sendMessage(options).then(response=>{
          res.status(201).send(response);
          })
          user.otp=otp;
          user.save();
        } catch(err) {
          return res.status(500).send(err);
       }
}  
exports.loginotp = async(req,res)=>{
   const { mobile } = req.body;
   const {otp} = req.body;
   // Check we have an email
   if (!mobile) {
       return res.status(422).send({ 
            message: "Missing mobile number." 
       });
   }
   try{
       // Step 1 - Verify a user with the email exists
       const user = await User.findOne({ mobile }).exec();
       if (!user) {
            return res.status(404).send({ 
                  message: "User does not exists" 
            });
       }
       // Step 2 - Ensure the account has been verified
       if(!user.mobile_verified){
            return res.status(403).send({ 
                  message: "Verify your Account." 
            });
       }
       if(user.otp!=otp){ 
            return res.status(401).send({ 
               message: "Wrong OTP" 
           });
       }
       if(user.otp==otp){
             console.log("LOGGED IN");
             return res.status(200).send({ 
               message: "Logged In" 
           });
       }
     } catch(err) {
       return res.status(500).send(err);
    }

}
exports.update = async (req, res) => {
   const login_method = req.params.login_method;
   incoming_user = {};
   incoming_user[login_method] = req.body[login_method];
   const user = await User.findOne(incoming_user).exec();
   const { email } = req.body;
   const { firstname } = req.body;
   const {lastname} = req.body;
   const{mobile} = req.body;
   if(login_method=="mobile"){
         if(req.body.firstname){
         user.firstname = firstname;
         }
         if(req.body.lastname){
         user.lastname = lastname;
         }
         if(req.body.email){
         user.email = email;
         }
         if(req.body.newpassword){
         user.password = req.body.newpassword;
         }
   }
   if(login_method=="email"){
      if(req.body.firstname){
      user.firstname = firstname;
      }
      if(req.body.lastname){
      user.lastname = lastname;
      }
      if(req.body.mobile){
      user.mobile = mobile;
      }
      if(req.body.newpassword){
      user.password = req.body.newpassword;
      }
      
   }
   console.log(user);
   user.save(function(){
   console.log("Saved");
   });
   return res.status(200).send({
   message: "Updated!!"
   });
        
}
exports.logInMiddwre =async (req, res, next) =>{
      //const { mobile } = req.body;
      const login_method = req.params.login_method;
      incoming_user = {};
      incoming_user[login_method] = req.body[login_method];
      // Check we have an valid login method
      if (!incoming_user[login_method]) {
          return res.status(422).send({ 
               message: `Missing ${login_method}.` 
          });
      }
      try{
          
          const user = await User.findOne(incoming_user).exec();
          if (!user) {
               return res.status(404).send({ 
                     message: "User does not exists" 
               });
          }
          // Step 2 - Ensure the account has been verified
          if(login_method=="mobile" && !user.mobile_verified){
            
               return res.status(403).send({ 
                     message: "Verify your Account." 
               });
          
          }
          if(login_method=="email" && !user.mail_verified){
            
               return res.status(403).send({ 
                     message: "Verify your Account." 
               });
          }
          user.comparePassword(req.body.password, function(err, isMatch) {
           if (err) throw err;
           console.log('Password Matched', isMatch);
           if(isMatch){
              next()   
           }
           else{
              return res.status(403).send({ 
                 message: "Wrong Password" 
           });
           }
           
       });
       } catch(err) {
          return res.status(500).send(err);
       }
}
exports.dispData = async(req,res)=>{
   const login_method = req.params.login_method;
   incoming_user = {};
   incoming_user[login_method] = req.body[login_method];
   try {
      var cache=await client.hGetAll(incoming_user[login_method]);
      //console.log(cache);
      //console.log(Object.keys(cache).length);
   } catch (error) {
      console.log(error);
   }
   if(Object.keys(cache).length!=0){
      return res.status(200).send({
         cache
      });
   }
   else{
      const user = await User.findOne(incoming_user).exec();
      return res.status(200).send({
         user
      });
   }
}