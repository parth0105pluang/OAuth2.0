const express = require('express');
const router = express.Router();
const UserController = require('../controllers/user_controller.js');
var key = "2e35f242a46d67eeb74aabc37d5e5d05";
router.post('/signup/mail', UserController.signupMail);
router.post('/signup/mobile', UserController.signupMobile);
router.post('/login', UserController.login);
router.get('/verify/:token', UserController.verify);
router.get('/reset/:token/:Password',UserController.reset);
router.put('/update',UserController.update);
router.post('/forgotpassword',UserController.forgotpassword);

module.exports = router;