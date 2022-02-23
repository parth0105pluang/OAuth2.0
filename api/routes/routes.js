const express = require('express');
const router = express.Router();
const UserController = require('../controllers/user_controller.js');
router.post('/signup', UserController.signup);
router.post('/login', UserController.login);
router.get('/verify/:token', UserController.verify);
router.put('/update',UserController.update);
module.exports = router;
