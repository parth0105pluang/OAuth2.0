/* eslint-disable unicorn/filename-case */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable sonarjs/cognitive-complexity */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable sonarjs/no-duplicated-branches */
/* eslint-disable sonarjs/no-duplicate-string */
/* eslint-disable promise/always-return */
/* eslint-disable promise/catch-or-return */
/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable no-console */
/* eslint-disable unicorn/filename-case */
/* eslint-disable @typescript-eslint/no-var-requires */
import * as bcrypt from 'bcrypt';
import * as fast2sms from 'fast-two-sms';
import * as jwt from 'jsonwebtoken';
import * as mongoose from 'mongoose';
import * as nodemailer from 'nodemailer';
import * as otpGenerator from 'otp-generator';

import * as client from '../helpers/account.cache';
import User from '../models/user_model';
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

const transporter = nodemailer.createTransport({
    service: 'Gmail',
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
export async function signup(req, res) {
    const login_method = req.params.login_method;
    const incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    const { mobile } = req.body;
    const { email } = req.body;
    const { firstname } = req.body;
    const { lastname } = req.body;
    const { password } = req.body;
    if (!incoming_user[login_method]) {
        return res.status(422).send({ message: `Missing ${login_method}` });
    }
    try {
        // Check if the email is in use
        const existingUser = await User.findOne(incoming_user).exec();
        if (existingUser) {
            return res.status(409).send({
                message: `${login_method} is already in use.`,
            });
        }
        // Step 1 - Create and save the user
        const user = await new User({
            _id: new mongoose.Types.ObjectId(),
            email: email,
            firstname: firstname,
            lastname: lastname,
            password: password,
            mobile: mobile,
        }).save();
        //Cache the data
        try {
            await client.sendCommand([
                'hmset',
                incoming_user[login_method],
                'id',
                user._id,
                'email',
                email,
                'firstname',
                firstname,
                'lastname',
                lastname,
                'mobile',
                mobile,
                'mail_verified',
                'false',
                'mobile_verified',
                'false',
            ]);

            bcrypt.hash(password, 10, function (err: any, hash) {
                //console.log(err);
                client.HSET(incoming_user[login_method], 'password', hash);
            });
        } catch (error) {
            console.log(error);
        }

        // Step 2 - Generate a verification token with the user's ID
        const verificationToken = user.generateVerificationToken();
        //console.log(verificationToken);
        // Step 3 - Email the user a unique verification link
        const url = `http://localhost:3000/user/verify/${verificationToken}/${login_method}`;
        console.log(url);
        if (login_method == 'email') {
            transporter.sendMail({
                to: email,
                subject: 'Verify Account',
                html: `Click <a href = '${url}'>here</a> to confirm your email.`,
            });
            return res.status(201).send({
                message: `Sent a verification email to ${email}`,
            });
        } else if (login_method == 'mobile') {
            const options = {
                authorization: 'zRoW9QuKVcC5qhgIYnbDXrmPdZT36iajk8pJ4tFUL2xvNwESAybHQcfnlaOJ2DBqIVsg46F0ijUrzM38',
                message: url,
                numbers: [mobile],
            };
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            fast2sms.sendMessage(options).then((response: any) => {
                res.status(201).send(response);
            });
        }
    } catch (err) {
        console.log(err);
        return res.status(500).send(err);
    }
}
export async function verify(req, res) {
    console.log('verify called');
    const { token } = req.params;
    const { user_varification_type } = req.params;
    // Check we have an id
    if (!token) {
        return res.status(422).send({
            message: 'Missing Token',
        });
    }
    // Step 1 -  Verify the token from the URL
    let payload;
    try {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        payload = jwt.verify(token, process.env.USER_VERIFICATION_TOKEN_SECRET!);
    } catch (err) {
        return res.status(500).send(err);
    }
    try {
        // Step 2 - Find user with matching ID
        const user = await User.findOne({ _id: payload.ID }).exec();
        const cache = await client.hGetAll(user[user_varification_type]);
        if (!user) {
            return res.status(404).send({
                message: 'User does not  exists',
            });
        }
        // Step 3 - Update user verification status to true
        if (user_varification_type == 'mobile') {
            user.mobile_verified = true;
            if (Object.keys(cache).length != 0) {
                await client.HSET(user.mobile, 'mobile_verified', 'true');
            }
        } else if (user_varification_type == 'email') {
            user.mail_verified = true;
            if (Object.keys(cache).length != 0) {
                await client.HSET(user.email, 'mail_verified', 'true');
            }
        }
        await user.save();
        return res.status(200).send({
            message: 'Account Verified',
        });
    } catch (err) {
        console.log(err);
        return res.status(500).send(err);
    }
}
export async function login(req, res) {
    const login_method = req.params.login_method;
    const incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    //console.log(incoming_user[login_method])
    if (!incoming_user[login_method]) {
        return res.status(422).send({
            message: `Missing ${login_method}`,
        });
    }

    const cache = await client.hGetAll(incoming_user[login_method]);
    if (Object.keys(cache).length != 0) {
        //console.log(cache.password);
        //console.log(cache.mail_verified);
        console.log('Searching Cache');
        if (login_method == 'email' && cache.mail_verified == 'false') {
            return res.status(403).send({
                message: 'Verify your Account.',
            });
        } else if (login_method == 'mobile' && cache.mobile_verified == 'false') {
            return res.status(403).send({
                message: 'Verify your Account.',
            });
        }
        bcrypt.compare(req.body.password, cache.password, function (err: any, result: boolean) {
            console.log(err);
            if (result) {
                return res.status(200).send({
                    cache,
                });
            } else {
                return res.status(403).send({
                    message: 'Wrong Password',
                });
            }
        });
    } else {
        try {
            // Step 1 - Verify a user with the email exists
            const user = await User.findOne(incoming_user).exec();
            if (!user) {
                return res.status(404).send({
                    message: 'User does not exists',
                });
            }
            // Step 2 - Ensure the account has been verified
            if (login_method == 'email' && !user.mail_verified) {
                return res.status(403).send({
                    message: 'Verify your Account.',
                });
            } else if (login_method == 'mobile' && !user.mobile_verified) {
                return res.status(403).send({
                    message: 'Verify your Account.',
                });
            }
            user.comparePassword(req.body.password, function (err: any, isMatch: any) {
                if (err) throw err;
                console.log('Password Matched', isMatch);
                if (isMatch) {
                    return res.status(200).send({
                        message: 'User logged in',
                    });
                } else {
                    return res.status(403).send({
                        message: 'Wrong Password',
                    });
                }
            });
        } catch (err) {
            console.log(err);
            return res.status(500).send(err);
        }
    }
}
export async function forgotpassword(req, res) {
    const login_method = req.params.login_method;
    const incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    const user = await User.findOne(incoming_user).exec();
    const verificationToken = user.generateVerificationToken();
    const encodedData = btoa(req.body.newpassword.toString());
    const Password = encodedData;
    //console.log(verificationToken);
    // Step 3 - Email the user a unique verification link
    const url = `http://localhost:3000/user/reset/${verificationToken}/${Password}/${login_method}`;
    console.log(url);
    console.log(login_method);
    if (login_method == 'mobile') {
        const options = {
            authorization: 'zRoW9QuKVcC5qhgIYnbDXrmPdZT36iajk8pJ4tFUL2xvNwESAybHQcfnlaOJ2DBqIVsg46F0ijUrzM38',
            message: 'your reset link: ' + url,
            numbers: [incoming_user[login_method]],
        };
        fast2sms.sendMessage(options).then((response: any) => {
            console.log(response);
        });
        return res.status(201).send({
            message: `Sent a verification sms to ${login_method}`,
        });
    } else if (login_method == 'email') {
        transporter.sendMail({
            to: incoming_user[login_method],
            subject: 'Password Reset',
            html: `Click <a href = '${url}'>here</a> to confirm your email for password reset.`,
        });
        return res.status(201).send({
            message: `Sent a verification email to ${login_method}`,
        });
    }
}

export async function reset(req, res) {
    console.log('reset called');
    const { token } = req.params;
    const login_method = req.params.login_method;
    //incoming_user = {};
    //incoming_user[login_method] = req.body[login_method];
    // Check we have an id
    if (!token) {
        return res.status(422).send({
            message: 'Missing Token',
        });
    }
    // Step 1 -  Verify the token from the URL
    let payload;
    try {
        payload = jwt.verify(token, process.env.USER_VERIFICATION_TOKEN_SECRET!);
    } catch (err) {
        return res.status(500).send(err);
    }
    try {
        // Step 2 - Find user with matching ID
        const user = await User.findOne({ _id: payload.ID }).exec();
        if (!user) {
            return res.status(404).send({
                message: 'User does not  exists',
            });
        }
        // Step 3 - Update user verification status to true
        //console.log(req.params.Password);
        try {
            //var decrypted = CryptoJS.AES.decrypt(req.params.Password, key).toString(CryptoJS.enc.Utf8);
            const cache = await client.hGetAll(user[login_method]);
            //console.log(login_method);
            if (Object.keys(cache).length != 0) {
                if (login_method == 'email' && cache.mail_verified == 'false') {
                    return res.status(403).send({
                        message: 'Verify your Account.',
                    });
                } else if (login_method == 'mobile' && cache.mobile_verified == 'false') {
                    return res.status(403).send({
                        message: 'Verify your Account.',
                    });
                }
                const decodedData = atob(req.params.Password);
                //console.log("DecodedData: "+decodedData);
                bcrypt.hash(decodedData, 10, function (err: any, hash) {
                    client.HSET(user[login_method], 'password', hash);
                });
            }
            const decodedData = atob(req.params.Password);
            user.password = decodedData;
        } catch (err) {
            console.log(err);
        }

        await user.save();
        return res.status(200).send({
            message: 'Password Changed',
        });
    } catch (err) {
        return res.status(500).send(err);
    }
}

export async function getotp(req, res) {
    const { mobile } = req.body;
    // Check we have an email
    if (!mobile) {
        return res.status(422).send({
            message: 'Missing mobile number.',
        });
    }
    try {
        // Step 1 - Verify a user with the email exists
        const user = await User.findOne({ mobile }).exec();
        if (!user) {
            return res.status(404).send({
                message: 'User does not exists',
            });
        }
        // Step 2 - Ensure the account has been verified
        if (!user.mobile_verified) {
            return res.status(403).send({
                message: 'Verify your Account.',
            });
        }
        const otp = otpGenerator.generate(8, {});
        const options = {
            authorization: 'zRoW9QuKVcC5qhgIYnbDXrmPdZT36iajk8pJ4tFUL2xvNwESAybHQcfnlaOJ2DBqIVsg46F0ijUrzM38',
            message: 'your otp: ' + otp,
            numbers: [mobile],
        };
        fast2sms.sendMessage(options).then((response) => {
            res.status(201).send(response);
        });
        user.otp = otp;
        user.save();
    } catch (err) {
        return res.status(500).send(err);
    }
}
export async function loginotp(req, res) {
    const { mobile } = req.body;
    const { otp } = req.body;
    // Check we have an email
    if (!mobile) {
        return res.status(422).send({
            message: 'Missing mobile number.',
        });
    }
    try {
        // Step 1 - Verify a user with the email exists
        const user = await User.findOne({ mobile }).exec();
        if (!user) {
            return res.status(404).send({
                message: 'User does not exists',
            });
        }
        // Step 2 - Ensure the account has been verified
        if (!user.mobile_verified) {
            return res.status(403).send({
                message: 'Verify your Account.',
            });
        }
        if (user.otp != otp) {
            return res.status(401).send({
                message: 'Wrong OTP',
            });
        }
        if (user.otp == otp) {
            console.log('LOGGED IN');
            return res.status(200).send({
                message: 'Logged In',
            });
        }
    } catch (err) {
        console.log(err);
        return res.status(500).send(err);
    }
}
export async function update(req, res) {
    const login_method = req.params.login_method;
    const incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    const user = await User.findOne(incoming_user).exec();
    const cache = await client.hGetAll(incoming_user[login_method]);
    const { email } = req.body;
    const { firstname } = req.body;
    const { lastname } = req.body;
    const { mobile } = req.body;
    if (login_method == 'mobile') {
        if (req.body.firstname) {
            user.firstname = firstname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'firstname', firstname);
            }
        }
        if (req.body.lastname) {
            user.lastname = lastname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'lastname', lastname);
            }
        }
        if (req.body.email) {
            user.email = email;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'email', email);
            }
        }
        if (req.body.newpassword) {
            user.password = req.body.newpassword;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'password', req.body.newpassword);
            }
        }
    }
    if (login_method == 'email') {
        if (req.body.firstname) {
            user.firstname = firstname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'firstname', firstname);
            }
        }
        if (req.body.lastname) {
            user.lastname = lastname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'lastname', lastname);
            }
        }
        if (req.body.mobile) {
            user.mobile = mobile;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'mobile', mobile);
            }
        }
        if (req.body.newpassword) {
            user.password = req.body.newpassword;
            if (Object.keys(cache).length != 0) {
                await client.HSET(incoming_user[login_method], 'password', req.body.newpassword);
            }
        }
    }
    console.log(user);
    user.save(function () {
        console.log('Saved');
    });
    return res.status(200).send({
        message: 'Updated!!',
    });
}
export async function logInMiddwre(req, res, next: () => void) {
    //const { mobile } = req.body;
    const login_method = req.params.login_method;
    const incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    // Check we have an valid login method
    if (!incoming_user[login_method]) {
        return res.status(422).send({
            message: `Missing ${login_method}.`,
        });
    }

    const cache = await client.hGetAll(incoming_user[login_method]);

    if (Object.keys(cache).length != 0) {
        //console.log(cache.password);
        //console.log(cache.mail_verified);
        if (login_method == 'email' && cache.mail_verified == 'false') {
            return res.status(403).send({
                message: 'Verify your Account.',
            });
        } else if (login_method == 'mobile' && cache.mobile_verified == 'false') {
            return res.status(403).send({
                message: 'Verify your Account.',
            });
        }
        bcrypt.compare(req.body.password, cache.password, function (err: any, result: boolean) {
            if (result) {
                next();
            } else {
                return res.status(403).send({
                    message: 'Wrong Password',
                });
            }
        });
    } else {
        try {
            const user = await User.findOne(incoming_user).exec();
            if (!user) {
                return res.status(404).send({
                    message: 'User does not exists',
                });
            }
            // Step 2 - Ensure the account has been verified
            if (login_method == 'mobile' && !user.mobile_verified) {
                return res.status(403).send({
                    message: 'Verify your Account.',
                });
            }
            if (login_method == 'email' && !user.mail_verified) {
                return res.status(403).send({
                    message: 'Verify your Account.',
                });
            }
            user.comparePassword(req.body.password, function (err: any, isMatch: any) {
                if (err) throw err;
                console.log('Password Matched', isMatch);
                if (isMatch) {
                    next();
                } else {
                    return res.status(403).send({
                        message: 'Wrong Password',
                    });
                }
            });
        } catch (err) {
            return res.status(500).send(err);
        }
    }
}
export async function dispData(req, res) {
    const login_method = req.params.login_method;
    const incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    const cache = await client.hGetAll(incoming_user[login_method]);

    if (Object.keys(cache).length != 0) {
        return res.status(200).send({
            cache,
        });
    } else {
        const user = await User.findOne(incoming_user).exec();
        return res.status(200).send({
            user,
        });
    }
}
export async function deleteUser(req,res){
    console.log("Delete Called");
    const login_method = req.params.login_method;
    const incoming_user = {};
    incoming_user[login_method] = req.body[login_method];
    const cache = await client.hGetAll(incoming_user[login_method]);
    const user = await User.findOne(incoming_user).exec();
    if (Object.keys(cache).length != 0) {
        client.del(incoming_user[login_method]);
    } 
    if(user){
        User.remove(incoming_user, function(err) {
            if (err) {
                console.log(err);
            }

        });
    }
    return res.status(200).send({
        message: 'Deleted your account'
    });
} 
