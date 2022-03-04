/* eslint-disable sonarjs/no-duplicate-string */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable sonarjs/cognitive-complexity */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable promise/always-return */
/* eslint-disable promise/catch-or-return */
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
export async function signup(req, res) {
    const LoginMethod = req.params.LoginMethod;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    const { mobile } = req.body;
    const { email } = req.body;
    const { firstname } = req.body;
    const { lastname } = req.body;
    const { password } = req.body;
    if (!IncomingUser[LoginMethod]) {
        return res.status(422).send({ message: `Missing ${LoginMethod}` });
    }
    try {
        // Check if the email is in use
        const existingUser = await User.findOne(IncomingUser).exec();
        if (existingUser) {
            return res.status(409).send({
                message: `${LoginMethod} is already in use.`,
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
                IncomingUser[LoginMethod],
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
                if (err) {
                    console.log(err);
                }
                client.HSET(IncomingUser[LoginMethod], 'password', hash);
            });
        } catch (error) {
            console.log(error);
        }

        // Step 2 - Generate a verification token with the user's ID
        const verificationToken = user.generateVerificationToken();
        // Step 3 - Email the user a unique verification link
        const url = `http://localhost:3000/user/verify/${verificationToken}/${LoginMethod}`;
        console.log(url);
        if (LoginMethod == 'email') {
            transporter.sendMail({
                to: email,
                subject: 'Verify Account',
                html: `Click <a href = '${url}'>here</a> to confirm your email.`,
            });
            return res.status(201).send({
                message: `Sent a verification email to ${email}`,
            });
        } else if (LoginMethod == 'mobile') {
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
    const { UserVerificationType } = req.params;
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
        const cache = await client.hGetAll(user[UserVerificationType]);
        if (!user) {
            return res.status(404).send({
                message: 'User does not  exists',
            });
        }
        // Step 3 - Update user verification status to true
        if (UserVerificationType == 'mobile') {
            user.mobile_verified = true;
            if (Object.keys(cache).length != 0) {
                await client.HSET(user.mobile, 'mobile_verified', 'true');
            }
        } else if (UserVerificationType == 'email') {
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
    const LoginMethod = req.params.LoginMethod;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    //console.log(IncomingUser[LoginMethod])
    if (!IncomingUser[LoginMethod]) {
        return res.status(422).send({
            message: `Missing ${LoginMethod}`,
        });
    }

    const cache = await client.hGetAll(IncomingUser[LoginMethod]);
    if (Object.keys(cache).length != 0) {
        //console.log(cache.password);
        //console.log(cache.mail_verified);
        console.log('Searching Cache');
        if (
            (LoginMethod == 'email' && cache.mail_verified == 'false') ||
            (LoginMethod == 'mobile' && cache.mobile_verified == 'false')
        ) {
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
            const user = await User.findOne(IncomingUser).exec();
            if (!user) {
                return res.status(404).send({
                    message: 'User does not exists',
                });
            }
            // Step 2 - Ensure the account has been verified
            if (
                (LoginMethod == 'email' && !user.mail_verified) ||
                (LoginMethod == 'mobile' && !user.mobile_verified)
            ) {
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
    const LoginMethod = req.params.LoginMethod;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    const user = await User.findOne(IncomingUser).exec();
    const verificationToken = user.generateVerificationToken();
    const encodedData = btoa(req.body.newpassword.toString());
    const Password = encodedData;
    //console.log(verificationToken);
    // Step 3 - Email the user a unique verification link
    const url = `http://localhost:3000/user/reset/${verificationToken}/${Password}/${LoginMethod}`;
    console.log(url);
    console.log(LoginMethod);
    if (LoginMethod == 'mobile') {
        const options = {
            authorization: 'zRoW9QuKVcC5qhgIYnbDXrmPdZT36iajk8pJ4tFUL2xvNwESAybHQcfnlaOJ2DBqIVsg46F0ijUrzM38',
            message: 'your reset link: ' + url,
            numbers: [IncomingUser[LoginMethod]],
        };
        fast2sms.sendMessage(options).then((response: any) => {
            console.log(response);
        });
        return res.status(201).send({
            message: `Sent a verification sms to ${LoginMethod}`,
        });
    } else if (LoginMethod == 'email') {
        transporter.sendMail({
            to: IncomingUser[LoginMethod],
            subject: 'Password Reset',
            html: `Click <a href = '${url}'>here</a> to confirm your email for password reset.`,
        });
        return res.status(201).send({
            message: `Sent a verification email to ${LoginMethod}`,
        });
    }
}

export async function reset(req, res) {
    console.log('reset called');
    const { token } = req.params;
    const LoginMethod = req.params.LoginMethod;
    //IncomingUser = {};
    //IncomingUser[LoginMethod] = req.body[LoginMethod];
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
            const cache = await client.hGetAll(user[LoginMethod]);
            //console.log(LoginMethod);
            if (Object.keys(cache).length != 0) {
                if (
                    (LoginMethod == 'email' && cache.mail_verified == 'false') ||
                    (LoginMethod == 'mobile' && cache.mobile_verified == 'false')
                ) {
                    return res.status(403).send({
                        message: 'Verify your Account.',
                    });
                }
                const decodedData = atob(req.params.Password);
                //console.log("DecodedData: "+decodedData);
                bcrypt.hash(decodedData, 10, function (err: any, hash) {
                    client.HSET(user[LoginMethod], 'password', hash);
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
    const LoginMethod = req.params.LoginMethod;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    const user = await User.findOne(IncomingUser).exec();
    const cache = await client.hGetAll(IncomingUser[LoginMethod]);
    const { email } = req.body;
    const { firstname } = req.body;
    const { lastname } = req.body;
    const { mobile } = req.body;
    if (LoginMethod == 'mobile') {
        if (req.body.firstname) {
            user.firstname = firstname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'firstname', firstname);
            }
        }
        if (req.body.lastname) {
            user.lastname = lastname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'lastname', lastname);
            }
        }
        if (req.body.email) {
            user.email = email;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'email', email);
            }
        }
        if (req.body.newpassword) {
            user.password = req.body.newpassword;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'password', req.body.newpassword);
            }
        }
    }
    if (LoginMethod == 'email') {
        if (req.body.firstname) {
            user.firstname = firstname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'firstname', firstname);
            }
        }
        if (req.body.lastname) {
            user.lastname = lastname;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'lastname', lastname);
            }
        }
        if (req.body.mobile) {
            user.mobile = mobile;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'mobile', mobile);
            }
        }
        if (req.body.newpassword) {
            user.password = req.body.newpassword;
            if (Object.keys(cache).length != 0) {
                await client.HSET(IncomingUser[LoginMethod], 'password', req.body.newpassword);
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
    const LoginMethod = req.params.LoginMethod;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    // Check we have an valid login method
    if (!IncomingUser[LoginMethod]) {
        return res.status(422).send({
            message: `Missing ${LoginMethod}.`,
        });
    }

    const cache = await client.hGetAll(IncomingUser[LoginMethod]);

    if (Object.keys(cache).length != 0) {
        //console.log(cache.password);
        //console.log(cache.mail_verified);
        if (
            (LoginMethod == 'email' && cache.mail_verified == 'false') ||
            (LoginMethod == 'mobile' && cache.mobile_verified == 'false')
        ) {
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
            const user = await User.findOne(IncomingUser).exec();
            if (!user) {
                return res.status(404).send({
                    message: 'User does not exists',
                });
            }
            // Step 2 - Ensure the account has been verified
            if (LoginMethod == 'mobile' && !user.mobile_verified) {
                return res.status(403).send({
                    message: 'Verify your Account.',
                });
            }
            if (LoginMethod == 'email' && !user.mail_verified) {
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
    const LoginMethod = req.params.LoginMethod;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    const cache = await client.hGetAll(IncomingUser[LoginMethod]);

    if (Object.keys(cache).length != 0) {
        return res.status(200).send({
            cache,
        });
    } else {
        const user = await User.findOne(IncomingUser).exec();
        return res.status(200).send({
            user,
        });
    }
}
export async function deleteUser(req, res) {
    console.log('Delete Called');
    const LoginMethod = req.params.LoginMethod;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    const cache = await client.hGetAll(IncomingUser[LoginMethod]);
    const user = await User.findOne(IncomingUser).exec();
    if (Object.keys(cache).length != 0) {
        client
            .del(IncomingUser[LoginMethod])
            .then(function () {
                console.log('Data deleted from redis'); // Success
            })
            .catch(function (error) {
                console.log(error); // Failure
            });
    }
    if (user) {
        User.deleteOne(IncomingUser)
            .then(function () {
                console.log('Data deleted from mongo');
            })
            .catch(function (error) {
                console.log(error);
            });
    }
    return res.status(200).send({
        message: 'Deleted your account',
    });
}
