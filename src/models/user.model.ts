/* eslint-disable unicorn/filename-case */
/* eslint-disable @typescript-eslint/no-this-alias */
import * as bcrypt from 'bcrypt';
import * as mongoose from 'mongoose';
const SALT_WORK_FACTOR = 10;
import * as jwt from 'jsonwebtoken';
import { env } from 'process';
const UserSchema = new mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    email: String,
    firstname: String,
    lastname: String,
    password: { type: String, required: true },
    mobile: { type: String },
    mail_verified: {
        type: Boolean,
        required: true,
        default: false,
    },
    mobile_verified: {
        type: Boolean,
        required: true,
        default: false,
    },
    otp: {
        type: String,
    },
});
UserSchema.pre('save', function (next) {
    const user = this;

    // only hash the password if it has been modified (or is new)
    if (!user.isModified('password')) return next();

    // generate a salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, function (error, hash) {
            if (error) return next(error);
            // override the cleartext password with the hashed one
            user.password = hash;
            next();
        });
    });
});
UserSchema.methods.generateVerificationToken = function () {
    const user = this;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return jwt.sign({ ID: user._id }, env.USER_VERIFICATION_TOKEN_SECRET!, {
        expiresIn: '7d',
    });
};
UserSchema.methods.comparePassword = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};
export default mongoose.model('User', UserSchema);
