/* eslint-disable @typescript-eslint/no-this-alias */
import * as bcrypt from 'bcrypt';
import * as mongoose from 'mongoose';

const SALT_WORK_FACTOR = 10;

const AppSchema = new mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    redirectLink: String,
    appName: String,
    AppKey:String
});
AppSchema.pre('save', function (next) {
    const app = this;
    bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
        if (err) return next(err);

        bcrypt.hash(app.AppKey, salt, function (error, hash) {
            if (error) return next(error);
            // override the cleartext password with the hashed one
            app.AppKey = hash;
            next();
        });
    });
});
AppSchema.methods.compareKey = function (AppKey, cb) {
    bcrypt.compare(AppKey, this.AppKey, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};
export default mongoose.model('App', AppSchema);
