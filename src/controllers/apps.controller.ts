import * as mongoose from 'mongoose';

import logger from '../helpers/logger';
import App from '../models/apps.model';
import User from '../models/user.model';
export async function registerApp(req,res){
    const {redirectLink} = req.body;
    const{appName} = req.body;
    const {AppKey} = req.body;
    const incomingApp={
        "appName":appName
    }
    try {
        // Check if the appName is in use
        const existingApp = await App.findOne(incomingApp).exec();
        if (existingApp) {
            return res.status(409).send({
                message: `${appName} is already in use.`,
            });
        }
        // Step 1 - Create and save the App
        const app = await new App({
            _id: new mongoose.Types.ObjectId(),
            redirectLink: redirectLink,
            appName: appName,
            AppKey: AppKey
        }).save();
        logger.info(app);
        return res.status(200).send({
            message:"App Registered"
        });
    }catch(error){
        logger.info(error); // Failure
    }
}
export async function reqToken(req,res){
    const LoginMethod = req.params.LoginMethod;
    const appName = req.params.appName;
    const IncomingUser = {};
    IncomingUser[LoginMethod] = req.body[LoginMethod];
    const IncomingApp={
        "appName":appName
    }
    const user = await User.findOne(IncomingUser).exec();
    const app = await App.findOne(IncomingApp).exec();
    if(app==null){
        return res.status(404).send({
            message: "No such app exits!!",
        });
    }
    const url = app.redirectLink;
    if(user.ExternalAppToken){
        logger.info("came inside");
        const token = user.ExternalAppToken;
        const rdr = url+`${token}`
        return res.redirect(rdr);
        /*return res.status(200).send({
            token
        });*/
    }
    else{
        const verificationToken = user.generateVerificationToken();
        user.ExternalAppToken = verificationToken;
        user.save();
        return res.redirect(url+`/${verificationToken}`);
        /*return res.status(200).send({
            verificationToken 
        });*/
    }

}
export async function ValidateAppKey(req, res, next: () => void){
    const {appName} = req.body;
    const IncomingApp={
        "appName":appName
    }
    const app = await App.findOne(IncomingApp).exec();
    if(app==null){
        return res.status(404).send({
            message: "No app exists",
        });
    }
    else{
        app.compareKey(req.params.AppKey, function (err, isMatch) {
            if (err) throw err;
            if (isMatch) {
                next();
            } else {
                return res.status(403).send({
                    message: "Wrong Key!!",
                });
            }
        });
    }
}
export async function validateToken(req,res){

    //logger.info("Sample Route Yet"+req+res);
    const token = req.params.token;
    logger.info(token);
    const user = await User.findOne({ ExternalAppToken:token } ).exec();
    const userData={
        firstname:user.firstname,
        lastname:user.lastname
    }
    res.status(200).send({
        userData
    })
}
