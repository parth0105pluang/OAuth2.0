import * as Joi from '@hapi/joi';

import logger from '../helpers/logger';
const schema = Joi.object({
    MONGO_ATLAS: Joi.string().uri()
        .required(),
    EMAIL_USERNAME: Joi.string().email()
        .required(),
    EMAIL_PASSWORD: Joi.string().required(),
    USER_VERIFICATION_TOKEN_SECRET: Joi.string().required(),
})
let envi;
try {
    const value = schema.validate({ MONGO_ATLAS: process.env.MONGO_ATLAS, USER_VERIFICATION_TOKEN_SECRET:process.env.USER_VERIFICATION_TOKEN_SECRET,EMAIL_USERNAME:process.env.EMAIL_USERNAME,EMAIL_PASSWORD: process.env.EMAIL_PASSWORD})
    envi=value;
    logger.info(value);
}
catch (err) { 
    logger.info(err);
}

/*const envi= {
    MONGO_ATLAS: process.env.MONGO_ATLAS,
    EMAIL_USERNAME: process.env.EMAIL_USERNAME,
    EMAIL_PASSWORD: process.env.EMAIL_PASSWORD,
    USER_VERIFICATION_TOKEN_SECRET: process.env.USER_VERIFICATION_TOKEN_SECRET
};*/
export default envi;
