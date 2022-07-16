import Joi from 'joi';

import logger from '../helpers/logger';

interface Environment {
    MONGO_ATLAS: string;
    EMAIL_USERNAME: string;
    EMAIL_PASSWORD: string;
    USER_VERIFICATION_TOKEN_SECRET: string;
}

const schema = Joi.object({
    MONGO_ATLAS: Joi.string().uri()
        .required(),
    EMAIL_USERNAME: Joi.string().email()
        .required(),
    EMAIL_PASSWORD: Joi.string().required(),
    USER_VERIFICATION_TOKEN_SECRET: Joi.string().required(),
}).options({ stripUnknown: true, convert: true, abortEarly: false });

let envi: Environment;

try {
    const value = schema.validate({
        MONGO_ATLAS: process.env.MONGO_ATLAS,
        USER_VERIFICATION_TOKEN_SECRET: process.env.USER_VERIFICATION_TOKEN_SECRET,
        EMAIL_USERNAME: process.env.EMAIL_USERNAME,
        EMAIL_PASSWORD: process.env.EMAIL_PASSWORD,
    });
    envi = value.value;
    logger.info(value);
} catch (err) {
    logger.info(err);
    throw err;
}
export default envi;
