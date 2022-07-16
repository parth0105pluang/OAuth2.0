import * as redis from 'redis';

import logger from './logger';
const client = redis.createClient();

client.on('error', (err) => logger.info('Redis Client Error', err));
client.on('connect', function (err) {
    if (err) {
        logger.info(err);
    }
    logger.info('Connected to redis successfully');
});
client.connect();
export async function addUser(user, key) {
    await client.sendCommand([
        'hmset',
        key,
        'id',
        user._id,
        'email',
        user.email,
        'firstname',
        user.firstname,
        'lastname',
        user.lastname,
        'mobile',
        user.mobile,
        'mail_verified',
        'false',
        'mobile_verified',
        'false',
    ]);
}
export async function addFeild(key, feildName, value) {
    return client.HSET(key, feildName, value);
}
export async function GetAll(key) {
    return client.hGetAll(key);
}
export async function delUser(key) {
    return client.del(key);
}
