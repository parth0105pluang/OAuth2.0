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
export = client;
