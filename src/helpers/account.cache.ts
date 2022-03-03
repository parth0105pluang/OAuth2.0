/* eslint-disable no-console */
import * as redis from 'redis';
const client = redis.createClient();

client.on('error', (err) => console.log('Redis Client Error', err));
client.on('connect', function (err) {
    if (err) {
        console.log(err);
    }
    console.log('Connected to redis successfully');
});
client.connect();
export = client;
