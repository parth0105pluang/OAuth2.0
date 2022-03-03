/* eslint-disable promise/always-return */
/* eslint-disable no-console */

import { config } from 'dotenv';
import * as express from 'express';
const app = express();
//import redis from "redis";
import * as mongoose from 'mongoose';
//set up mongoDB connection
config();
import { userRouter } from './routes';
const PORT = 3000;
mongoose
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    .connect(process.env.MONGO_ATLAS!, {})
    .then(() => {
        console.log('Successfully connected to mongo.');
    })
    .catch((err) => {
        console.log('Error connecting to mongo.', err);
    });
app.use(express.json()); // parse body
// routes
// eslint-disable-next-line @typescript-eslint/no-var-requires
app.use('/user', userRouter);
//const redisClient = redis.createClient();
app.listen(PORT, () => {
    console.log('Listening on port: ' + PORT);
});
