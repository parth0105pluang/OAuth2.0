import { config } from 'dotenv';
import * as express from 'express';
import * as session from 'express-session';
//import * as oauth2orize from "oauth2orize"
const app = express();
//const oauth = oauth2orize.createServer();
//import redis from "redis";
import * as mongoose from 'mongoose';
//set up mongoDB connection
config();
import  envi  from './config';

import logger from './helpers/logger';
import { appsRouter,userRouter  } from './routes';
const PORT = 3000;
mongoose
    .connect(envi.MONGO_ATLAS as string, {})
    .then(() => {
        logger.info('Successfully connected to mongo.');
        return "connected mongo"
    })
    .catch((err) => {
        logger.info('Error connecting to mongo.', err);
    });
app.use(express.json()); // parse body
app.use(session({secret:'random-sec',
    resave: true,
    saveUninitialized: true
}));
app.use('/user', userRouter);
app.use('/app', appsRouter);
//const redisClient = redis.createClient();
app.listen(PORT, () => {
    logger.info('Listening on port: ' + PORT);
});
