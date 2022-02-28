require('dotenv').config();
const express = require("express");
const app = express();
const redis = require("redis");
const mongoose = require("mongoose");
//set up mongoDB connection

mongoose.connect(process.env.MONGO_ATLAS, {
    
})
.then(() => {
    console.log("Successfully connected to mongo.");
})
.catch((err) => {
    console.log("Error connecting to mongo.", err);
});
app.use(express.json()); // parse body
// routes
app.use('/api', require('./api/routes/routes.js'));
const PORT = 3000;
//const redisClient = redis.createClient();
app.listen(PORT, () => {
     console.log("Listening on port: " + PORT);
});