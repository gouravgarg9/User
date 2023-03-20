require('dotenv').config();
const path = require('path');
const mongoose = require('mongoose');

process.on('uncaughtException',(err)=>{
    console.log(err);
    process.exit(1);
})

const app = require('./app');

const DB = process.env.DB_CONN_STR
mongoose.connect(DB,{
    useNewUrlParser: true
})
.then(() => console.log('DB connection successful!'));

const port = process.env.PORT;
const server = app.listen(port,() => console.log("Server running on port :",port));

process.on('unhandledRejection',(err)=>{
    console.log(err);
    server.close(()=>process.exit(1));
})