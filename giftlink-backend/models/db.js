// db.js
require('dotenv').config();
const MongoClient = require('mongodb').MongoClient;
// console.log('Mongo URL:', process.env.MONGO_URL);

// MongoDB connection URL with authentication options
let url = `${process.env.MONGO_URL}`;

let dbInstance = null;
const dbName = "giftdb";

async function connectToDatabase() {
    if (dbInstance){
        return dbInstance
    };

    // const client = new MongoClient(url);
    const client = new MongoClient(url, { useUnifiedTopology: true });
    
    await client.connect();
    dbInstance = client.db(dbName);
    return dbInstance;  

    // Task 1: Connect to MongoDB
    // {{insert code}}

    // Task 2: Connect to database giftDB and store in variable dbInstance
    //{{insert code}}

    // Task 3: Return database instance
    // {{insert code}}
}

module.exports = connectToDatabase;
