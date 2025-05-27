const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const dotenv = require('dotenv');
const pino = require('pino');

const router = express.Router();
const logger = pino();

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', 
    // Optional: Add validation middleware here if needed
    async (req, res) => {
        try {
            // Connect to database
            const db = await connectToDatabase();

            // Access users collection
            const collection = db.collection("users");

            // Check if email already exists
            const existingEmail = await collection.findOne({ email: req.body.email });
            if (existingEmail) {
                return res.status(400).json({ error: "Email already registered" });
            }

            // Hash the password
            const salt = await bcryptjs.genSalt(10);
            const hash = await bcryptjs.hash(req.body.password, salt);

            // Save new user details
            const newUser = await collection.insertOne({
                email: req.body.email,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                password: hash,
                createdAt: new Date(),
            });

            // Create JWT token payload
            const payload = {
                user: {
                    id: newUser.insertedId,
                },
            };

            // Sign token with secret key
            const authtoken = jwt.sign(payload, JWT_SECRET);

            logger.info('User registered successfully');

            // Send response
            res.json({ authtoken, email: req.body.email });
        } catch (e) {
            logger.error(e);
            res.status(500).send('Internal server error');
        }
});
module.exports = router;

