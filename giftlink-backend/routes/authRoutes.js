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
            const email=req.body.email;

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


router.post('/login', async (req, res) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection("users");
    const theUser = await collection.findOne({ email: req.body.email });

    if (!theUser) {
      logger.error('User not found');
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordCorrect = await bcryptjs.compare(req.body.password, theUser.password);
    if (!isPasswordCorrect) {
      logger.error('Passwords do not match');
      return res.status(404).json({ error: 'Wrong password' });
    }

    const payload = {
      user: {
        id: theUser._id.toString(),
      },
    };

    const authtoken = jwt.sign(payload, JWT_SECRET);
    const userName = theUser.firstName;
    const userEmail = theUser.email;

    logger.info('User logged in successfully');
    return res.status(200).json({ authtoken, userName, userEmail });

  } catch (e) {
    logger.error(e);
    return res.status(500).json({ error: 'Internal server error', details: e.message });
  }
});
const { body, validationResult } = require('express-validator');

router.put('/update', 
  // Example validation rules (adjust fields as needed)
  body('name').isLength({ min: 2 }).withMessage('Name must be at least 2 characters long'),
  async (req, res) => {
    // Task 2: Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors in update request', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      // Task 3: Check email in headers
      const email = req.headers.email;
      if (!email) {
        logger.error('Email not found in the request headers');
        return res.status(400).json({ error: "Email not found in the request headers" });
      }

      // Task 4: Connect to MongoDB and access collection
      const db = await connectToDatabase();
      const collection = db.collection("users");

      // Task 5: Find user
      const existingUser = await collection.findOne({ email });
      if (!existingUser) {
        logger.error('User not found');
        return res.status(404).json({ error: "User not found" });
      }

      // Task 6: Update user details and timestamp
      existingUser.firstName = req.body.name;
      existingUser.updatedAt = new Date();

      const updatedUser = await collection.findOneAndUpdate(
        { email },
        { $set: existingUser },
        { returnDocument: 'after' }
      );

      // Task 7: Create JWT token with updated user ID
      const payload = { user: { id: updatedUser._id.toString() } };
      const authtoken = jwt.sign(payload, JWT_SECRET);

      logger.info('User updated successfully');
      return res.json({ authtoken });

    } catch (error) {
      logger.error(error);
      return res.status(500).send("Internal Server Error");
    }
});


module.exports = router;