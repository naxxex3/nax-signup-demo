const express = require("express");
const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();
const cors = require("cors");
const app = express();
app.use(express.json()); // for parsing JSON in requests
const bcrypt = require("bcrypt");

const uri = process.env.MONGO_URI;
app.use(cors());
// Create a MongoDB client
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
let usersCollection;

// Async function to connect to MongoDB
async function connectDB() {
  try {
    await client.connect();
    const db = client.db("login_signup");
    usersCollection = db.collection("login_signup");
    console.log("✅ MongoDB connected successfully");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1); 
  }
}


connectDB();

// ----------------- SIGNUP ROUTE -----------------
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required",success: false });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({
        message: "Password must be at least 6 characters",
        success: false,
      });
  }

  try {
    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "Email already registered", success: false });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = await usersCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      createdAt: new Date(),
    });

    res
      .status(201)
      .json({ message: "Account created successfully", success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// ----------------- LOGIN ROUTE -----------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "All fields are required", success: false });
  }

  try {
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid credentials", success: false });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res
        .status(400)
        .json({ message: "Invalid credentials", success: false });
    }

    res
      .status(200)
      .json({ message: `Welcome back, ${user.name}`, success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", success: false });
  }
});


// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

