const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: { type: String, unique: true, sparse: true },
  semester: { type: Number, default: null },
  course: { type: String, default: null },
  specialization: { type: String, default: null },
  isClubMember: { type: Boolean, default: false },
  clubName: { type: [String], default: [] },
  isAdmin: { type: Boolean, default: false },
  isHeadCoordinator: { type: Boolean, default: false },
  headCoordinatorClubs: { type: [String], default: [] },
  createdAt: { type: Date, default: Date.now },
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

// Club Schema
const clubSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  icon: { type: String, required: true },
  description: { type: String, required: true },
  category: {
    type: String,
    enum: ["Technical", "Cultural", "Literary", "Entrepreneurial"],
    required: true,
  },
  contactEmail: { type: String },
  headCoordinators: { type: [String], default: [] }, // Emails of head coordinators
});

const Club = mongoose.model("Club", clubSchema);

// Activity Schema
const activitySchema = new mongoose.Schema({
  title: { type: String, required: true },
  date: { type: String, required: true },
  description: { type: String, required: true },
  club: { type: String, required: true },
  images: [{ type: String }],
});

const Activity = mongoose.model("Activity", activitySchema);

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT, 10),
  secure: process.env.EMAIL_PORT == 465,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Verify transporter configuration
transporter.verify((error, success) => {
  if (error) {
    console.error("Nodemailer configuration error:", {
      message: error.message,
      code: error.code,
      response: error.response,
    });
  } else {
    console.log("Nodemailer transporter is ready to send emails");
  }
});

// Generate OTP
const generateOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

// Store OTPs temporarily (in-memory, replace with Redis in production)
const otpStore = {};

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = user;
    next();
  });
};

// Middleware to check admin
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: "Admin access required" });
    }
    next();
  } catch (err) {
    console.error("Admin check error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

// Middleware to check head coordinator or admin for a specific club
const isHeadCoordinatorOrAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    const club = await Club.findById(req.params.id);
    if (!user || !club) {
      return res.status(404).json({ error: "User or club not found" });
    }
    if (
      !user.isAdmin &&
      (!user.isHeadCoordinator || !club.headCoordinators.includes(user.email))
    ) {
      return res
        .status(403)
        .json({ error: "Head coordinator or admin access required" });
    }
    next();
  } catch (err) {
    console.error("Head coordinator check error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

// Authentication Routes
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email address" });
  }

  const otp = generateOtp();
  otpStore[email] = otp;

  try {
    await transporter.sendMail({
      from: `"ACEM" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your ACEM OTP",
      text: `Your OTP for ACEM is ${otp}. It is valid for 10 minutes.`,
    });
    console.log(`OTP ${otp} sent to ${email}`);
    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Nodemailer sendMail error:", {
      message: err.message,
      code: err.code,
      response: err.response,
      responseCode: err.responseCode,
    });
    res.status(500).json({ error: `Failed to send OTP: ${err.message}` });
  }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || otpStore[email] !== otp) {
    return res.status(400).json({ error: "Invalid OTP" });
  }

  delete otpStore[email];

  let user = await User.findOne({ email });
  if (!user) {
    return res.json({ message: "OTP verified, proceed to set password" });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
  res.json({ token });
});

app.post("/api/auth/login-password", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    return res.status(400).json({ error: "Invalid password" });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
  res.json({ token });
});

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, mobile } = req.body;
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email, and password are required" });
  }
  if (password.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters" });
  }

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: "User already exists" });
    }

    const adminIds = process.env.ADMIN_IDS
      ? process.env.ADMIN_IDS.split(",").map((id) => id.trim())
      : [];
    const isAdmin = adminIds.includes(email);

    // Check if email is a head coordinator for any club
    const clubs = await Club.find({ headCoordinators: email });
    const headCoordinatorClubs = clubs.map((club) => club.name);
    const isHeadCoordinator = headCoordinatorClubs.length > 0;

    user = new User({
      name,
      email,
      password,
      mobile,
      isAdmin,
      isHeadCoordinator,
      headCoordinatorClubs,
    });
    await user.save();

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.json({ token });
  } catch (err) {
    console.error("Signup error:", err);
    if (err.name === "ValidationError") {
      return res
        .status(400)
        .json({ error: `Validation failed: ${err.message}` });
    }
    if (err.code === 11000) {
      return res
        .status(400)
        .json({ error: "Duplicate key error: email or mobile already exists" });
    }
    res.status(500).json({ error: "Signup failed: Internal server error" });
  }
});

app.post("/api/auth/verify-otp-login", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || otpStore[email] !== otp) {
    return res.status(400).json({ error: "Invalid OTP" });
  }

  delete otpStore[email];

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
  res.json({ token });
});

// User Details Endpoint (POST)
app.post("/api/auth/user-details", authenticateToken, async (req, res) => {
  const { semester, course, specialization, isClubMember, clubName } = req.body;
  if (!semester || !course || !specialization) {
    return res
      .status(400)
      .json({ error: "Semester, course, and specialization are required" });
  }
  if (isClubMember && (!clubName || clubName.length === 0)) {
    return res
      .status(400)
      .json({ error: "Club names are required if you are a club member" });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.semester = semester;
    user.course = course;
    user.specialization = specialization;
    user.isClubMember = isClubMember;
    user.clubName = isClubMember ? clubName : [];
    await user.save();

    res.status(200).json({ message: "User details saved successfully" });
  } catch (err) {
    console.error("User details error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// User Details Endpoint (PATCH for joining clubs)
app.patch("/api/auth/user-details", authenticateToken, async (req, res) => {
  const { clubName, isClubMember } = req.body;
  if (!clubName || !Array.isArray(clubName)) {
    return res.status(400).json({ error: "clubName must be an array" });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Validate club names
    const validClubs = await Club.find({ name: { $in: clubName } }).distinct(
      "name"
    );
    if (clubName.some((name) => !validClubs.includes(name))) {
      return res.status(400).json({ error: "One or more club names are invalid" });
    }

    // Add new clubs to user's clubName array, avoiding duplicates
    user.clubName = [...new Set([...user.clubName, ...clubName])];
    user.isClubMember =
      isClubMember !== undefined ? isClubMember : user.clubName.length > 0;
    await user.save();

    res.status(200).json({ message: "Club joined successfully" });
  } catch (err) {
    console.error("Error updating user details:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get User Data
app.get("/api/auth/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "name email semester course specialization isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs"
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Clubs
app.get("/api/clubs", authenticateToken, async (req, res) => {
  try {
    const { name, category } = req.query;
    const query = {};
    if (name) query.name = new RegExp(`^${name}$`, "i");
    if (category) query.category = category;
    const clubs = await Club.find(query);
    res.json(clubs);
  } catch (err) {
    console.error("Error fetching clubs:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Create Club (Admin only)
app.post("/api/clubs", authenticateToken, isAdmin, async (req, res) => {
  const { name, icon, description, category, contactEmail, headCoordinators } =
    req.body;
  if (!name || !icon || !description || !category) {
    return res
      .status(400)
      .json({ error: "Name, icon, description, and category are required" });
  }
  if (
    category &&
    !["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(category)
  ) {
    return res.status(400).json({ error: "Invalid category" });
  }

  try {
    // Validate head coordinator emails
    let validHeadCoordinators = [];
    if (headCoordinators) {
      const emails = headCoordinators
        .split(",")
        .map((email) => email.trim())
        .filter((email) => email);
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      validHeadCoordinators = emails.filter((email) => emailRegex.test(email));
      // Update existing users who are head coordinators
      await User.updateMany(
        { email: { $in: validHeadCoordinators } },
        {
          $set: { isHeadCoordinator: true },
          $addToSet: { headCoordinatorClubs: name },
        }
      );
    }

    const club = new Club({
      name,
      icon,
      description,
      category,
      contactEmail,
      headCoordinators: validHeadCoordinators,
    });
    await club.save();
    res.status(201).json({ message: "Club created successfully", club });
  } catch (err) {
    console.error("Club creation error:", err);
    if (err.code === 11000) {
      return res.status(400).json({ error: "Club name already exists" });
    }
    res.status(500).json({ error: "Server error" });
  }
});

// Update Club (Admin or Head Coordinator)
app.patch(
  "/api/clubs/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { id } = req.params;
    const { icon, description, category, contactEmail, headCoordinators } =
      req.body;

    // Prevent updating club name
    if (req.body.name) {
      return res.status(400).json({ error: "Club name cannot be updated" });
    }

    try {
      const club = await Club.findById(id);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      // Validate and update head coordinator emails
      let validHeadCoordinators = club.headCoordinators;
      if (headCoordinators !== undefined) {
        const emails = headCoordinators
          ? headCoordinators
              .split(",")
              .map((email) => email.trim())
              .filter((email) => email)
          : [];
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        validHeadCoordinators = emails.filter((email) => emailRegex.test(email));
        // Update users who are new head coordinators
        await User.updateMany(
          { email: { $in: validHeadCoordinators } },
          {
            $set: { isHeadCoordinator: true },
            $addToSet: { headCoordinatorClubs: club.name },
          }
        );
        // Remove head coordinator status from users no longer in the list
        await User.updateMany(
          {
            email: { $nin: validHeadCoordinators, $in: club.headCoordinators },
            headCoordinatorClubs: club.name,
          },
          {
            $pull: { headCoordinatorClubs: club.name },
            $set: {
              isHeadCoordinator: { $cond: [{ $eq: ["$headCoordinatorClubs", []] }, false, true] },
            },
          }
        );
      }

      // Update club fields
      if (icon) club.icon = icon;
      if (description) club.description = description;
      if (category) {
        if (!["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(category)) {
          return res.status(400).json({ error: "Invalid category" });
        }
        club.category = category;
      }
      if (contactEmail !== undefined) club.contactEmail = contactEmail;
      club.headCoordinators = validHeadCoordinators;

      await club.save();
      res.status(200).json({ message: "Club updated successfully", club });
    } catch (err) {
      console.error("Club update error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get Activities
app.get("/api/activities", authenticateToken, async (req, res) => {
  try {
    const { club } = req.query;
    const query = club ? { club } : {};
    const activities = await Activity.find(query);
    res.json(activities);
  } catch (err) {
    console.error("Error fetching activities:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Club Contact Form Endpoint
app.post("/api/clubs/:id/contact", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ error: "Message is required" });
  }

  try {
    const club = await Club.findById(id);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }

    await transporter.sendMail({
      from: `"ACEM" <${process.env.EMAIL_USER}>`,
      to: club.contactEmail || process.env.EMAIL_USER,
      subject: `Contact Request for ${club.name}`,
      text: `Message from ${req.user.email}:\n\n${message}`,
    });
    res.json({ message: "Message sent successfully" });
  } catch (err) {
    console.error("Error sending contact email:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
