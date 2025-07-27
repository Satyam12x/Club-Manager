const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "Uploads")));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, "Uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(UploadsDir, { recursive: true });
}

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "Uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error("Only JPEG and PNG images are allowed"));
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

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
  rollNo: { type: String, unique: true, sparse: true },
  semester: { type: Number, default: null },
  course: { type: String, default: null },
  specialization: { type: String, default: null },
  phone: { type: String, default: null },
  isClubMember: { type: Boolean, default: false },
  clubName: { type: [String], default: [] },
  pendingClubs: { type: [String], default: [] },
  isAdmin: { type: Boolean, default: false },
  isHeadCoordinator: { type: Boolean, default: false },
  headCoordinatorClubs: { type: [String], default: [] },
  createdAt: { type: Date, default: Date.now },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

// Club Schema
const clubSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  icon: { type: String, required: true },
  banner: { type: String },
  description: { type: String, required: true, maxlength: 500 },
  category: {
    type: String,
    enum: ["Technical", "Cultural", "Literary", "Entrepreneurial"],
    required: true,
  },
  contactEmail: { type: String },
  headCoordinators: { type: [String], default: [] },
  superAdmins: {
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    default: [],
    validate: {
      validator: function (v) {
        return v.length <= 2;
      },
      message: "A club can have at most 2 super admins",
    },
  },
  memberCount: { type: Number, default: 0 },
  eventsCount: { type: Number, default: 0 },
});

const Club = mongoose.model("Club", clubSchema);

// Event Schema
const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: String, required: true },
  time: { type: String, required: true },
  location: { type: String, required: true },
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club", required: true },
  banner: { type: String },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

const Event = mongoose.model("Event", eventSchema);

// Activity Schema
const activitySchema = new mongoose.Schema({
  title: { type: String, required: true },
  date: { type: String, required: true },
  description: { type: String, required: true },
  club: { type: String, required: true },
  images: [{ type: String }],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

const Activity = mongoose.model("Activity", activitySchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  message: { type: String, required: true },
  type: {
    type: String,
    enum: ["membership", "event", "activity", "general", "attendance"],
    default: "general",
  },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const Notification = mongoose.model("Notification", notificationSchema);

// Membership Request Schema
const membershipRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  clubName: { type: String, required: true },
  status: {
    type: String,
    enum: ["pending", "approved", "rejected"],
    default: "pending",
  },
  requestedAt: { type: Date, default: Date.now },
});

const MembershipRequest = mongoose.model(
  "MembershipRequest",
  membershipRequestSchema
);

// Attendance Schema (Aligned with frontend)
const attendanceSchema = new mongoose.Schema({
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club", required: true },
  date: { type: String, required: true },
  lectureNumber: { type: Number, required: true },
  attendance: { type: Map, of: String, required: true },
  stats: {
    presentCount: { type: Number, default: 0 },
    absentCount: { type: Number, default: 0 },
    totalMarked: { type: Number, default: 0 },
    attendanceRate: { type: Number, default: 0 },
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

const Attendance = mongoose.model("Attendance", attendanceSchema);

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

// Store OTPs temporarily
const otpStore = {};

// Middleware to verify JWT
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    console.log("authenticateToken: No token provided");
    return res
      .status(401)
      .json({ success: false, error: "Unauthorized: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      console.log("authenticateToken: User not found for token");
      return res
        .status(401)
        .json({ success: false, error: "Unauthorized: Invalid token" });
    }
    req.user = user;
    console.log("authenticateToken: User authenticated", {
      userId: user._id,
      email: user.email,
    });
    next();
  } catch (err) {
    console.error("authenticateToken: Error verifying token:", err.message);
    res
      .status(401)
      .json({ success: false, error: "Unauthorized: Invalid or expired token" });
  }
};

// Middleware to check global admin
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("isAdmin: User not found", { userId: req.user._id });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }
    if (!user.isAdmin) {
      console.log("isAdmin: User is not an admin", { userId: user._id });
      return res
        .status(403)
        .json({ success: false, error: "Admin access required" });
    }
    console.log("isAdmin: User is admin", { userId: user._id });
    next();
  } catch (err) {
    console.error("isAdmin: Error", err.message);
    res
      .status(500)
      .json({ success: false, error: "Server error during admin check" });
  }
};

// Middleware to check super admin or admin
const isSuperAdminOrAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("isSuperAdminOrAdmin: User not found", {
        userId: req.user._id,
      });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];

    // Check if user is a global admin or super admin
    if (user.isAdmin || superAdminEmails.includes(user.email)) {
      console.log("isSuperAdminOrAdmin: User is global admin or super admin", {
        userId: user._id,
        email: user.email,
      });
      return next();
    }

    // Check club-specific access
    const clubId = req.query.club || req.body.club;
    if (!clubId) {
      console.log("isSuperAdminOrAdmin: Club ID not provided");
      return res
        .status(400)
        .json({ success: false, error: "Club ID is required" });
    }

    if (!mongoose.Types.ObjectId.isValid(clubId)) {
      console.log("isSuperAdminOrAdmin: Invalid club ID", { clubId });
      return res
        .status(400)
        .json({ success: false, error: "Invalid club ID" });
    }

    const club = await Club.findById(clubId);
    if (!club) {
      console.log("isSuperAdminOrAdmin: Club not found", { clubId });
      return res
        .status(404)
        .json({ success: false, error: "Club not found" });
    }

    // Check if user is a super admin or head coordinator for the club
    if (
      club.superAdmins.some((id) => id.toString() === user._id.toString()) ||
      user.headCoordinatorClubs.includes(club.name)
    ) {
      console.log("isSuperAdminOrAdmin: User authorized for club", {
        clubId,
        clubName: club.name,
        role: club.superAdmins.some((id) => id.toString() === user._id.toString())
          ? "SuperAdmin"
          : "HeadCoordinator",
      });
      return next();
    }

    console.log("isSuperAdminOrAdmin: User not authorized for club", {
      userId: user._id,
      clubId,
      clubName: club.name,
    });
    res.status(403).json({
      success: false,
      error: "Super admin or head coordinator access required",
    });
  } catch (err) {
    console.error("isSuperAdminOrAdmin: Error", {
      message: err.message,
      stack: err.stack,
      userId: req.user?._id,
      clubId: req.query.club || req.body.club,
    });
    res
      .status(500)
      .json({ success: false, error: "Server error during authorization" });
  }
};

// Middleware to check super admin (global or club-specific)
const isSuperAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("isSuperAdmin: User not found", { userId: req.user._id });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];

    // Check if user is a global super admin
    if (superAdminEmails.includes(user.email)) {
      console.log("isSuperAdmin: User is global super admin", {
        userId: user._id,
        email: user.email,
      });
      return next();
    }

    // Check for club-specific super admin
    const clubId = req.params.id || req.body.club || req.query.club;
    if (!clubId) {
      console.log("isSuperAdmin: Club ID not provided");
      return res
        .status(400)
        .json({ success: false, error: "Club ID is required" });
    }

    if (!mongoose.Types.ObjectId.isValid(clubId)) {
      console.log("isSuperAdmin: Invalid club ID", { clubId });
      return res
        .status(400)
        .json({ success: false, error: "Invalid club ID" });
    }

    const club = await Club.findById(clubId);
    if (!club) {
      console.log("isSuperAdmin: Club not found", { clubId });
      return res
        .status(404)
        .json({ success: false, error: "Club not found" });
    }

    if (club.superAdmins.some((id) => id.toString() === user._id.toString())) {
      console.log("isSuperAdmin: User is super admin for club", {
        clubId,
        clubName: club.name,
      });
      return next();
    }

    console.log("isSuperAdmin: User not authorized for club", {
      userId: user._id,
      clubId,
      clubName: club.name,
    });
    res.status(403).json({
      success: false,
      error: "Super admin access required for this club",
    });
  } catch (err) {
    console.error("isSuperAdmin: Error", {
      message: err.message,
      stack: err.stack,
      userId: req.user?._id,
      clubId: req.params.id || req.body.club || req.query.club,
    });
    res
      .status(500)
      .json({ success: false, error: "Server error during super admin check" });
  }
};

// Middleware to check head coordinator or admin
const isHeadCoordinatorOrAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("isHeadCoordinatorOrAdmin: User not found", {
        userId: req.user._id,
      });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    if (user.isAdmin) {
      console.log("isHeadCoordinatorOrAdmin: User is global admin", {
        userId: user._id,
      });
      return next();
    }

    const clubId = req.params.id || req.body.club || req.query.club;
    if (!clubId) {
      console.log("isHeadCoordinatorOrAdmin: Club ID not provided");
      return res
        .status(400)
        .json({ success: false, error: "Club ID is required" });
    }

    if (!mongoose.Types.ObjectId.isValid(clubId)) {
      console.log("isHeadCoordinatorOrAdmin: Invalid club ID", { clubId });
      return res
        .status(400)
        .json({ success: false, error: "Invalid club ID" });
    }

    const club = await Club.findById(clubId);
    if (!club) {
      console.log("isHeadCoordinatorOrAdmin: Club not found", { clubId });
      return res
        .status(404)
        .json({ success: false, error: "Club not found" });
    }

    if (user.headCoordinatorClubs.includes(club.name)) {
      console.log("isHeadCoordinatorOrAdmin: User is head coordinator for club", {
        clubId,
        clubName: club.name,
      });
      return next();
    }

    console.log("isHeadCoordinatorOrAdmin: User not authorized for club", {
      userId: user._id,
      clubId,
      clubName: club.name,
    });
    res.status(403).json({
      success: false,
      error: "Head coordinator or admin access required",
    });
  } catch (err) {
    console.error("isHeadCoordinatorOrAdmin: Error", {
      message: err.message,
      stack: err.stack,
      userId: req.user?._id,
      clubId: req.params.id || req.body.club || req.query.club,
    });
    res
      .status(500)
      .json({ success: false, error: "Server error during authorization" });
  }
};

// Authentication Routes
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    console.log("send-otp: Invalid email address", { email });
    return res
      .status(400)
      .json({ success: false, error: "Invalid email address" });
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
    console.log("send-otp: OTP sent", { email, otp });
    res.json({ success: true, data: { message: "OTP sent successfully" } });
  } catch (err) {
    console.error("send-otp: Nodemailer error", {
      message: err.message,
      code: err.code,
    });
    res
      .status(500)
      .json({ success: false, error: `Failed to send OTP: ${err.message}` });
  }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || otpStore[email] !== otp) {
    console.log("verify-otp: Invalid OTP", { email, otp });
    return res
      .status(400)
      .json({ success: false, error: "Invalid OTP" });
  }

  delete otpStore[email];

  let user = await User.findOne({ email });
  if (!user) {
    console.log("verify-otp: User not found, proceed to signup", { email });
    return res.json({
      success: true,
      data: { message: "OTP verified, proceed to set password" },
    });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
  console.log("verify-otp: OTP verified, token generated", {
    userId: user._id,
    email,
  });
  res.json({ success: true, data: { token } });
});

app.post("/api/auth/login-password", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    console.log("login-password: Missing email or password", req.body);
    return res
      .status(400)
      .json({ success: false, error: "Email and password are required" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    console.log("login-password: User not found", { email });
    return res
      .status(400)
      .json({ success: false, error: "User not found" });
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    console.log("login-password: Invalid password", { email });
    return res
      .status(400)
      .json({ success: false, error: "Invalid password" });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
  console.log("login-password: Login successful", { userId: user._id, email });
  res.json({ success: true, data: { token, user } });
});

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, mobile, rollNo } = req.body;
  if (!name || !email || !password) {
    console.log("signup: Missing required fields", req.body);
    return res
      .status(400)
      .json({ success: false, error: "Name, email, and password are required" });
  }
  if (password.length < 6) {
    console.log("signup: Password too short", { email });
    return res
      .status(400)
      .json({ success: false, error: "Password must be at least 6 characters" });
  }

  try {
    let user = await User.findOne({ email });
    if (user) {
      console.log("signup: User already exists", { email });
      return res
        .status(400)
        .json({ success: false, error: "User already exists" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    const isAdmin = superAdminEmails.includes(email);
    const clubs = await Club.find({ headCoordinators: email });
    const headCoordinatorClubs = clubs.map((club) => club.name);
    const isHeadCoordinator = headCoordinatorClubs.length > 0;

    user = new User({
      name,
      email,
      password,
      mobile,
      rollNo,
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
    console.log("signup: User created", { userId: user._id, email });
    res.json({ success: true, data: { token } });
  } catch (err) {
    console.error("signup: Error", err);
    if (err.name === "ValidationError") {
      return res
        .status(400)
        .json({ success: false, error: `Validation error: ${err.message}` });
    }
    if (err.code === 11000) {
      return res.status(400).json({
        success: false,
        error:
          "Duplicate key error: email, mobile, or roll number already exists",
      });
    }
    res
      .status(500)
      .json({ success: false, error: "Signup failed: Internal server error" });
  }
});

app.post("/api/auth/verify-otp-login", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || otpStore[email] !== otp) {
    console.log("verify-otp-login: Invalid OTP", { email, otp });
    return res
      .status(400)
      .json({ success: false, error: "Invalid OTP" });
  }

  delete otpStore[email];

  const user = await User.findOne({ email });
  if (!user) {
    console.log("verify-otp-login: User not found", { email });
    return res
      .status(400)
      .json({ success: false, error: "User not found" });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );
  console.log("verify-otp-login: OTP verified, token generated", {
    userId: user._id,
    email,
  });
  res.json({ success: true, data: { token } });
});

// User Profile Update
app.put("/api/auth/user", authenticateToken, async (req, res) => {
  const { name, email, phone } = req.body;
  if (!name || !email) {
    console.log("update-user: Missing required fields", req.body);
    return res
      .status(400)
      .json({ success: false, error: "Name and email are required" });
  }

  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("update-user: User not found", { userId: req.user._id });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    if (email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        console.log("update-user: Email already in use", { email });
        return res
          .status(400)
          .json({ success: false, error: "Email already in use" });
      }
    }

    user.name = name;
    user.email = email;
    user.phone = phone || user.phone;
    await user.save();

    if (email !== req.user.email) {
      await Club.updateMany(
        { headCoordinators: req.user.email },
        { $set: { "headCoordinators.$": email } }
      );
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    console.log("update-user: Profile updated", { userId: user._id, email });
    res.json({
      success: true,
      data: { message: "Profile updated successfully", user, token },
    });
  } catch (err) {
    console.error("update-user: Error", err);
    if (err.code === 11000) {
      return res
        .status(400)
        .json({ success: false, error: "Email or phone already exists" });
    }
    res
      .status(500)
      .json({ success: false, error: "Server error during profile update" });
  }
});

// User Details Endpoint (POST)
app.post("/api/auth/user-details", authenticateToken, async (req, res) => {
  const { semester, course, specialization, isClubMember, clubName, rollNo } =
    req.body;
  if (!semester || !course || !specialization) {
    console.log("user-details: Missing required fields", req.body);
    return res
      .status(400)
      .json({
        success: false,
        error: "Semester, course, and specialization are required",
      });
  }
  if (isClubMember && (!clubName || clubName.length === 0)) {
    console.log("user-details: Missing club names for club member", req.body);
    return res
      .status(400)
      .json({ success: false, error: "Club names are required if you are a club member" });
  }

  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("user-details: User not found", { userId: req.user._id });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    user.semester = semester;
    user.course = course;
    user.specialization = specialization;
    user.rollNo = rollNo || user.rollNo;
    user.isClubMember = isClubMember;
    user.clubName = isClubMember ? clubName : [];
    await user.save();

    console.log("user-details: User details saved", { userId: user._id });
    res.json({
      success: true,
      data: { message: "User details saved successfully" },
    });
  } catch (err) {
    console.error("user-details: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error during user details update" });
  }
});

// User Details Endpoint (PATCH for joining clubs)
app.patch("/api/auth/user-details", authenticateToken, async (req, res) => {
  const { clubName, isClubMember } = req.body;
  if (!clubName || !Array.isArray(clubName)) {
    console.log("patch-user-details: Invalid clubName", req.body);
    return res
      .status(400)
      .json({ success: false, error: "clubName must be an array" });
  }

  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("patch-user-details: User not found", { userId: req.user._id });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    const validClubs = await Club.find({ name: { $in: clubName } }).distinct(
      "name"
    );
    if (clubName.some((name) => !validClubs.includes(name))) {
      console.log("patch-user-details: Invalid club names", { clubName });
      return res
        .status(400)
        .json({ success: false, error: "One or more club names are invalid" });
    }

    user.clubName = [...new Set([...user.clubName, ...clubName])];
    user.isClubMember =
      isClubMember !== undefined ? isClubMember : user.clubName.length > 0;
    await user.save();

    for (const name of clubName) {
      await Club.updateOne({ name }, { $inc: { memberCount: 1 } });
    }

    await Notification.create({
      userId: user._id,
      message: `You have successfully joined ${clubName.join(", ")}.`,
      type: "membership",
    });

    console.log("patch-user-details: Clubs joined", {
      userId: user._id,
      clubName,
    });
    res.json({ success: true, data: { message: "Club joined successfully" } });
  } catch (err) {
    console.error("patch-user-details: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error during club join" });
  }
});

// Get User Data
app.get("/api/auth/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select(
      "name email semester course specialization phone isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs rollNo"
    );
    if (!user) {
      console.log("get-user: User not found", { userId: req.user._id });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }
    console.log("get-user: User fetched", { userId: user._id });
    res.json({ success: true, data: user });
  } catch (err) {
    console.error("get-user: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching user data" });
  }
});

// Get All Users (Admin only)
app.get("/api/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select(
      "name email mobile semester course specialization phone isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs createdAt rollNo"
    );
    console.log("get-users: Fetched users", { count: users.length });
    res.json({ success: true, data: users });
  } catch (err) {
    console.error("get-users: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching users" });
  }
});

// Get Clubs
app.get("/api/clubs", authenticateToken, async (req, res) => {
  try {
    const { name, category } = req.query;
    const query = {};
    if (name) query.name = new RegExp(`^${name}$`, "i");
    if (category) query.category = category;
    const clubs = await Club.find(query).populate("superAdmins", "name email");
    const transformedClubs = await Promise.all(
      clubs.map(async (club) => {
        const members = await User.find({
          clubName: club.name,
        }).countDocuments();
        return {
          ...club._doc,
          icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
          banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
          memberCount: members,
        };
      })
    );
    console.log("get-clubs: Fetched clubs", { count: transformedClubs.length });
    res.json({ success: true, data: transformedClubs });
  } catch (err) {
    console.error("get-clubs: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching clubs" });
  }
});

// Create Club (Admin only)
app.post(
  "/api/clubs",
  authenticateToken,
  isAdmin,
  upload.fields([
    { name: "icon", maxCount: 1 },
    { name: "banner", maxCount: 1 },
  ]),
  async (req, res) => {
    const {
      name,
      description,
      category,
      contactEmail,
      headCoordinators,
      superAdmins,
    } = req.body;
    if (!name || !description || !category || !req.files.icon) {
      console.log("create-club: Missing required fields", req.body);
      return res
        .status(400)
        .json({
          success: false,
          error: "Name, description, category, and icon are required",
        });
    }
    if (
      !["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(category)
    ) {
      console.log("create-club: Invalid category", { category });
      return res
        .status(400)
        .json({ success: false, error: "Invalid category" });
    }
    if (description.length > 500) {
      console.log("create-club: Description too long", { description });
      return res
        .status(400)
        .json({
          success: false,
          error: "Description must be 500 characters or less",
        });
    }
    if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
      console.log("create-club: Invalid contact email", { contactEmail });
      return res
        .status(400)
        .json({ success: false, error: "Invalid contact email" });
    }

    try {
      let validHeadCoordinators = [];
      if (headCoordinators) {
        const emails = headCoordinators
          .split(",")
          .map((email) => email.trim())
          .filter((email) => email);
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        validHeadCoordinators = emails.filter((email) =>
          emailRegex.test(email)
        );
        await User.updateMany(
          { email: { $in: validHeadCoordinators } },
          {
            $set: { isHeadCoordinator: true },
            $addToSet: { headCoordinatorClubs: name },
          }
        );
      }

      let validSuperAdmins = [req.user._id];
      if (superAdmins) {
        const adminIds = superAdmins
          .split(",")
          .map((id) => id.trim())
          .filter((id) => id && id !== req.user._id.toString());
        if (adminIds.length + 1 > 2) {
          console.log("create-club: Too many super admins", { adminIds });
          return res
            .status(400)
            .json({
              success: false,
              error: "A club can have at most 2 super admins",
            });
        }
        const users = await User.find({ _id: { $in: adminIds } });
        validSuperAdmins = [
          ...validSuperAdmins,
          ...users.map((user) => user._id),
        ];
        if (validSuperAdmins.length !== adminIds.length + 1) {
          console.log("create-club: Invalid super admin IDs", { adminIds });
          return res
            .status(400)
            .json({ success: false, error: "One or more super admin IDs are invalid" });
        }
      }

      const club = new Club({
        name,
        icon: req.files.icon[0].path,
        banner: req.files.banner ? req.files.banner[0].path : null,
        description,
        category,
        contactEmail,
        headCoordinators: validHeadCoordinators,
        superAdmins: validSuperAdmins,
        memberCount: 0,
        eventsCount: 0,
      });
      await club.save();

      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      if (superAdminEmails.length > 0) {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: superAdminEmails,
          subject: `New Club Created: ${name}`,
          text: `A new club "${name}" has been created by ${req.user.email}.`,
        });
      }

      const populatedClub = await Club.findById(club._id).populate(
        "superAdmins",
        "name email"
      );
      const transformedClub = {
        ...populatedClub._doc,
        icon: populatedClub.icon
          ? `http://localhost:5000/${populatedClub.icon}`
          : null,
        banner: populatedClub.banner
          ? `http://localhost:5000/${populatedClub.banner}`
          : null,
      };
      console.log("create-club: Club created", { clubId: club._id, name });
      res.status(201).json({
        success: true,
        data: { message: "Club created successfully", club: transformedClub },
      });
    } catch (err) {
      console.error("create-club: Error", err);
      if (err.code === 11000) {
        return res
          .status(400)
          .json({ success: false, error: "Club name already exists" });
      }
      res
        .status(500)
        .json({ success: false, error: "Server error during club creation" });
    }
});

// Update Club (Super Admin only)
app.patch(
  "/api/clubs/:id",
  authenticateToken,
  isSuperAdmin,
  upload.fields([
    { name: "icon", maxCount: 1 },
    { name: "banner", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const {
      description,
      category,
      contactEmail,
      headCoordinators,
      superAdmins,
    } = req.body;

    if (req.body.name) {
      console.log("update-club: Attempt to update club name", { clubId: id });
      return res
        .status(400)
        .json({ success: false, error: "Club name cannot be updated" });
    }

    try {
      const club = await Club.findById(id);
      if (!club) {
        console.log("update-club: Club not found", { clubId: id });
        return res
          .status(404)
          .json({ success: false, error: "Club not found" });
      }

      if (description && description.length > 500) {
        console.log("update-club: Description too long", { description });
        return res
          .status(400)
          .json({
            success: false,
            error: "Description must be 500 characters or less",
          });
      }
      if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
        console.log("update-club: Invalid contact email", { contactEmail });
        return res
          .status(400)
          .json({ success: false, error: "Invalid contact email" });
      }

      let validHeadCoordinators = club.headCoordinators;
      if (headCoordinators !== undefined) {
        const emails = headCoordinators
          ? headCoordinators
              .split(",")
              .map((email) => email.trim())
              .filter((email) => email)
          : [];
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        validHeadCoordinators = emails.filter((email) =>
          emailRegex.test(email)
        );
        await User.updateMany(
          { email: { $in: validHeadCoordinators } },
          {
            $set: { isHeadCoordinator: true },
            $addToSet: { headCoordinatorClubs: club.name },
          }
        );
        await User.updateMany(
          {
            email: { $nin: validHeadCoordinators, $in: club.headCoordinators },
            headCoordinatorClubs: club.name,
          },
          {
            $pull: { headCoordinatorClubs: club.name },
            $set: {
              isHeadCoordinator: {
                $cond: [{ $eq: ["$headCoordinatorClubs", []] }, false, true],
              },
            },
          }
        );
      }

      let validSuperAdmins = club.superAdmins;
      if (superAdmins !== undefined) {
        const adminIds = superAdmins
          ? superAdmins
              .split(",")
              .map((id) => id.trim())
              .filter((id) => id)
          : [];
        if (adminIds.length > 2) {
          console.log("update-club: Too many super admins", { adminIds });
          return res
            .status(400)
            .json({
              success: false,
              error: "A club can have at most 2 super admins",
            });
        }
        const users = await User.find({ _id: { $in: adminIds } });
        validSuperAdmins = users.map((user) => user._id);
        if (validSuperAdmins.length !== adminIds.length) {
          console.log("update-club: Invalid super admin IDs", { adminIds });
          return res
            .status(400)
            .json({
              success: false,
              error: "One or more super admin IDs are invalid",
            });
        }
      }

      if (req.files.icon) {
        if (club.icon && fs.existsSync(club.icon)) fs.unlinkSync(club.icon);
        club.icon = req.files.icon[0].path;
      }
      if (req.files.banner) {
        if (club.banner && fs.existsSync(club.banner))
          fs.unlinkSync(club.banner);
        club.banner = req.files.banner[0].path;
      }
      if (description) club.description = description;
      if (category) {
        if (
          !["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(
            category
          )
        ) {
          console.log("update-club: Invalid category", { category });
          return res
            .status(400)
            .json({ success: false, error: "Invalid category" });
        }
        club.category = category;
      }
      if (contactEmail !== undefined) club.contactEmail = contactEmail;
      club.headCoordinators = validHeadCoordinators;
      club.superAdmins = validSuperAdmins;

      club.memberCount = await User.countDocuments({ clubName: club.name });
      club.eventsCount = await Event.countDocuments({ club: club._id });

      await club.save();

      const members = await User.find({ clubName: club.name });
      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      const recipients = [...members.map((m) => m.email), ...superAdminEmails];
      if (recipients.length > 0) {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: recipients,
          subject: `Club Updated: ${club.name}`,
          text: `The club "${club.name}" has been updated by ${req.user.email}.`,
        });
      }

      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `Club "${club.name}" has been updated.`,
          type: "general",
        });
      }

      const transformedClub = {
        ...club._doc,
        icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
        banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
      };
      console.log("update-club: Club updated", { clubId: club._id });
      res.json({
        success: true,
        data: { message: "Club updated successfully", club: transformedClub },
      });
    } catch (err) {
      console.error("update-club: Error", err);
      res
        .status(500)
        .json({ success: false, error: "Server error during club update" });
    }
});

// Delete Club (Admin only)
app.delete("/api/clubs/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      console.log("delete-club: Club not found", { clubId: req.params.id });
      return res
        .status(404)
        .json({ success: false, error: "Club not found" });
    }

    const members = await User.find({ clubName: club.name });
    await User.updateMany(
      { $or: [{ clubName: club.name }, { pendingClubs: club.name }] },
      {
        $pull: { clubName: club.name, pendingClubs: club.name },
        $set: {
          isClubMember: { $cond: [{ $eq: ["$clubName", []] }, false, true] },
        },
      }
    );

    await MembershipRequest.deleteMany({ clubName: club.name });
    await Event.deleteMany({ club: club._id });
    await Attendance.deleteMany({ club: club._id });

    if (club.icon && fs.existsSync(club.icon)) fs.unlinkSync(club.icon);
    if (club.banner && fs.existsSync(club.banner)) fs.unlinkSync(club.banner);

    await club.deleteOne();

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    const recipients = [...members.map((m) => m.email), ...superAdminEmails];
    if (recipients.length > 0) {
      await transporter.sendMail({
        from: `"ACEM" <${process.env.EMAIL_USER}>`,
        to: recipients,
        subject: `Club Deleted: ${club.name}`,
        text: `The club "${club.name}" has been deleted by ${req.user.email}.`,
      });
    }

    for (const member of members) {
      await Notification.create({
        userId: member._id,
        message: `Club "${club.name}" has been deleted.`,
        type: "general",
      });
    }

    console.log("delete-club: Club deleted", { clubId: club._id });
    res.json({ success: true, data: { message: "Club deleted successfully" } });
  } catch (err) {
    console.error("delete-club: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error during club deletion" });
  }
});

// Join Club
app.post("/api/clubs/:id/join", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const club = await Club.findById(id);
    if (!club) {
      console.log("join-club: Club not found", { clubId: id });
      return res
        .status(404)
        .json({ success: false, error: "Club not found" });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("join-club: User not found", { userId: req.user._id });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    if (user.clubName.includes(club.name)) {
      console.log("join-club: User already a member", {
        userId: user._id,
        clubName: club.name,
      });
      return res
        .status(400)
        .json({ success: false, error: "You are already a member of this club" });
    }

    if (user.pendingClubs.includes(club.name)) {
      console.log("join-club: Membership request already pending", {
        userId: user._id,
        clubName: club.name,
      });
      return res
        .status(400)
        .json({ success: false, error: "Membership request already pending" });
    }

    const membershipRequest = new MembershipRequest({
      userId: user._id,
      clubName: club.name,
    });
    await membershipRequest.save();

    user.pendingClubs.push(club.name);
    await user.save();

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    const recipients = [...club.headCoordinators, ...superAdminEmails];
    if (recipients.length > 0) {
      await transporter.sendMail({
        from: `"ACEM" <${process.env.EMAIL_USER}>`,
        to: recipients,
        subject: `New Membership Request for ${club.name}`,
        text: `User ${user.name} (${user.email}) has requested to join ${club.name}. Please review the request in the admin dashboard.`,
      });
    }

    await Notification.create({
      userId: user._id,
      message: `Your request to join ${club.name} has been submitted.`,
      type: "membership",
    });

    console.log("join-club: Membership request sent", {
      userId: user._id,
      clubName: club.name,
    });
    res.json({
      success: true,
      data: { message: "Membership request sent successfully" },
    });
  } catch (err) {
    console.error("join-club: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error during membership request" });
  }
});

// Get Membership Requests
app.get("/api/membership-requests", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("get-membership-requests: User not found", {
        userId: req.user._id,
      });
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    let query = {};
    if (!superAdminEmails.includes(user.email) && !user.isAdmin) {
      if (!user.isHeadCoordinator || !user.headCoordinatorClubs.length) {
        console.log("get-membership-requests: User not authorized", {
          userId: user._id,
        });
        return res
          .status(403)
          .json({ success: false, error: "Access denied" });
      }
      query.clubName = { $in: user.headCoordinatorClubs };
    }

    const requests = await MembershipRequest.find(query).populate(
      "userId",
      "name email mobile"
    );
    console.log("get-membership-requests: Fetched requests", {
      count: requests.length,
    });
    res.json({ success: true, data: requests });
  } catch (err) {
    console.error("get-membership-requests: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching membership requests" });
  }
});

// Approve/Reject Membership Request
app.patch(
  "/api/membership-requests/:id",
  authenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    if (!["approved", "rejected"].includes(status)) {
      console.log("update-membership-request: Invalid status", { status });
      return res
        .status(400)
        .json({ success: false, error: "Invalid status" });
    }

    try {
      const request = await MembershipRequest.findById(id);
      if (!request) {
        console.log("update-membership-request: Request not found", {
          requestId: id,
        });
        return res
          .status(404)
          .json({ success: false, error: "Membership request not found" });
      }

      const user = await User.findById(req.user._id);
      if (!user) {
        console.log("update-membership-request: User not found", {
          userId: req.user._id,
        });
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      if (
        !superAdminEmails.includes(user.email) &&
        !user.isAdmin &&
        !user.headCoordinatorClubs.includes(request.clubName)
      ) {
        console.log("update-membership-request: User not authorized", {
          userId: user._id,
          clubName: request.clubName,
        });
        return res
          .status(403)
          .json({ success: false, error: "Access denied" });
      }

      request.status = status;
      await request.save();

      const targetUser = await User.findById(request.userId);
      if (!targetUser) {
        console.log("update-membership-request: Target user not found", {
          userId: request.userId,
        });
        return res
          .status(404)
          .json({ success: false, error: "Target user not found" });
      }

      if (status === "approved") {
        targetUser.clubName.push(request.clubName);
        targetUser.isClubMember = true;
        targetUser.pendingClubs = targetUser.pendingClubs.filter(
          (club) => club !== request.clubName
        );
        await targetUser.save();

        const club = await Club.findOne({ name: request.clubName });
        if (club) {
          club.memberCount = await User.countDocuments({ clubName: club.name });
          await club.save();
        }

        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: targetUser.email,
          subject: `Membership Request Approved for ${request.clubName}`,
          text: `Congratulations! Your request to join ${request.clubName} has been approved.`,
        });

        await Notification.create({
          userId: targetUser._id,
          message: `Your request to join ${request.clubName} has been approved.`,
          type: "membership",
        });
      } else {
        targetUser.pendingClubs = targetUser.pendingClubs.filter(
          (club) => club !== request.clubName
        );
        await targetUser.save();

        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: targetUser.email,
          subject: `Membership Request Rejected for ${request.clubName}`,
          text: `We regret to inform you that your request to join ${request.clubName} has been rejected.`,
        });

        await Notification.create({
          userId: targetUser._id,
          message: `Your request to join ${request.clubName} has been rejected.`,
          type: "membership",
        });
      }

      console.log("update-membership-request: Request updated", {
        requestId: id,
        status,
      });
      res.json({
        success: true,
        data: { message: `Membership request ${status} successfully` },
      });
    } catch (err) {
      console.error("update-membership-request: Error", err);
      res
        .status(500)
        .json({
          success: false,
          error: "Server error during membership request update",
        });
    }
  }
);

// Get Single Club
app.get("/api/clubs/:id", authenticateToken, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id).populate(
      "superAdmins",
      "name email"
    );
    if (!club) {
      console.log("get-club: Club not found", { clubId: req.params.id });
      return res
        .status(404)
        .json({ success: false, error: "Club not found" });
    }
    const members = await User.countDocuments({ clubName: club.name });
    const transformedClub = {
      ...club._doc,
      icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
      banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
      memberCount: members,
    };
    console.log("get-club: Club fetched", { clubId: club._id });
    res.json({ success: true, data: transformedClub });
  } catch (err) {
    console.error("get-club: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching club" });
  }
});

// Get Club Members
app.get("/api/clubs/:clubId/members", authenticateToken, async (req, res) => {
  try {
    const club = await Club.findById(req.params.clubId);
    if (!club) {
      console.log("get-club-members: Club not found", {
        clubId: req.params.clubId,
      });
      return res
        .status(404)
        .json({ success: false, error: "Club not found" });
    }
    const members = await User.find(
      { clubName: club.name },
      "name email mobile phone rollNo"
    ).lean();
    console.log("get-club-members: Fetched members", {
      clubId: club._id,
      count: members.length,
    });
    res.json({ success: true, data: members });
  } catch (err) {
    console.error("get-club-members: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching club members" });
  }
});

// Remove Club Member
app.delete(
  "/api/clubs/:id/members",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { email } = req.body;
    if (!email) {
      console.log("remove-club-member: Missing email", req.body);
      return res
        .status(400)
        .json({ success: false, error: "Member email is required" });
    }

    try {
      const club = await Club.findById(req.params.id);
      if (!club) {
        console.log("remove-club-member: Club not found", {
          clubId: req.params.id,
        });
        return res
          .status(404)
          .json({ success: false, error: "Club not found" });
      }

      const user = await User.findOne({ email });
      if (!user) {
        console.log("remove-club-member: User not found", { email });
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      if (!user.clubName.includes(club.name)) {
        console.log("remove-club-member: User not a member", {
          userId: user._id,
          clubName: club.name,
        });
        return res
          .status(400)
          .json({ success: false, error: "User is not a member of this club" });
      }

      user.clubName = user.clubName.filter((name) => name !== club.name);
      user.isClubMember = user.clubName.length > 0;
      await user.save();

      club.memberCount = await User.countDocuments({ clubName: club.name });
      await club.save();

      await Notification.create({
        userId: user._id,
        message: `You have been removed from ${club.name}.`,
        type: "membership",
      });

      console.log("remove-club-member: Member removed", {
        userId: user._id,
        clubName: club.name,
      });
      res.json({
        success: true,
        data: { message: "Member removed successfully" },
      });
    } catch (err) {
      console.error("remove-club-member: Error", err);
      res
        .status(500)
        .json({ success: false, error: "Server error removing club member" });
    }
  }
);

// Create Event (Super Admin only)
app.post(
  "/api/events",
  authenticateToken,
  isSuperAdmin,
  upload.single("banner"),
  async (req, res) => {
    const { title, description, date, time, location, club } = req.body;
    if (!title || !description || !date || !time || !location || !club) {
      console.log("create-event: Missing required fields", req.body);
      return res
        .status(400)
        .json({
          success: false,
          error: "All fields are required except banner",
        });
    }

    try {
      if (!mongoose.Types.ObjectId.isValid(club)) {
        console.log("create-event: Invalid club ID", { club });
        return res
          .status(400)
          .json({ success: false, error: "Invalid club ID" });
      }

      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        console.log("create-event: Club not found", { club });
        return res
          .status(404)
          .json({ success: false, error: "Club not found" });
      }

      const event = new Event({
        title,
        description,
        date,
        time,
        location,
        club,
        banner: req.file ? req.file.path : null,
        createdBy: req.user._id,
      });
      await event.save();

      clubDoc.eventsCount = await Event.countDocuments({ club: clubDoc._id });
      await clubDoc.save();

      const members = await User.find({ clubName: clubDoc.name });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `New event "${title}" created for ${clubDoc.name} on ${date}.`,
          type: "event",
        });
      }

      const transformedEvent = {
        ...event._doc,
        banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
      };
      console.log("create-event: Event created", { eventId: event._id });
      res.status(201).json({ success: true, data: transformedEvent });
    } catch (err) {
      console.error("create-event: Error", err);
      res
        .status(500)
        .json({ success: false, error: "Server error during event creation" });
    }
  }
);

// Get Events
app.get("/api/events", authenticateToken, async (req, res) => {
  try {
    const { club } = req.query;
    const query = club ? { club } : {};
    if (club && !mongoose.Types.ObjectId.isValid(club)) {
      console.log("get-events: Invalid club ID", { club });
      return res
        .status(400)
        .json({ success: false, error: "Invalid club ID" });
    }
    const events = await Event.find(query)
      .populate("club", "name")
      .populate("createdBy", "name email");
    const transformedEvents = events.map((event) => ({
      ...event._doc,
      banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
    }));
    console.log("get-events: Fetched events", { count: events.length });
    res.json({ success: true, data: transformedEvents });
  } catch (err) {
    console.error("get-events: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching events" });
  }
});

// Get Single Event
app.get("/api/events/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      console.log("get-event: Invalid event ID", { eventId: req.params.id });
      return res
        .status(400)
        .json({ success: false, error: "Invalid event ID" });
    }
    const event = await Event.findById(req.params.id)
      .populate("club", "name")
      .populate("createdBy", "name email");
    if (!event) {
      console.log("get-event: Event not found", { eventId: req.params.id });
      return res
        .status(404)
        .json({ success: false, error: "Event not found" });
    }
    const transformedEvent = {
      ...event._doc,
      banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
    };
    console.log("get-event: Event fetched", { eventId: event._id });
    res.json({ success: true, data: transformedEvent });
  } catch (err) {
    console.error("get-event: Error", err);
    res
      .status(500)
      .json({ success: false, error: "Server error fetching event" });
  }
});

// Update Event (Super Admin only)
app.put(
  "/api/events/:id",
  authenticateToken,
  isSuperAdmin,
  upload.single("banner"),
  async (req, res) => {
    const { id } = req.params;
    const { title, description, date, time, location, club } = req.body;

    if (!title || !description || !date || !time || !location || !club) {
      console.log("update-event: Missing required fields", req.body);
      return res
        .status(400)
        .json({
          success: false,
          error: "All fields are required except banner",
        });
    }

    try {
      if (!mongoose.Types.ObjectId.isValid(id)) {
        console.log("update-event: Invalid event ID", { eventId: id });
        return res
          .status(400)
          .json({ success: false, error: "Invalid event ID" });
      }
      if (!mongoose.Types.ObjectId.isValid(club)) {
        console.log("update-event: Invalid club ID", { club });
        return res
          .status(400)
          .json({ success: false, error: "Invalid club ID" });
      }

      const event = await Event.findById(id);
      if (!event) {
        console.log("update-event: Event not found", { eventId: id });
        return res
          .status(404)
          .json({ success: false, error: "Event not found" });
      }

      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        console.log("update-event: Club not found", { club });
        return res
          .status(404)
          .json({ success: false, error: "Club not found" });
      }

      if (req.file && event.banner && fs.existsSync(event.banner)) {
        fs.unlinkSync(event.banner);
      }

      event.title = title;
      event.description = description;
      event.date = date;
      event.time = time;
      event.location = location;
      event.club = club;
      event.banner = req.file ? req.file.path : event.banner;
      await event.save();

      const members = await User.find({ clubName: clubDoc.name });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `Event "${title}" for ${clubDoc.name} has been updated.`,
          type: "event",
        });
      }

      const transformedEvent = {
        ...event._doc,
        banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
      };
      console.log("update-event: Event updated", { eventId: event._id });
      res.json({
        success: true,
        data: { message: "Event updated successfully", event: transformedEvent },
      });
    } catch (err) {
      console.error("update-event: Error", err);
      res
        .status(500)
        .json({ success: false, error: "Server error during event update" });
    }
  }
);


// Delete Event (Super Admin only)
app.delete(
  "/api/events/:id",
  authenticateToken,
  isSuperAdmin,
  async (req, res) => {
    try {
      const event = await Event.findById(req.params.id);
      if (!event) {
        return res.status(404).json({ error: "Event not found" });
      }

      const club = await Club.findById(event.club);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      if (event.banner && fs.existsSync(event.banner)) {
        fs.unlinkSync(event.banner);
      }

      await event.deleteOne();

      club.eventsCount = await Event.countDocuments({ club: club._id });
      await club.save();

      const members = await User.find({ clubName: club.name });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `Event "${event.title}" for ${club.name} has been deleted.`,
          type: "event",
        });
      }

      res.json({ message: "Event deleted successfully" });
    } catch (err) {
      console.error("Event deletion error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Create Activity
app.post(
  "/api/activities",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  upload.array("images", 5),
  async (req, res) => {
    const { title, date, description, club } = req.body;
    if (!title || !date || !description || !club) {
      return res.status(400).json({ error: "All fields are required" });
    }

    try {
      const clubDoc = await Club.findOne({ name: club });
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user.isAdmin && !user.headCoordinatorClubs.includes(club)) {
        return res.status(403).json({
          error: "You are not authorized to create activities for this club",
        });
      }

      const activity = new Activity({
        title,
        date,
        description,
        club,
        images: req.files ? req.files.map((file) => file.path) : [],
        createdBy: req.user.id,
      });
      await activity.save();

      const members = await User.find({ clubName: club });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `New activity "${title}" created for ${club} on ${date}.`,
          type: "activity",
        });
      }

      const transformedActivity = {
        ...activity._doc,
        images: activity.images.map((img) => `http://localhost:5000/${img}`),
      };
      res.status(201).json(transformedActivity);
    } catch (err) {
      console.error("Activity creation error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get Activities
app.get("/api/activities", authenticateToken, async (req, res) => {
  try {
    const { club } = req.query;
    const query = club ? { club } : {};
    const activities = await Activity.find(query).populate(
      "createdBy",
      "name email"
    );
    const transformedActivities = activities.map((activity) => ({
      ...activity._doc,
      images: activity.images.map((img) => `http://localhost:5000/${img}`),
    }));
    res.json(transformedActivities);
  } catch (err) {
    console.error("Error fetching activities:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Single Activity
app.get("/api/activities/:id", authenticateToken, async (req, res) => {
  try {
    const activity = await Activity.findById(req.params.id).populate(
      "createdBy",
      "name email"
    );
    if (!activity) {
      return res.status(404).json({ error: "Activity not found" });
    }
    const transformedActivity = {
      ...activity._doc,
      images: activity.images.map((img) => `http://localhost:5000/${img}`),
    };
    res.json(transformedActivity);
  } catch (err) {
    console.error("Error fetching activity:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update Activity
app.put(
  "/api/activities/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  upload.array("images", 5),
  async (req, res) => {
    const { id } = req.params;
    const { title, date, description, club } = req.body;

    if (!title || !date || !description || !club) {
      return res.status(400).json({ error: "All fields are required" });
    }

    try {
      const activity = await Activity.findById(id);
      if (!activity) {
        return res.status(404).json({ error: "Activity not found" });
      }

      const clubDoc = await Club.findOne({ name: club });
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user.isAdmin && !user.headCoordinatorClubs.includes(club)) {
        return res.status(403).json({
          error: "You are not authorized to update activities for this club",
        });
      }

      if (req.files && req.files.length > 0) {
        for (const img of activity.images) {
          if (fs.existsSync(img)) fs.unlinkSync(img);
        }
        activity.images = req.files.map((file) => file.path);
      }

      activity.title = title;
      activity.date = date;
      activity.description = description;
      activity.club = club;
      await activity.save();

      const members = await User.find({ clubName: club });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `Activity "${title}" for ${club} has been updated.`,
          type: "activity",
        });
      }

      const transformedActivity = {
        ...activity._doc,
        images: activity.images.map((img) => `http://localhost:5000/${img}`),
      };
      res.json({
        message: "Activity updated successfully",
        activity: transformedActivity,
      });
    } catch (err) {
      console.error("Activity update error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Delete Activity
app.delete(
  "/api/activities/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    try {
      const activity = await Activity.findById(req.params.id);
      if (!activity) {
        return res.status(404).json({ error: "Activity not found" });
      }

      const club = await Club.findOne({ name: activity.club });
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user.isAdmin && !user.headCoordinatorClubs.includes(club.name)) {
        return res.status(403).json({
          error: "You are not authorized to delete activities for this club",
        });
      }

      for (const img of activity.images) {
        if (fs.existsSync(img)) fs.unlinkSync(img);
      }

      await activity.deleteOne();

      const members = await User.find({ clubName: club.name });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `Activity "${activity.title}" for ${club.name} has been deleted.`,
          type: "activity",
        });
      }

      res.json({ message: "Activity deleted successfully" });
    } catch (err) {
      console.error("Activity deletion error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get Notifications
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(notifications);
  } catch (err) {
    console.error("Error fetching notifications:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Mark Notification as Read
app.patch(
  "/api/notifications/:id/read",
  authenticateToken,
  async (req, res) => {
    try {
      const notification = await Notification.findOne({
        _id: req.params.id,
        userId: req.user.id,
      });
      if (!notification) {
        return res.status(404).json({ error: "Notification not found" });
      }
      notification.read = true;
      await notification.save();
      res.json({ message: "Notification marked as read" });
    } catch (err) {
      console.error("Error updating notification:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Club Contact Form
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

    await Notification.create({
      userId: req.user.id,
      message: `Your contact message for ${club.name} has been sent.`,
      type: "general",
    });

    res.json({ message: "Message sent successfully" });
  } catch (err) {
    console.error("Error sending contact email:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Global Contact Form
app.post("/api/contact", authenticateToken, async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res
      .status(400)
      .json({ error: "Name, email, and message are required" });
  }

  try {
    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : ["satyam.pandey@acem.edu.in"];
    if (superAdminEmails.length === 0) {
      return res
        .status(500)
        .json({ error: "No super admin emails configured" });
    }

    await transporter.sendMail({
      from: `"ACEM" <${process.env.EMAIL_USER}>`,
      to: superAdminEmails,
      subject: `Contact Form Submission from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\nMessage:\n${message}`,
    });

    await Notification.create({
      userId: req.user.id,
      message: "Your contact message has been sent to the administrators.",
      type: "general",
    });

    res.json({ message: "Message sent successfully" });
  } catch (err) {
    console.error("Error sending contact email:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Get Club Contact Details
app.get("/api/clubs/:clubId/contacts", authenticateToken, async (req, res) => {
  try {
    const club = await Club.findById(req.params.clubId);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }

    const defaultContact = {
      email: "satyam.pandey@acem.edu.in",
      number: "8851020767",
      room: "CSE Dept.",
      timing: "9 to 4",
    };

    const contactDetails = {
      email: club.contactEmail || defaultContact.email,
      number: defaultContact.number,
      room: defaultContact.room,
      timing: defaultContact.timing,
    };

    res.json(contactDetails);
  } catch (err) {
    console.error("Error fetching club contact details:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Create Attendance Record
app.post(
  "/api/attendance",
  authenticateToken,
  isSuperAdminOrAdmin,
  async (req, res) => {
    const { club, date, lectureNumber, attendance, stats } = req.body;
    if (!club || !date || !lectureNumber || !attendance || !stats) {
      return res.status(400).json({ error: "All fields are required" });
    }

    try {
      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      const attendanceRecord = new Attendance({
        club,
        date,
        lectureNumber,
        attendance: Object.entries(attendance).map(([userId, status]) => ({
          userId,
          status,
        })),
        stats,
        createdBy: req.user.id,
      });
      await attendanceRecord.save();

      const members = await User.find({ clubName: clubDoc.name });
      for (const member of members) {
        const status = attendanceRecord.attendance.find(
          (entry) => entry.userId.toString() === member._id.toString()
        )?.status;
        if (status) {
          await Notification.create({
            userId: member._id,
            message: `Your attendance for ${clubDoc.name} (Lecture ${lectureNumber}, ${date}) was marked as ${status}.`,
            type: "attendance",
          });
        }
      }

      res.status(201).json({
        message: "Attendance recorded successfully",
        attendance: attendanceRecord,
      });
    } catch (err) {
      console.error("Attendance creation error:", {
        message: err.message,
        stack: err.stack,
        clubId: club,
        userId: req.user.id,
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get Attendance Records
app.get(
  "/api/attendance",
  authenticateToken,
  isSuperAdminOrAdmin,
  async (req, res) => {
    try {
      const { club, date, lectureNumber } = req.query;
      const query = {};
      if (club) query.club = club;
      if (date) query.date = date;
      if (lectureNumber) query.lectureNumber = Number(lectureNumber);

      const user = await User.findById(req.user.id);
      if (!user) {
        console.error("Get attendance: User not found for ID:", req.user.id);
        return res.status(404).json({ error: "User not found" });
      }

      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];

      // Restrict to authorized clubs for non-global admins
      if (!user.isAdmin && !superAdminEmails.includes(user.email)) {
        const authorizedClubs = await Club.find({
          $or: [
            { superAdmins: user._id },
            { name: { $in: user.headCoordinatorClubs } },
          ],
        }).distinct("_id");
        if (!authorizedClubs.length) {
          console.error(
            "Get attendance: User not authorized for any clubs",
            "User ID:",
            user._id,
            "HeadCoordinatorClubs:",
            user.headCoordinatorClubs
          );
          return res
            .status(403)
            .json({ error: "Not authorized to view attendance" });
        }
        if (
          club &&
          !authorizedClubs.map((id) => id.toString()).includes(club)
        ) {
          console.error(
            "Get attendance: User not authorized for club ID:",
            club,
            "User ID:",
            user._id
          );
          return res
            .status(403)
            .json({ error: "Not authorized for this club" });
        }
        query.club = { $in: authorizedClubs };
      }

      console.log(
        "Get attendance: Querying with",
        query,
        "for user",
        user.email
      );

      const attendanceRecords = await Attendance.find(query)
        .populate("club", "name")
        .populate("createdBy", "name email")
        .populate("attendance.userId", "name email rollNo");

      res.json(attendanceRecords);
    } catch (err) {
      console.error("Error fetching attendance records:", {
        message: err.message,
        stack: err.stack,
        userId: req.user?.id,
        query: req.query,
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
