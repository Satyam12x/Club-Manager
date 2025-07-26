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
  fs.mkdirSync(UploadsDir);
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
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
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
  semester: { type: Number, default: null },
  course: { type: String, default: null },
  specialization: { type: String, default: null },
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
        return v.length <= 2; // Max 2 super admins
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
  date: { type: String, required: true }, // ISO format: YYYY-MM-DD
  time: { type: String, required: true }, // HH:MM
  location: { type: String, required: true },
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club", required: true },
  banner: { type: String },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
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
});

const Activity = mongoose.model("Activity", activitySchema);

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

const MembershipRequest = mongoose.model("MembershipRequest", membershipRequestSchema);

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
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// Store OTPs temporarily
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

// Middleware to check super admin (global or club-specific)
const isSuperAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    if (superAdminEmails.includes(user.email)) {
      return next();
    }
    // Check club-specific super admin
    if (req.params.id || req.body.club) {
      const clubId = req.params.id || req.body.club;
      const club = await Club.findById(clubId);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }
      if (club.superAdmins.map((id) => id.toString()).includes(user._id.toString())) {
        return next();
      }
    }
    res.status(403).json({ error: "Super admin access required" });
  } catch (err) {
    console.error("Super admin check error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

// Middleware to check head coordinator or admin
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
      return res.status(403).json({ error: "Head coordinator or admin access required" });
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

  const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
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

  const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
  res.json({ token });
});

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, mobile } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Name, email, and password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: "User already exists" });
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
      isAdmin,
      isHeadCoordinator,
      headCoordinatorClubs,
    });
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });
    res.json({ token });
  } catch (err) {
    console.error("Signup error:", err);
    if (err.name === "ValidationError") {
      return res.status(400).json({ error: `Validation error: ${err.message}` });
    }
    if (err.code === 11000) {
      return res.status(400).json({ error: "Duplicate key error: email or mobile already exists" });
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

  const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
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

    const validClubs = await Club.find({ name: { $in: clubName } }).distinct(
      "name"
    );
    if (clubName.some((name) => !validClubs.includes(name))) {
      return res
        .status(400)
        .json({ error: "One or more club names are invalid" });
    }

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
    const clubs = await Club.find(query).populate("superAdmins", "name email");
    const transformedClubs = clubs.map((club) => ({
      ...club._doc,
      icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
      banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
    }));
    res.json(transformedClubs);
  } catch (err) {
    console.error("Error fetching clubs:", err);
    res.status(500).json({ error: "Server error" });
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
    const { name, description, category, contactEmail, headCoordinators, superAdmins } = req.body;
    if (!name || !description || !category || !req.files.icon) {
      return res.status(400).json({ error: "Name, description, category, and icon are required" });
    }
    if (!["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(category)) {
      return res.status(400).json({ error: "Invalid category" });
    }
    if (description.length > 500) {
      return res.status(400).json({ error: "Description must be 500 characters or less" });
    }
    if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
      return res.status(400).json({ error: "Invalid contact email" });
    }

    try {
      let validHeadCoordinators = [];
      if (headCoordinators) {
        const emails = headCoordinators.split(",").map((email) => email.trim()).filter((email) => email);
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        validHeadCoordinators = emails.filter((email) => emailRegex.test(email));
        await User.updateMany(
          { email: { $in: validHeadCoordinators } },
          { $set: { isHeadCoordinator: true }, $addToSet: { headCoordinatorClubs: name } }
        );
      }

      let validSuperAdmins = [];
      if (superAdmins) {
        const adminIds = superAdmins.split(",").map((id) => id.trim()).filter((id) => id);
        if (adminIds.length > 2) {
          return res.status(400).json({ error: "A club can have at most 2 super admins" });
        }
        const users = await User.find({ _id: { $in: adminIds } });
        validSuperAdmins = users.map((user) => user._id);
        if (validSuperAdmins.length !== adminIds.length) {
          return res.status(400).json({ error: "One or more super admin IDs are invalid" });
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
  }
);

// Delete Club (Admin only)
app.delete("/api/clubs/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }

    // Remove club from users' clubName and pendingClubs
    await User.updateMany(
      { $or: [{ clubName: club.name }, { pendingClubs: club.name }] },
      { $pull: { clubName: club.name, pendingClubs: club.name }, $set: { isClubMember: { $cond: [{ $eq: ["$clubName", []] }, false, true] } } }
    );

    // Remove membership requests
    await MembershipRequest.deleteMany({ clubName: club.name });

    // Remove events
    await Event.deleteMany({ club: club._id });

    // Delete club
    await club.deleteOne();

    res.json({ message: "Club deleted successfully" });
  } catch (err) {
    console.error("Club deletion error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Join Club
app.post("/api/clubs/:id/join", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const club = await Club.findById(id);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.clubName.includes(club.name)) {
      return res.status(400).json({ error: "You are already a member of this club" });
    }

    if (user.pendingClubs.includes(club.name)) {
      return res.status(400).json({ error: "Membership request already pending" });
    }

    const membershipRequest = new MembershipRequest({
      userId: user._id,
      clubName: club.name,
    });
    await membershipRequest.save();

    user.pendingClubs.push(club.name);
    await user.save();

    const recipients = [
      ...club.headCoordinators,
      ...(process.env.SUPER_ADMIN_EMAILS ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim()) : []),
    ];
    if (recipients.length > 0) {
      await transporter.sendMail({
        from: `"ACEM" <${process.env.EMAIL_USER}>`,
        to: recipients,
        subject: `New Membership Request for ${club.name}`,
        text: `User ${user.name} (${user.email}) has requested to join ${club.name}. Please review the request in the admin dashboard.`,
      });
    }

    res.json({ message: "Membership request sent successfully" });
  } catch (err) {
    console.error("Error requesting club membership:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Membership Requests
app.get("/api/membership-requests", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    let query = {};
    if (!superAdminEmails.includes(user.email)) {
      if (!user.isHeadCoordinator || !user.headCoordinatorClubs.length) {
        return res.status(403).json({ error: "Access denied" });
      }
      query.clubName = { $in: user.headCoordinatorClubs };
    }

    const requests = await MembershipRequest.find(query).populate("userId", "name email mobile");
    res.json(requests);
  } catch (err) {
    console.error("Error fetching membership requests:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Approve/Reject Membership Request
app.patch("/api/membership-requests/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  try {
    const request = await MembershipRequest.findById(id);
    if (!request) {
      return res.status(404).json({ error: "Membership request not found" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    if (
      !superAdminEmails.includes(user.email) &&
      (!user.isHeadCoordinator || !user.headCoordinatorClubs.includes(request.clubName))
    ) {
      return res.status(403).json({ error: "Access denied" });
    }

    request.status = status;
    await request.save();

    const targetUser = await User.findById(request.userId);
    if (!targetUser) {
      return res.status(404).json({ error: "Target user not found" });
    }

    if (status === "approved") {
      targetUser.clubName.push(request.clubName);
      targetUser.isClubMember = true;
      targetUser.pendingClubs = targetUser.pendingClubs.filter((club) => club !== request.clubName);
      await targetUser.save();

      const club = await Club.findOne({ name: request.clubName });
      if (club) {
        club.memberCount += 1;
        await club.save();
      }

      await transporter.sendMail({
        from: `"ACEM" <${process.env.EMAIL_USER}>`,
        to: targetUser.email,
        subject: `Membership Request Approved for ${request.clubName}`,
        text: `Congratulations! Your request to join ${request.clubName} has been approved.`,
      });
    } else {
      targetUser.pendingClubs = targetUser.pendingClubs.filter((club) => club !== request.clubName);
      await targetUser.save();

      await transporter.sendMail({
        from: `"ACEM" <${process.env.EMAIL_USER}>`,
        to: targetUser.email,
        subject: `Membership Request Rejected for ${request.clubName}`,
        text: `We regret to inform you that your request to join ${request.clubName} has been rejected.`,
      });
    }

    res.json({ message: `Membership request ${status} successfully` });
  } catch (err) {
    console.error("Error updating membership request:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Single Club
app.get("/api/clubs/:id", authenticateToken, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id).populate("superAdmins", "name email");
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }
    const transformedClub = {
      ...club._doc,
      icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
      banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
    };
    res.json(transformedClub);
  } catch (err) {
    console.error("Error fetching club:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update Club
app.patch(
  "/api/clubs/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  upload.fields([
    { name: "icon", maxCount: 1 },
    { name: "banner", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const { description, category, contactEmail, headCoordinators, superAdmins } = req.body;

    if (req.body.name) {
      return res.status(400).json({ error: "Club name cannot be updated" });
    }

    try {
      const club = await Club.findById(id);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      if (description && description.length > 500) {
        return res.status(400).json({ error: "Description must be 500 characters or less" });
      }
      if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
        return res.status(400).json({ error: "Invalid contact email" });
      }

      let validHeadCoordinators = club.headCoordinators;
      if (headCoordinators !== undefined) {
        const emails = headCoordinators
          ? headCoordinators.split(",").map((email) => email.trim()).filter((email) => email)
          : [];
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        validHeadCoordinators = emails.filter((email) => emailRegex.test(email));
        await User.updateMany(
          { email: { $in: validHeadCoordinators } },
          { $set: { isHeadCoordinator: true }, $addToSet: { headCoordinatorClubs: club.name } }
        );
        await User.updateMany(
          { email: { $nin: validHeadCoordinators, $in: club.headCoordinators }, headCoordinatorClubs: club.name },
          { $pull: { headCoordinatorClubs: club.name }, $set: { isHeadCoordinator: { $cond: [{ $eq: ["$headCoordinatorClubs", []] }, false, true] } } }
        );
      }

      let validSuperAdmins = club.superAdmins;
      if (superAdmins !== undefined) {
        const adminIds = superAdmins
          ? superAdmins.split(",").map((id) => id.trim()).filter((id) => id)
          : [];
        if (adminIds.length > 2) {
          return res.status(400).json({ error: "A club can have at most 2 super admins" });
        }
        const users = await User.find({ _id: { $in: adminIds } });
        validSuperAdmins = users.map((user) => user._id);
        if (validSuperAdmins.length !== adminIds.length) {
          return res.status(400).json({ error: "One or more super admin IDs are invalid" });
        }
      }

      if (req.files.icon) club.icon = req.files.icon[0].path;
      if (req.files.banner) club.banner = req.files.banner[0].path;
      if (description) club.description = description;
      if (category) {
        if (!["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(category)) {
          return res.status(400).json({ error: "Invalid category" });
        }
        club.category = category;
      }
      if (contactEmail !== undefined) club.contactEmail = contactEmail;
      club.headCoordinators = validHeadCoordinators;
      club.superAdmins = validSuperAdmins;

      await club.save();
      res.status(200).json({ message: "Club updated successfully", club });
    } catch (err) {
      console.error("Club update error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get Club Members
app.get("/api/clubs/:id/members", authenticateToken, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }
    const members = await User.find({ clubName: club.name }, "name email").lean();
    res.json(members);
  } catch (err) {
    console.error("Error fetching club members:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Remove Club Member
app.delete("/api/clubs/:id/members", authenticateToken, isHeadCoordinatorOrAdmin, async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: "Member email is required" });
  }

  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!user.clubName.includes(club.name)) {
      return res.status(400).json({ error: "User is not a member of this club" });
    }

    user.clubName = user.clubName.filter((name) => name !== club.name);
    user.isClubMember = user.clubName.length > 0;
    await user.save();

    club.memberCount = Math.max(0, club.memberCount - 1);
    await club.save();

    res.json({ message: "Member removed successfully" });
  } catch (err) {
    console.error("Error removing club member:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Create Event
app.post("/api/events", authenticateToken, isSuperAdmin, upload.single("banner"), async (req, res) => {
  const { title, description, date, time, location, club } = req.body;
  if (!title || !description || !date || !time || !location || !club) {
    return res.status(400).json({ error: "All fields are required except banner" });
  }

  try {
    const clubDoc = await Club.findById(club);
    if (!clubDoc) {
      return res.status(404).json({ error: "Club not found" });
    }

    const event = new Event({
      title,
      description,
      date,
      time,
      location,
      club,
      banner: req.file ? req.file.path : null,
      createdBy: req.user.id,
    });
    await event.save();

    clubDoc.eventsCount += 1;
    await clubDoc.save();

    const transformedEvent = {
      ...event._doc,
      banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
    };
    res.status(201).json(transformedEvent);
  } catch (err) {
    console.error("Event creation error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Events
app.get("/api/events", authenticateToken, async (req, res) => {
  try {
    const { club } = req.query;
    const query = club ? { club } : {};
    const events = await Event.find(query)
      .populate("club", "name")
      .populate("createdBy", "name email");
    const transformedEvents = events.map((event) => ({
      ...event._doc,
      banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
    }));
    res.json(transformedEvents);
  } catch (err) {
    console.error("Error fetching events:", err);
    res.status(500).json({ error: "Server error" });
  }
});

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
    res.json({ message: "Message sent successfully" });
  } catch (err) {
    console.error("Error sending contact email:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));