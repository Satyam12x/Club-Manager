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

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club", required: true },
  date: { type: String, required: true },
  lectureNumber: { type: Number, required: true },
  attendance: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    status: { type: String, enum: ["present", "absent"], required: true },
  }],
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

// Middleware to check super admin or admin
const isSuperAdminOrAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    if (user.isAdmin || superAdminEmails.includes(user.email)) {
      return next();
    }
    if (req.body.club) {
      const club = await Club.findById(req.body.club);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }
      if (
        club.superAdmins
          .map((id) => id.toString())
          .includes(user._id.toString())
      ) {
        return next();
      }
    }
    res.status(403).json({ error: "Super admin or admin access required" });
  } catch (err) {
    console.error("Super admin or admin check error:", err);
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
    if (req.params.id || req.body.club) {
      const clubId = req.params.id || req.body.club;
      const club = await Club.findById(clubId);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }
      if (
        club.superAdmins
          .map((id) => id.toString())
          .includes(user._id.toString())
      ) {
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
    const clubId = req.params.id || req.body.club;
    const club = clubId ? await Club.findById(clubId) : null;
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    if (
      club &&
      !user.isAdmin &&
      (!user.isHeadCoordinator ||
        !user.headCoordinatorClubs.includes(club.name))
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
    {
      expiresIn: "1d",
    }
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
    {
      expiresIn: "1d",
    }
  );
  res.json({ token });
});

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, mobile, rollNo } = req.body;
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
      {
        expiresIn: "1d",
      }
    );
    res.json({ token });
  } catch (err) {
    console.error("Signup error:", err);
    if (err.name === "ValidationError") {
      return res
        .status(400)
        .json({ error: `Validation error: ${err.message}` });
    }
    if (err.code === 11000) {
      return res
        .status(400)
        .json({ error: "Duplicate key error: email, mobile, or roll number already exists" });
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
    {
      expiresIn: "1d",
    }
  );
  res.json({ token });
});

// User Profile Update
app.put("/api/auth/user", authenticateToken, async (req, res) => {
  const { name, email, phone } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: "Name and email are required" });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "Email already in use" });
      }
    }

    user.name = name;
    user.email = email;
    user.phone = phone || user.phone;
    await user.save();

    // Update headCoordinators in clubs if email changed
    if (email !== req.user.email) {
      await Club.updateMany(
        { headCoordinators: req.user.email },
        { $set: { "headCoordinators.$": email } }
      );
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );
    res.json({ message: "Profile updated successfully", user, token });
  } catch (err) {
    console.error("Profile update error:", err);
    if (err.code === 11000) {
      return res
        .status(400)
        .json({ error: "Duplicate key error: email or phone already exists" });
    }
    res.status(500).json({ error: "Server error" });
  }
});

// User Details Endpoint (POST)
app.post("/api/auth/user-details", authenticateToken, async (req, res) => {
  const { semester, course, specialization, isClubMember, clubName, rollNo } = req.body;
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
    user.rollNo = rollNo || user.rollNo;
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

    // Update memberCount for each club
    for (const name of clubName) {
      await Club.updateOne({ name }, { $inc: { memberCount: 1 } });
    }

    // Notify user of successful club join
    await Notification.create({
      userId: user._id,
      message: `You have successfully joined ${clubName.join(", ")}.`,
      type: "membership",
    });

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
      "name email semester course specialization phone isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs rollNo"
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get All Users (Admin only)
app.get("/api/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select(
      "name email mobile semester course specialization phone isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs createdAt rollNo"
    );
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
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
    const {
      name,
      description,
      category,
      contactEmail,
      headCoordinators,
      superAdmins,
    } = req.body;
    if (!name || !description || !category || !req.files.icon) {
      return res
        .status(400)
        .json({ error: "Name, description, category, and icon are required" });
    }
    if (
      !["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(
        category
      )
    ) {
      return res.status(400).json({ error: "Invalid category" });
    }
    if (description.length > 500) {
      return res
        .status(400)
        .json({ error: "Description must be 500 characters or less" });
    }
    if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
      return res.status(400).json({ error: "Invalid contact email" });
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

      let validSuperAdmins = [req.user.id]; // Add creator as super admin
      if (superAdmins) {
        const adminIds = superAdmins
          .split(",")
          .map((id) => id.trim())
          .filter((id) => id && id !== req.user.id);
        if (adminIds.length + 1 > 2) {
          return res
            .status(400)
            .json({ error: "A club can have at most 2 super admins" });
        }
        const users = await User.find({ _id: { $in: adminIds } });
        validSuperAdmins = [
          ...validSuperAdmins,
          ...users.map((user) => user._id),
        ];
        if (validSuperAdmins.length !== adminIds.length + 1) {
          return res
            .status(400)
            .json({ error: "One or more super admin IDs are invalid" });
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

      // Notify super admins
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
      res
        .status(201)
        .json({ message: "Club created successfully", club: transformedClub });
    } catch (err) {
      console.error("Club creation error:", err);
      if (err.code === 11000) {
        return res.status(400).json({ error: "Club name already exists" });
      }
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Update Club (Head Coordinator or Admin)
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
    const {
      description,
      category,
      contactEmail,
      headCoordinators,
      superAdmins,
    } = req.body;

    if (req.body.name) {
      return res.status(400).json({ error: "Club name cannot be updated" });
    }

    try {
      const club = await Club.findById(id);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      if (description && description.length > 500) {
        return res
          .status(400)
          .json({ error: "Description must be 500 characters or less" });
      }
      if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
        return res.status(400).json({ error: "Invalid contact email" });
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
          return res
            .status(400)
            .json({ error: "A club can have at most 2 super admins" });
        }
        const users = await User.find({ _id: { $in: adminIds } });
        validSuperAdmins = users.map((user) => user._id);
        if (validSuperAdmins.length !== adminIds.length) {
          return res
            .status(400)
            .json({ error: "One or more super admin IDs are invalid" });
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
          return res.status(400).json({ error: "Invalid category" });
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
      res
        .status(200)
        .json({ message: "Club updated successfully", club: transformedClub });
    } catch (err) {
      console.error("Club update error:", err);
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
      return res
        .status(400)
        .json({ error: "You are already a member of this club" });
    }

    if (user.pendingClubs.includes(club.name)) {
      return res
        .status(400)
        .json({ error: "Membership request already pending" });
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

    const requests = await MembershipRequest.find(query).populate(
      "userId",
      "name email mobile"
    );
    res.json(requests);
  } catch (err) {
    console.error("Error fetching membership requests:", err);
    res.status(500).json({ error: "Server error" });
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
        (!user.isHeadCoordinator ||
          !user.headCoordinatorClubs.includes(request.clubName))
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

      res.json({ message: `Membership request ${status} successfully` });
    } catch (err) {
      console.error("Error updating membership request:", err);
      res.status(500).json({ error: "Server error" });
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
      return res.status(404).json({ error: "Club not found" });
    }
    const members = await User.countDocuments({ clubName: club.name });
    const transformedClub = {
      ...club._doc,
      icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
      banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
      memberCount: members,
    };
    res.json(transformedClub);
  } catch (err) {
    console.error("Error fetching club:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Club Members
app.get("/api/clubs/:id/members", authenticateToken, async (req, res) => {
  try {
    const club = await Club.findById(req.params.id);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }
    const members = await User.find(
      { clubName: club.name },
      "name email mobile phone rollNo"
    ).lean();
    res.json(members);
  } catch (err) {
    console.error("Error fetching club members:", err);
    res.status(500).json({ error: "Server error" });
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
        return res
          .status(400)
          .json({ error: "User is not a member of this club" });
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

      res.json({ message: "Member removed successfully" });
    } catch (err) {
      console.error("Error removing club member:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Create Event
app.post(
  "/api/events",
  authenticateToken,
  isSuperAdmin,
  upload.single("banner"),
  async (req, res) => {
    const { title, description, date, time, location, club } = req.body;
    if (!title || !description || !date || !time || !location || !club) {
      return res
        .status(400)
        .json({ error: "All fields are required except banner" });
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
      res.status(201).json(transformedEvent);
    } catch (err) {
      console.error("Event creation error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

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

// Get Single Event
app.get("/api/events/:id", authenticateToken, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate("club", "name")
      .populate("createdBy", "name email");
    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }
    const transformedEvent = {
      ...event._doc,
      banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
    };
    res.json(transformedEvent);
  } catch (err) {
    console.error("Error fetching event:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update Event
app.put(
  "/api/events/:id",
  authenticateToken,
  isSuperAdmin,
  upload.single("banner"),
  async (req, res) => {
    const { id } = req.params;
    const { title, description, date, time, location, club } = req.body;

    if (!title || !description || !date || !time || !location || !club) {
      return res
        .status(400)
        .json({ error: "All fields are required except banner" });
    }

    try {
      const event = await Event.findById(id);
      if (!event) {
        return res.status(404).json({ error: "Event not found" });
      }

      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
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
      res.json({
        message: "Event updated successfully",
        event: transformedEvent,
      });
    } catch (err) {
      console.error("Event update error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Delete Event
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
app.post("/api/attendance", authenticateToken, isSuperAdminOrAdmin, async (req, res) => {
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

    res.status(201).json({ message: "Attendance recorded successfully", attendance: attendanceRecord });
  } catch (err) {
    console.error("Attendance creation error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Attendance Records
app.get("/api/attendance", authenticateToken, isSuperAdminOrAdmin, async (req, res) => {
  try {
    const { club, date, lectureNumber } = req.query;
    const query = {};
    if (club) query.club = club;
    if (date) query.date = date;
    if (lectureNumber) query.lectureNumber = Number(lectureNumber);

    const user = await User.findById(req.user.id);
    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    if (!user.isAdmin && !superAdminEmails.includes(user.email)) {
      const clubs = await Club.find({
        superAdmins: user._id,
      }).distinct("_id");
      query.club = { $in: clubs };
    }

    const attendanceRecords = await Attendance.find(query)
      .populate("club", "name")
      .populate("createdBy", "name email")
      .populate("attendance.userId", "name email rollNo");
    res.json(attendanceRecords);
  } catch (err) {
    console.error("Error fetching attendance records:", err);
    res.status(500).json({ error: "Server error" });
  }
});



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));