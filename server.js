const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises;
const {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  Table,
  TableRow,
  TableCell,
  WidthType,
} = require("docx");

dotenv.config();

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "Uploads")));

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

// Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: { type: String, unique: true, sparse: true },
  rollNo: { type: String, unique: true, sparse: true },
  branch: { type: String, default: null },
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
  isACEMStudent: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  clubs: [{ type: mongoose.Schema.Types.ObjectId, ref: "Club", default: [] }],
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
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }],
  memberCount: { type: Number, default: 0 },
  eventsCount: { type: Number, default: 0 },
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
});

const Club = mongoose.model("Club", clubSchema);

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
  registeredUsers: [
    {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      name: String,
      email: String,
      rollNo: String,
      isACEMStudent: Boolean,
    },
  ],
  category: {
    type: String,
    enum: ["Seminar", "Competition"],
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

const Event = mongoose.model("Event", eventSchema);

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

const attendanceSchema = new mongoose.Schema({
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club", required: true },
  event: { type: mongoose.Schema.Types.ObjectId, ref: "Event", required: true },
  date: { type: Date, required: true },
  attendance: [
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      status: { type: String, enum: ["present", "absent"], required: true },
    },
  ],
  stats: {
    presentCount: { type: Number, default: 0 },
    absentCount: { type: Number, default: 0 },
    totalMarked: { type: Number, default: 0 },
    attendanceRate: { type: Number, default: 0 },
    totalPoints: { type: Number, default: 0 }, // New field for total points
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});

const Attendance = mongoose.model("Attendance", attendanceSchema);


const practiceAttendanceSchema = new mongoose.Schema({
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club", required: true },
  title: { type: String, required: true },
  date: { type: Date, required: true },
  roomNo: { type: String, required: true },
  attendance: [
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      status: { type: String, enum: ["present", "absent"], required: true },
    },
  ],
  stats: {
    presentCount: { type: Number, default: 0 },
    absentCount: { type: Number, default: 0 },
    totalMarked: { type: Number, default: 0 },
    attendanceRate: { type: Number, default: 0 },
    totalPoints: { type: Number, default: 0 }, // New field for total points
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
});
practiceAttendanceSchema.index(
  { club: 1, title: 1, date: 1, roomNo: 1 },
  { unique: true }
);
const PracticeAttendance = mongoose.model(
  "PracticeAttendance",
  practiceAttendanceSchema
);


const isValidDate = (dateString) => {
  return !isNaN(new Date(dateString).getTime());
};

const contactMessageSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  club: { type: String },
  status: {
    type: String,
    enum: ["new", "read", "replied", "archived"],
    default: "new",
  },
  priority: {
    type: String,
    enum: ["low", "medium", "high"],
    default: "low",
  },
  isStarred: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  replies: [
    {
      reply: { type: String, required: true },
      repliedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      repliedAt: { type: Date, default: Date.now },
    },
  ],
});

const ContactMessage = mongoose.model("ContactMessage", contactMessageSchema);
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

// Authentication Middleware
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

const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: "Admin access required" });
    }
    next();
  } catch (err) {
    console.error("Admin check error:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in admin check" });
  }
};

const isSuperAdmin = async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: "Invalid club ID" });
    }
    const user = await User.findById(req.user.id);
    if (!user) {
      console.error("isSuperAdmin: User not found for ID:", req.user.id);
      return res.status(404).json({ error: "User not found" });
    }
    const club = await Club.findById(req.params.id);
    if (!club) {
      console.error("isSuperAdmin: Club not found for ID:", req.params.id);
      return res.status(404).json({ error: "Club not found" });
    }
    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    const isAuthorized =
      superAdminEmails.includes(user.email) ||
      club.creator?.toString() === user._id.toString();
    if (!isAuthorized) {
      console.error(
        "isSuperAdmin: User not authorized for club:",
        club.name,
        "User ID:",
        user._id,
        "Role check:",
        {
          isGlobalAdmin: superAdminEmails.includes(user.email),
          isCreator: club.creator?.toString() === user._id.toString(),
        }
      );
      return res
        .status(403)
        .json({
          error: "You are not authorized to perform this action on this club",
        });
    }
    next();
  } catch (err) {
    console.error("Super admin check error:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
      clubId: req.params.id,
    });
    res.status(500).json({ error: "Server error in authorization check" });
  }
};

const isSuperAdminOrAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.error("isSuperAdminOrAdmin: User not found for ID:", req.user.id);
      return res.status(404).json({ error: "User not found" });
    }
    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];

    if (superAdminEmails.includes(user.email)) {
      console.log("isSuperAdminOrAdmin: User is global admin:", user.email);
      return next();
    }

    const clubId =
      req.body.club ||
      req.query.club ||
      req.body.event?.club ||
      req.params.clubId ||
      req.params.id;
    if (!clubId) {
      console.error("isSuperAdminOrAdmin: Club ID not provided in request");
      return res.status(400).json({ error: "Club ID is required" });
    }

    const club = await Club.findById(clubId);
    if (!club) {
      console.error("isSuperAdminOrAdmin: Club not found for ID:", clubId);
      return res.status(404).json({ error: "Club not found" });
    }

    if (club.creator.toString() === user._id.toString()) {
      console.log(
        "isSuperAdminOrAdmin: User authorized for club:",
        club.name,
        "as Creator"
      );
      return next();
    }

    console.error(
      "isSuperAdminOrAdmin: User not authorized for club:",
      club.name,
      "User ID:",
      user._id
    );
    res.status(403).json({ error: "Creator access required" });
  } catch (err) {
    console.error("isSuperAdminOrAdmin error:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
      clubId: req.body.club || req.query.club || req.params.id,
    });
    res.status(500).json({ error: "Server error in authorization check" });
  }
};

const isHeadCoordinatorOrAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.error(
        "isHeadCoordinatorOrAdmin: User not found for ID:",
        req.user.id
      );
      return res.status(404).json({ error: "User not found" });
    }
    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];

    if (superAdminEmails.includes(user.email)) {
      console.log(
        "isHeadCoordinatorOrAdmin: User is global super admin:",
        user.email
      );
      return next();
    }

    const clubId =
      req.params.id ||
      req.body.club ||
      req.body.event?.club ||
      req.params.clubId;
    if (!clubId) {
      console.error(
        "isHeadCoordinatorOrAdmin: Club ID not provided in request"
      );
      return res.status(400).json({ error: "Club ID is required" });
    }

    const club = await Club.findById(clubId);
    if (!club) {
      console.error("isHeadCoordinatorOrAdmin: Club not found for ID:", clubId);
      return res.status(404).json({ error: "Club not found" });
    }

    if (user.headCoordinatorClubs.includes(club.name)) {
      console.log(
        "isHeadCoordinatorOrAdmin: User authorized for club:",
        club.name,
        "as HeadCoordinator"
      );
      return next();
    }

    console.error(
      "isHeadCoordinatorOrAdmin: User not authorized for club:",
      club.name,
      "User ID:",
      user._id,
      "HeadCoordinatorClubs:",
      user.headCoordinatorClubs
    );
    res.status(403).json({ error: "Head coordinator access required" });
  } catch (err) {
    console.error("Head coordinator check error:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
      clubId: req.params.id || req.body.club,
    });
    res.status(500).json({ error: "Server error in authorization check" });
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
  const { name, email, password, mobile, rollNo, branch, isACEMStudent } =
    req.body;
  if (!name || !email || !password || isACEMStudent === undefined) {
    return res.status(400).json({
      error: "Name, email, password, and ACEM student status are required",
    });
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
      branch,
      isAdmin,
      isHeadCoordinator,
      headCoordinatorClubs,
      isACEMStudent,
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
    console.error("Signup error:", { message: err.message, stack: err.stack });
    if (err.name === "ValidationError") {
      return res
        .status(400)
        .json({ error: `Validation error: ${err.message}` });
    }
    if (err.code === 11000) {
      return res.status(400).json({
        error:
          "Duplicate key error: email, mobile, or roll number already exists",
      });
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
  const { name, email, phone, isACEMStudent } = req.body;
  if (!name || !email || isACEMStudent === undefined) {
    return res
      .status(400)
      .json({ error: "Name, email, and ACEM student status are required" });
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
    user.isACEMStudent = isACEMStudent;
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
      {
        expiresIn: "1d",
      }
    );
    res.json({ message: "Profile updated successfully", user, token });
  } catch (err) {
    console.error("Profile update error:", {
      message: err.message,
      stack: err.stack,
    });
    if (err.code === 11000) {
      return res
        .status(400)
        .json({ error: "Duplicate key error: email or phone already exists" });
    }
    res.status(500).json({ error: "Server error in profile update" });
  }
});

// User Details Endpoint (POST)
app.post("/api/auth/user-details", authenticateToken, async (req, res) => {
  const {
    semester,
    course,
    specialization,
    isClubMember,
    clubName,
    rollNo,
    isACEMStudent,
  } = req.body;
  if (!semester || !course || !specialization || isACEMStudent === undefined) {
    return res.status(400).json({
      error:
        "Semester, course, specialization, and ACEM student status are required",
    });
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
    user.isACEMStudent = isACEMStudent;
    await user.save();

    res.status(200).json({ message: "User details saved successfully" });
  } catch (err) {
    console.error("User details error:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in user details update" });
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
    user.clubs = [
      ...new Set([
        ...user.clubs,
        ...(await Club.find({ name: { $in: clubName } }).distinct("_id")),
      ]),
    ];
    user.isClubMember =
      isClubMember !== undefined ? isClubMember : user.clubName.length > 0;
    await user.save();

    for (const name of clubName) {
      const club = await Club.findOne({ name });
      if (club && !club.members.includes(user._id)) {
        club.members.push(user._id);
        club.memberCount = await User.countDocuments({ clubName: club.name });
        await club.save();
      }
    }

    await Notification.create({
      userId: user._id,
      message: `You have successfully joined ${clubName.join(", ")}.`,
      type: "membership",
    });

    res.status(200).json({ message: "Club joined successfully" });
  } catch (err) {
    console.error("Error updating user details:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in user details update" });
  }
});

// Get User Data
app.get("/api/auth/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select(
        "name email semester course specialization phone isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs rollNo branch isACEMStudent clubs"
      )
      .populate("clubs", "name");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("Error fetching user:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching user data" });
  }
});

// Get All Users (Admin only)
app.get("/api/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find()
      .select(
        "name email mobile semester course specialization phone isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs createdAt rollNo branch isACEMStudent clubs"
      )
      .populate("clubs", "name");
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching users" });
  }
});

// Get Clubs
app.get("/api/clubs", authenticateToken, async (req, res) => {
  try {
    const clubs = await Club.find()
      .populate("superAdmins", "name email")
      .populate("members", "name email")
      .populate("creator", "name email")
      .lean();

    const clubsWithCounts = await Promise.all(
      clubs.map(async (club) => {
        const memberCount = club.members ? club.members.length : 0;
        const eventsCount = await Event.countDocuments({ club: club._id });
        return {
          ...club,
          memberCount,
          eventsCount,
          icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
          banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
        };
      })
    );

    res.json(clubsWithCounts);
  } catch (err) {
    console.error("Error fetching clubs:", {
      message: err.message,
      stack: err.stack,
      userId: req.user.id,
    });
    res.status(500).json({ error: "Server error in fetching clubs" });
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
    if (!name || !description || !category || !req.files?.icon) {
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

      let validSuperAdmins = [req.user.id];
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

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
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
        members: [req.user.id],
        memberCount: 1,
        eventsCount: 0,
        creator: req.user.id,
      });
      await club.save();

      user.clubs.push(club._id);
      user.clubName.push(club.name);
      user.isClubMember = true;
      await user.save();

      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      if (superAdminEmails.length > 0) {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: superAdminEmails,
          subject: `New Club Created: ${name}`,
          text: `A new club "${name}" has been created by ${req.user.email}, who has joined as a member.`,
        });
      }

      await Notification.create({
        userId: req.user.id,
        message: `You have successfully created and joined ${name}.`,
        type: "membership",
      });

      const populatedClub = await Club.findById(club._id)
        .populate("superAdmins", "name email")
        .populate("members", "name email")
        .populate("creator", "name email");
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
      console.error("Club creation error:", {
        message: err.message,
        stack: err.stack,
      });
      if (err.code === 11000) {
        return res.status(400).json({ error: "Club name already exists" });
      }
      res.status(500).json({ error: "Server error in club creation" });
    }
  }
);

// Update Club (Creator, Super Admin, or Head Coordinator only)
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

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: "Invalid club ID" });
    }

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
      if (
        category &&
        !["Technical", "Cultural", "Literary", "Entrepreneurial"].includes(
          category
        )
      ) {
        return res.status(400).json({ error: "Invalid category" });
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
        if (emails.length > 0 && validHeadCoordinators.length === 0) {
          return res
            .status(400)
            .json({
              error: "All provided head coordinator emails are invalid",
            });
        }
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
        if (adminIds.length > 0) {
          if (!adminIds.every((id) => mongoose.isValidObjectId(id))) {
            return res
              .status(400)
              .json({ error: "Invalid super admin ID format" });
          }
          const users = await User.find({ _id: { $in: adminIds } });
          validSuperAdmins = users.map((user) => user._id);
          if (validSuperAdmins.length !== adminIds.length) {
            return res
              .status(400)
              .json({ error: "One or more super admin IDs are invalid" });
          }
        } else {
          validSuperAdmins = [];
        }
      }

      if (req.files?.icon) {
        if (club.icon) {
          try {
            await fs.access(club.icon);
            await fs.unlink(club.icon);
          } catch (err) {
            console.warn("Failed to delete old icon:", {
              message: err.message,
              path: club.icon,
            });
          }
        }
        club.icon = req.files.icon[0].path;
      }
      if (req.files?.banner) {
        if (club.banner) {
          try {
            await fs.access(club.banner);
            await fs.unlink(club.banner);
          } catch (err) {
            console.warn("Failed to delete old banner:", {
              message: err.message,
              path: club.banner,
            });
          }
        }
        club.banner = req.files.banner[0].path;
      }
      if (description !== undefined) club.description = description;
      if (category) club.category = category;
      if (contactEmail !== undefined) club.contactEmail = contactEmail || null;
      club.headCoordinators = validHeadCoordinators;
      club.superAdmins = validSuperAdmins;

      club.memberCount = club.members.length;
      try {
        club.eventsCount = await Event.countDocuments({ club: club._id });
      } catch (err) {
        console.error("Error counting events:", {
          message: err.message,
          stack: err.stack,
        });
        club.eventsCount = 0;
      }

      await club.save();

      const members = await User.find({ _id: { $in: club.members } });
      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      const recipients = [...members.map((m) => m.email), ...superAdminEmails];
      if (recipients.length > 0) {
        try {
          await transporter.sendMail({
            from: `"ACEM" <${process.env.EMAIL_USER}>`,
            to: recipients,
            subject: `Club Updated: ${club.name}`,
            text: `The club "${club.name}" has been updated by ${req.user.email}.`,
          });
        } catch (err) {
          console.error("Error sending update notification email:", {
            message: err.message,
            stack: err.stack,
          });
        }
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
      console.error("Club update error:", {
        message: err.message,
        stack: err.stack,
        clubId: id,
        userId: req.user.id,
        requestBody: req.body,
        files: req.files ? Object.keys(req.files) : null,
      });
      if (err.name === "ValidationError") {
        return res
          .status(400)
          .json({ error: `Validation error: ${err.message}` });
      }
      res.status(500).json({ error: "Server error in club update" });
    }
  }
);

// Delete Club (Creator, Super Admin, or Head Coordinator only)
app.delete(
  "/api/clubs/:id",
  authenticateToken,
  isSuperAdmin,
  async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ error: "Invalid club ID" });
      }

      const club = await Club.findById(req.params.id);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const members = await User.find({ _id: { $in: club.members } });
      await User.updateMany(
        {
          $or: [
            { clubName: club.name },
            { pendingClubs: club.name },
            { clubs: club._id },
          ],
        },
        {
          $pull: {
            clubName: club.name,
            pendingClubs: club.name,
            clubs: club._id,
          },
          $set: {
            isClubMember: { $cond: [{ $eq: ["$clubName", []] }, false, true] },
          },
        }
      );

      await MembershipRequest.deleteMany({ clubName: club.name });
      await Event.deleteMany({ club: club._id });
      await Attendance.deleteMany({ club: club._id });
      await PracticeAttendance.deleteMany({ club: club._id });

      if (club.icon) {
        try {
          await fs.access(club.icon);
          await fs.unlink(club.icon);
        } catch (err) {
          console.warn("Failed to delete club icon:", {
            message: err.message,
            path: club.icon,
          });
        }
      }
      if (club.banner) {
        try {
          await fs.access(club.banner);
          await fs.unlink(club.banner);
        } catch (err) {
          console.warn("Failed to delete club banner:", {
            message: err.message,
            path: club.banner,
          });
        }
      }

      await club.deleteOne();

      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      const recipients = [...members.map((m) => m.email), ...superAdminEmails];
      if (recipients.length > 0) {
        try {
          await transporter.sendMail({
            from: `"ACEM" <${process.env.EMAIL_USER}>`,
            to: recipients,
            subject: `Club Deleted: ${club.name}`,
            text: `The club "${club.name}" has been deleted by ${req.user.email}.`,
          });
        } catch (err) {
          console.error("Error sending deletion notification email:", {
            message: err.message,
            stack: err.stack,
          });
        }
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
      console.error("Club deletion error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in club deletion" });
    }
  }
);

// Join Club
app.post("/api/clubs/:id/join", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: "Invalid club ID" });
    }

    const club = await Club.findById(id);
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.clubs.includes(club._id) || user.clubName.includes(club.name)) {
      return res
        .status(400)
        .json({ error: "You are already a member of this club" });
    }

    const existingRequest = await MembershipRequest.findOne({
      userId: user._id,
      clubName: club.name,
      status: "pending",
    });
    if (existingRequest) {
      return res
        .status(400)
        .json({ error: "You already have a pending request for this club" });
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
      try {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: recipients,
          subject: `New Membership Request for ${club.name}`,
          text: `User ${user.name} (${user.email}) has requested to join ${club.name}.`,
        });
      } catch (err) {
        console.error("Error sending membership request email:", {
          message: err.message,
          stack: err.stack,
        });
      }
    }

    await Notification.create({
      userId: user._id,
      message: `Your request to join ${club.name} has been submitted.`,
      type: "membership",
    });

    res.json({ message: "Membership request submitted successfully" });
  } catch (err) {
    console.error("Error submitting membership request:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in membership request" });
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
      const clubs = await Club.find({
        $or: [
          { creator: user._id },
          { superAdmins: user._id },
          { name: { $in: user.headCoordinatorClubs } },
        ],
      }).distinct("name");
      query.clubName = { $in: clubs };
    }

    const requests = await MembershipRequest.find(query).populate(
      "userId",
      "name email mobile rollNo isACEMStudent"
    );
    res.json(requests);
  } catch (err) {
    console.error("Error fetching membership requests:", {
      message: err.message,
      stack: err.stack,
    });
    res
      .status(500)
      .json({ error: "Server error in fetching membership requests" });
  }
});

// Approve/Reject Membership Request
app.patch(
  "/api/membership-requests/:id",
  authenticateToken,
  isSuperAdmin,
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

      const club = await Club.findOne({ name: request.clubName });
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      request.status = status;
      await request.save();

      const targetUser = await User.findById(request.userId);
      if (!targetUser) {
        return res.status(404).json({ error: "Target user not found" });
      }

      if (status === "approved") {
        targetUser.clubName.push(request.clubName);
        targetUser.clubs.push(club._id);
        targetUser.isClubMember = true;
        targetUser.pendingClubs = targetUser.pendingClubs.filter(
          (club) => club !== request.clubName
        );
        club.members.push(targetUser._id);
        club.memberCount = club.members.length;
        await targetUser.save();
        await club.save();

        try {
          await transporter.sendMail({
            from: `"ACEM" <${process.env.EMAIL_USER}>`,
            to: targetUser.email,
            subject: `Membership Request Approved for ${request.clubName}`,
            text: `Congratulations! Your request to join ${request.clubName} has been approved.`,
          });
        } catch (err) {
          console.error("Error sending approval email:", {
            message: err.message,
            stack: err.stack,
          });
        }

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

        try {
          await transporter.sendMail({
            from: `"ACEM" <${process.env.EMAIL_USER}>`,
            to: targetUser.email,
            subject: `Membership Request Rejected for ${request.clubName}`,
            text: `We regret to inform you that your request to join ${request.clubName} has been rejected.`,
          });
        } catch (err) {
          console.error("Error sending rejection email:", {
            message: err.message,
            stack: err.stack,
          });
        }

        await Notification.create({
          userId: targetUser._id,
          message: `Your request to join ${request.clubName} has been rejected.`,
          type: "membership",
        });
      }

      res.json({ message: `Membership request ${status} successfully` });
    } catch (err) {
      console.error("Error updating membership request:", {
        message: err.message,
        stack: err.stack,
      });
      res
        .status(500)
        .json({ error: "Server error in updating membership request" });
    }
  }
);

// Get Single Club
app.get("/api/clubs/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: "Invalid club ID" });
    }

    const club = await Club.findById(req.params.id)
      .populate("superAdmins", "name email")
      .populate("members", "name email")
      .populate("creator", "name email");
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }
    const transformedClub = {
      ...club._doc,
      icon: club.icon ? `http://localhost:5000/${club.icon}` : null,
      banner: club.banner ? `http://localhost:5000/${club.banner}` : null,
      memberCount: club.members.length,
    };
    res.json(transformedClub);
  } catch (err) {
    console.error("Error fetching club:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching club" });
  }
});

// Get Club Members
app.get("/api/clubs/:id/members", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: "Invalid club ID" });
    }

    const club = await Club.findById(req.params.id).populate(
      "members",
      "name email mobile phone rollNo branch semester course specialization isACEMStudent"
    );
    if (!club) {
      return res.status(404).json({ error: "Club not found" });
    }
    res.json(club.members);
  } catch (err) {
    console.error("Error fetching club members:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching club members" });
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
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ error: "Invalid club ID" });
      }

      const club = await Club.findById(req.params.id);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (
        !user.clubName.includes(club.name) ||
        !club.members.includes(user._id)
      ) {
        return res
          .status(400)
          .json({ error: "User is not a member of this club" });
      }

      user.clubName = user.clubName.filter((name) => name !== club.name);
      user.clubs = user.clubs.filter(
        (id) => id.toString() !== club._id.toString()
      );
      user.isClubMember = user.clubName.length > 0;
      club.members = club.members.filter(
        (id) => id.toString() !== user._id.toString()
      );
      club.memberCount = club.members.length;
      await user.save();
      await club.save();

      await Notification.create({
        userId: user._id,
        message: `You have been removed from ${club.name}.`,
        type: "membership",
      });

      res.json({ message: "Member removed successfully" });
    } catch (err) {
      console.error("Error removing club member:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in removing club member" });
    }
  }
);

// Create Event (Creator, Super Admin, or Head Coordinator only)
app.post(
  "/api/events",
  authenticateToken,
  isSuperAdmin,
  upload.single("banner"),
  async (req, res) => {
    const { title, description, date, time, location, club, category } =
      req.body;
    if (
      !title ||
      !description ||
      !date ||
      !time ||
      !location ||
      !club ||
      !category
    ) {
      return res
        .status(400)
        .json({ error: "All fields including category are required" });
    }
    if (!["Seminar", "Competition"].includes(category)) {
      return res.status(400).json({ error: "Invalid event category" });
    }

    try {
      if (!mongoose.isValidObjectId(club)) {
        return res.status(400).json({ error: "Invalid club ID" });
      }

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
        category,
      });
      await event.save();

      clubDoc.eventsCount = await Event.countDocuments({ club: clubDoc._id });
      await clubDoc.save();

      const members = await User.find({ _id: { $in: clubDoc.members } });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `New ${category.toLowerCase()} "${title}" created for ${clubDoc.name
            } on ${date}.`,
          type: "event",
        });
      }

      const transformedEvent = {
        ...event._doc,
        banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
      };
      res.status(201).json(transformedEvent);
    } catch (err) {
      console.error("Event creation error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in event creation" });
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
      .populate("createdBy", "name email")
      .populate("registeredUsers.userId", "name email rollNo isACEMStudent");
    const transformedEvents = events.map((event) => ({
      ...event._doc,
      banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
    }));
    res.json(transformedEvents);
  } catch (err) {
    console.error("Error fetching events:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching events" });
  }
});

// Get Single Event
app.get("/api/events/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }

    const event = await Event.findById(req.params.id)
      .populate("club", "name")
      .populate("createdBy", "name email")
      .populate("registeredUsers.userId", "name email rollNo isACEMStudent");
    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }
    const transformedEvent = {
      ...event._doc,
      banner: event.banner ? `http://localhost:5000/${event.banner}` : null,
    };
    res.json(transformedEvent);
  } catch (err) {
    console.error("Error fetching event:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching event" });
  }
});

// Update Event (Creator, Super Admin, or Head Coordinator only)
app.put(
  "/api/events/:id",
  authenticateToken,
  isSuperAdmin,
  upload.single("banner"),
  async (req, res) => {
    const { id } = req.params;
    const { title, description, date, time, location, club, category } =
      req.body;

    if (
      !title ||
      !description ||
      !date ||
      !time ||
      !location ||
      !club ||
      !category
    ) {
      return res
        .status(400)
        .json({ error: "All fields including category are required" });
    }
    if (!["Seminar", "Competition"].includes(category)) {
      return res.status(400).json({ error: "Invalid event category" });
    }

    try {
      if (!mongoose.isValidObjectId(id)) {
        return res.status(400).json({ error: "Invalid event ID" });
      }
      if (!mongoose.isValidObjectId(club)) {
        return res.status(400).json({ error: "Invalid club ID" });
      }

      const event = await Event.findById(id);
      if (!event) {
        return res.status(404).json({ error: "Event not found" });
      }

      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      if (req.file && event.banner) {
        try {
          await fs.access(event.banner);
          await fs.unlink(event.banner);
        } catch (err) {
          console.warn("Failed to delete old event banner:", {
            message: err.message,
            path: event.banner,
          });
        }
      }

      event.title = title;
      event.description = description;
      event.date = date;
      event.time = time;
      event.location = location;
      event.club = club;
      event.banner = req.file ? req.file.path : event.banner;
      event.category = category;
      await event.save();

      const members = await User.find({ _id: { $in: clubDoc.members } });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `${category} "${title}" for ${clubDoc.name} has been updated.`,
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
      console.error("Event update error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in event update" });
    }
  }
);

// Delete Event (Creator, Super Admin, or Head Coordinator only)
app.delete(
  "/api/events/:id",
  authenticateToken,
  isSuperAdmin,
  async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ error: "Invalid event ID" });
      }

      const event = await Event.findById(req.params.id);
      if (!event) {
        return res.status(404).json({ error: "Event not found" });
      }

      const club = await Club.findById(event.club);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      if (event.banner) {
        try {
          await fs.access(event.banner);
          await fs.unlink(event.banner);
        } catch (err) {
          console.warn("Failed to delete event banner:", {
            message: err.message,
            path: event.banner,
          });
        }
      }

      await event.deleteOne();

      club.eventsCount = await Event.countDocuments({ club: club._id });
      await club.save();

      const members = await User.find({ _id: { $in: club.members } });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `${event.category} "${event.title}" for ${club.name} has been deleted.`,
          type: "event",
        });
      }

      res.json({ message: "Event deleted successfully" });
    } catch (err) {
      console.error("Event deletion error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in event deletion" });
    }
  }
);

// Register for Event
app.post("/api/events/:id/register", authenticateToken, async (req, res) => {
  try {
    const { name, email, rollNo, isACEMStudent } = req.body;
    if (!name || !email || !rollNo || isACEMStudent === undefined) {
      return res
        .status(400)
        .json({ error: "All registration details are required" });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }

    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }

    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }

    const userId = req.user.id;
    if (event.registeredUsers.some((reg) => reg.userId.toString() === userId)) {
      return res
        .status(400)
        .json({ error: "User already registered for this event" });
    }

    event.registeredUsers.push({ userId, name, email, rollNo, isACEMStudent });
    await event.save();

    const club = await Club.findById(event.club);
    await Notification.create({
      userId,
      message: `You have successfully registered for the ${event.category.toLowerCase()} "${event.title
        }" in ${club.name}.`,
      type: "event",
    });

    res.json({ message: "Successfully registered for the event" });
  } catch (err) {
    console.error("Error registering for event:", {
      message: err.message,
      stack: err.stack,
    });
    if (err.code === 11000) {
      return res.status(400).json({ error: "Duplicate registration details" });
    }
    res.status(500).json({ error: "Server error in event registration" });
  }
});

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

      const members = await User.find({ _id: { $in: clubDoc.members } });
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
      console.error("Activity creation error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in activity creation" });
    }
  }
);

// Get Activities
app.get("/api/activities", authenticateToken, async (req, res) => {
  try {
    const { club } = req.query;
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    let query = club ? { club } : {};
    if (!superAdminEmails.includes(user.email)) {
      query.club = { $in: user.headCoordinatorClubs };
    }

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
    console.error("Error fetching activities:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching activities" });
  }
});

// Get Single Activity
app.get("/api/activities/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: "Invalid activity ID" });
    }

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
    console.error("Error fetching activity:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching activity" });
  }
});

// Update Activity (Creator, Super Admin, or Head Coordinator only)
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
      if (
        !user.isAdmin &&
        !user.headCoordinatorClubs.includes(club) &&
        activity.createdBy.toString() !== req.user.id
      ) {
        return res.status(403).json({
          error: "You are not authorized to update this activity",
        });
      }

      if (req.files && req.files.length > 0) {
        for (const oldImage of activity.images) {
          try {
            await fs.access(oldImage);
            await fs.unlink(oldImage);
          } catch (err) {
            console.warn("Failed to delete old activity image:", {
              message: err.message,
              path: oldImage,
            });
          }
        }
        activity.images = req.files.map((file) => file.path);
      }

      activity.title = title;
      activity.date = date;
      activity.description = description;
      activity.club = club;
      await activity.save();

      const members = await User.find({ _id: { $in: clubDoc.members } });
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
      console.error("Activity update error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in activity update" });
    }
  }
);

// Delete Activity (Creator, Super Admin, or Head Coordinator only)
app.delete(
  "/api/activities/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ error: "Invalid activity ID" });
      }

      const activity = await Activity.findById(req.params.id);
      if (!activity) {
        return res.status(404).json({ error: "Activity not found" });
      }

      const club = await Club.findOne({ name: activity.club });
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findById(req.user.id);
      if (
        !user.isAdmin &&
        !user.headCoordinatorClubs.includes(club.name) &&
        activity.createdBy.toString() !== req.user.id
      ) {
        return res.status(403).json({
          error: "You are not authorized to delete this activity",
        });
      }

      for (const image of activity.images) {
        try {
          await fs.access(image);
          await fs.unlink(image);
        } catch (err) {
          console.warn("Failed to delete activity image:", {
            message: err.message,
            path: image,
          });
        }
      }

      await activity.deleteOne();

      const members = await User.find({ _id: { $in: club.members } });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `Activity "${activity.title}" for ${club.name} has been deleted.`,
          type: "activity",
        });
      }

      res.json({ message: "Activity deleted successfully" });
    } catch (err) {
      console.error("Activity deletion error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in activity deletion" });
    }
  }
);

// Get Notifications
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user.id }).sort(
      {
        createdAt: -1,
      }
    );
    res.json(notifications);
  } catch (err) {
    console.error("Error fetching notifications:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching notifications" });
  }
});

// Mark Notification as Read
app.patch(
  "/api/notifications/:id/read",
  authenticateToken,
  async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ error: "Invalid notification ID" });
      }

      const notification = await Notification.findById(req.params.id);
      if (!notification) {
        return res.status(404).json({ error: "Notification not found" });
      }
      if (notification.userId.toString() !== req.user.id) {
        return res
          .status(403)
          .json({ error: "Not authorized to modify this notification" });
      }

      notification.read = true;
      await notification.save();
      res.json({ message: "Notification marked as read" });
    } catch (err) {
      console.error("Error marking notification as read:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in updating notification" });
    }
  }
);

app.get("/api/contact/messages", authenticateToken, async (req, res) => {
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
      const clubs = await Club.find({
        $or: [
          { superAdmins: user._id },
          { name: { $in: user.headCoordinatorClubs } },
        ],
      }).distinct("name");
      query.club = { $in: clubs };
    }

    const messages = await ContactMessage.find(query).sort({ createdAt: -1 });
    res.json(messages);
  } catch (err) {
    console.error("Error fetching contact messages:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Reply to Contact Message
app.post(
  "/api/contact/messages/:id/reply",
  authenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { reply } = req.body;
    if (!reply) {
      return res.status(400).json({ error: "Reply message is required" });
    }

    try {
      const message = await ContactMessage.findById(id);
      if (!message) {
        return res.status(404).json({ error: "Contact message not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const club = await Club.findOne({ name: message.club });
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      if (
        !superAdminEmails.includes(user.email) &&
        !club.superAdmins.some((id) => id.toString() === user._id.toString()) &&
        !user.headCoordinatorClubs.includes(message.club)
      ) {
        return res.status(403).json({ error: "Access denied" });
      }

      message.replies.push({
        reply,
        repliedBy: user._id,
        repliedAt: new Date(),
      });
      message.status = "replied";
      await message.save();

      await transporter.sendMail({
        from: `"ACEM" <${process.env.EMAIL_USER}>`,
        to: message.email,
        subject: `Reply to Your Message for ${message.club}`,
        text: `Dear ${message.name},\n\nWe have responded to your message:\n\nOriginal Message: ${message.message}\n\nReply: ${reply}\n\nBest regards,\n${club.name} Team`,
      });

      await Notification.create({
        userId: user._id,
        message: `You replied to a contact message for ${message.club}.`,
        type: "general",
      });

      res.json({ message: "Reply sent successfully" });
    } catch (err) {
      console.error("Error replying to contact message:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Update Contact Message Status
app.patch(
  "/api/contact/messages/:id/status",
  authenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { status, priority, isStarred } = req.body;
    if (!status && !priority && isStarred === undefined) {
      return res
        .status(400)
        .json({ error: "At least one field is required to update" });
    }

    try {
      const message = await ContactMessage.findById(id);
      if (!message) {
        return res.status(404).json({ error: "Contact message not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const club = await Club.findOne({ name: message.club });
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
        ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
        : [];
      if (
        !superAdminEmails.includes(user.email) &&
        !club.superAdmins.some((id) => id.toString() === user._id.toString()) &&
        !user.headCoordinatorClubs.includes(message.club)
      ) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (status && ["new", "read", "replied", "archived"].includes(status)) {
        message.status = status;
      }
      if (priority && ["low", "medium", "high"].includes(priority)) {
        message.priority = priority;
      }
      if (isStarred !== undefined) {
        message.isStarred = isStarred;
      }
      await message.save();

      res.json({ message: "Contact message updated successfully" });
    } catch (err) {
      console.error("Error updating contact message:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Create Attendance for Event (Head Coordinator or Admin only)
app.post(
  "/api/attendance",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { club, event, date, attendance } = req.body;
    if (!club || !event || !date || !Array.isArray(attendance)) {
      return res
        .status(400)
        .json({
          error: "Club, event, date, and attendance array are required",
        });
    }

    try {
      if (!mongoose.isValidObjectId(club) || !mongoose.isValidObjectId(event)) {
        return res.status(400).json({ error: "Invalid club or event ID" });
      }

      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      const eventDoc = await Event.findById(event);
      if (!eventDoc) {
        return res.status(404).json({ error: "Event not found" });
      }

      if (eventDoc.club.toString() !== club) {
        return res
          .status(400)
          .json({ error: "Event does not belong to the specified club" });
      }

      const validAttendance = attendance.filter(
        (entry) =>
          mongoose.isValidObjectId(entry.userId) &&
          ["present", "absent"].includes(entry.status)
      );
      if (validAttendance.length === 0) {
        return res
          .status(400)
          .json({ error: "No valid attendance entries provided" });
      }

      const userIds = validAttendance.map((entry) => entry.userId);
      const users = await User.find({ _id: { $in: userIds } });
      if (users.length !== userIds.length) {
        return res
          .status(400)
          .json({ error: "One or more user IDs are invalid" });
      }

      if (!users.every((user) => clubDoc.members.includes(user._id))) {
        return res
          .status(400)
          .json({ error: "One or more users are not members of the club" });
      }

      const presentCount = validAttendance.filter(
        (entry) => entry.status === "present"
      ).length;
      const absentCount = validAttendance.length - presentCount;
      const attendanceRate = (presentCount / validAttendance.length) * 100;
      const totalPoints = presentCount * 5; // 5 points per present student

      const attendanceRecord = new Attendance({
        club,
        event,
        date: new Date(date),
        attendance: validAttendance,
        stats: {
          presentCount,
          absentCount,
          totalMarked: validAttendance.length,
          attendanceRate,
          totalPoints,
        },
        createdBy: req.user.id,
      });
      await attendanceRecord.save();

      for (const entry of validAttendance) {
        await Notification.create({
          userId: entry.userId,
          message: `Your attendance for "${eventDoc.title}" on ${date} has been marked as ${entry.status} (${entry.status === "present" ? "5 points" : "0 points"}).`,
          type: "attendance",
        });
      }

      res.status(201).json({
        message: "Attendance recorded successfully",
        data: attendanceRecord.toObject(),
      });
    } catch (err) {
      console.error("Attendance creation error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in attendance creation" });
    }
  }
);

// Get Attendance for Event
app.get("/api/attendance", authenticateToken, async (req, res) => {
  try {
    const { club, event, startDate, endDate } = req.query;
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let query = {};
    if (club) {
      if (!mongoose.isValidObjectId(club)) {
        return res.status(400).json({ error: "Invalid club ID" });
      }
      query.club = club;
    }
    if (event) {
      if (!mongoose.isValidObjectId(event)) {
        return res.status(400).json({ error: "Invalid event ID" });
      }
      query.event = event;
    }
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    if (!superAdminEmails.includes(user.email)) {
      const clubs = await Club.find({
        $or: [
          { creator: user._id },
          { superAdmins: user._id },
          { name: { $in: user.headCoordinatorClubs } },
        ],
      }).distinct("_id");
      query.club = { $in: clubs };
    }

    const attendanceRecords = await Attendance.find(query)
      .populate("club", "name")
      .populate("event", "title")
      .populate("attendance.userId", "name email rollNo");
    res.json(attendanceRecords);
  } catch (err) {
    console.error("Error fetching attendance:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching attendance" });
  }
});

// Update Attendance for Event (Head Coordinator or Admin only)
app.put(
  "/api/attendance/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { id } = req.params;
    const { attendance } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: "Invalid attendance ID" });
    }
    if (!Array.isArray(attendance)) {
      return res.status(400).json({ error: "Attendance array is required" });
    }

    try {
      const attendanceRecord = await Attendance.findById(id);
      if (!attendanceRecord) {
        return res.status(404).json({ error: "Attendance record not found" });
      }

      const club = await Club.findById(attendanceRecord.club);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const event = await Event.findById(attendanceRecord.event);
      if (!event) {
        return res.status(404).json({ error: "Event not found" });
      }

      const validAttendance = attendance.filter(
        (entry) =>
          mongoose.isValidObjectId(entry.userId) &&
          ["present", "absent"].includes(entry.status)
      );
      if (validAttendance.length === 0) {
        return res
          .status(400)
          .json({ error: "No valid attendance entries provided" });
      }

      const userIds = validAttendance.map((entry) => entry.userId);
      const users = await User.find({ _id: { $in: userIds } });
      if (users.length !== userIds.length) {
        return res
          .status(400)
          .json({ error: "One or more user IDs are invalid" });
      }

      if (!users.every((user) => club.members.includes(user._id))) {
        return res
          .status(400)
          .json({ error: "One or more users are not members of the club" });
      }

      const presentCount = validAttendance.filter(
        (entry) => entry.status === "present"
      ).length;
      const absentCount = validAttendance.length - presentCount;
      const attendanceRate = (presentCount / validAttendance.length) * 100;
      const totalPoints = presentCount * 5; // 5 points per present student

      attendanceRecord.attendance = validAttendance;
      attendanceRecord.stats = {
        presentCount,
        absentCount,
        totalMarked: validAttendance.length,
        attendanceRate,
        totalPoints,
      };
      await attendanceRecord.save();

      for (const entry of validAttendance) {
        await Notification.create({
          userId: entry.userId,
          message: `Your attendance for "${event.title}" on ${attendanceRecord.date.toISOString().split("T")[0]
            } has been updated to ${entry.status} (${entry.status === "present" ? "5 points" : "0 points"}).`,
          type: "attendance",
        });
      }

      res.json({
        message: "Attendance updated successfully",
        attendance: attendanceRecord,
      });
    } catch (err) {
      console.error("Attendance update error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in attendance update" });
    }
  }
);

// Get Present Students for Attendance or Practice Attendance
app.get(
  "/api/attendance/:id/present",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { id } = req.params;
    try {
      if (!mongoose.isValidObjectId(id)) {
        return res.status(400).json({ error: "Invalid attendance ID" });
      }

      let attendanceRecord = await Attendance.findById(id)
        .populate("attendance.userId", "name email rollNo")
        .populate("club", "name")
        .populate("event", "title");

      let type = "event";
      let pointsPerPresent = 5;
      if (!attendanceRecord) {
        attendanceRecord = await PracticeAttendance.findById(id)
          .populate("attendance.userId", "name email rollNo")
          .populate("club", "name");
        type = "practice";
        pointsPerPresent = 3;
        if (!attendanceRecord) {
          return res.status(404).json({ error: "Attendance record not found" });
        }
        Rancho
      }

      const presentStudents = attendanceRecord.attendance
        .filter((entry) => entry.status === "present")
        .map((entry) => ({
          name: entry.userId.name,
          email: entry.userId.email,
          rollNo: entry.userId.rollNo,
          points: entry.status === "present" ? pointsPerPresent : 0,
        }));

      res.json({
        type,
        club: attendanceRecord.club.name,
        title:
          type === "event"
            ? attendanceRecord.event.title
            : attendanceRecord.title,
        date: attendanceRecord.date,
        roomNo: type === "practice" ? attendanceRecord.roomNo : undefined,
        presentStudents,
        totalPoints: attendanceRecord.stats.totalPoints,
      });
    } catch (err) {
      console.error("Error fetching present students:", {
        message: err.message,
        stack: err.stack,
        attendanceId: id,
        userId: req.user.id,
      });
      res
        .status(500)
        .json({ error: "Server error in fetching present students" });
    }
  }
);

// Add Student to Club (Head Coordinator or Admin only)
app.post(
  "/api/clubs/:id/add-student",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { id } = req.params;
    const { email, name, rollNo, isACEMStudent } = req.body;

    if (!email || !name || isACEMStudent === undefined) {
      return res
        .status(400)
        .json({ error: "Email, name, and ACEM student status are required" });
    }

    try {
      if (!mongoose.isValidObjectId(id)) {
        console.error("Invalid club ID:", id);
        return res.status(400).json({ error: "Invalid club ID" });
      }

      const club = await Club.findById(id);
      if (!club) {
        console.error("Club not found for ID:", id);
        return res.status(404).json({ error: "Club not found" });
      }

      // Check if creator is valid
      if (!club.creator || !mongoose.isValidObjectId(club.creator)) {
        // Set a fallback creator (e.g., the current user or a super admin)
        club.creator = req.user.id; // Use the current authenticated user
        console.warn(
          `Club ${club._id} had missing/invalid creator; set to ${req.user.id}`
        );
      }

      let user = await User.findOne({ email });
      if (user) {
        if (club.members.includes(user._id)) {
          return res
            .status(400)
            .json({ error: "User is already a member of this club" });
        }
      } else {
        user = new User({
          name,
          email,
          password: await bcrypt.hash("defaultPassword123", 10),
          rollNo,
          isACEMStudent,
          isClubMember: true,
          clubName: [club.name],
          clubs: [club._id],
        });
        await user.save();
      }

      club.members.push(user._id);
      club.memberCount = club.members.length;
      await club.save();

      if (!user.clubs.includes(club._id)) {
        user.clubs.push(club._id);
        user.clubName.push(club.name);
        user.isClubMember = true;
        await user.save();
      }

      await Notification.create({
        userId: user._id,
        message: `You have been added to ${club.name} as a member.`,
        type: "membership",
      });

      try {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: user.email,
          subject: `Added to ${club.name}`,
          text: `You have been added to ${club.name
            } as a member. Please log in to the ACEM platform to view details${user.password
              ? ". Your temporary password is 'defaultPassword123'. Please reset it upon login."
              : "."
            }`,
        });
      } catch (emailErr) {
        console.error("Error sending email to new member:", {
          message: emailErr.message,
          stack: emailErr.stack,
        });
      }

      res.status(201).json({
        message: "Student added to club successfully",
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          rollNo: user.rollNo,
          isACEMStudent: user.isACEMStudent,
        },
      });
    } catch (err) {
      console.error("Error adding student to club:", {
        message: err.message,
        stack: err.stack,
        clubId: id,
        userId: req.user.id,
        requestBody: req.body,
      });
      if (err.code === 11000) {
        return res
          .status(400)
          .json({ error: "Email or roll number already exists" });
      }
      if (err.name === "ValidationError") {
        return res
          .status(400)
          .json({ error: `Validation error: ${err.message}` });
      }
      res.status(500).json({ error: "Server error in adding student to club" });
    }
  }
);

// Generate DOCX Report for Specific Attendance or Practice Attendance
app.get(
  "/api/practice-attendance/:id/report",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { id } = req.params;
    try {
      if (!mongoose.isValidObjectId(id)) {
        return res
          .status(400)
          .json({ error: "Invalid practice attendance ID" });
      }

      const attendanceRecord = await PracticeAttendance.findById(id)
        .populate("attendance.userId", "name email rollNo")
        .populate("club", "name");

      if (!attendanceRecord) {
        return res
          .status(404)
          .json({ error: "Practice attendance record not found" });
      }

      const clubName = attendanceRecord.club?.name || "Unknown Club";
      const title = attendanceRecord.title || "Untitled Practice";
      const date = attendanceRecord.date
        ? attendanceRecord.date.toLocaleDateString()
        : "N/A";
      const roomNo = attendanceRecord.roomNo || "N/A";

      const doc = new Document({
        sections: [
          {
            properties: {},
            children: [
              new Paragraph({
                text: `Attendance Report for ${clubName}`,
                heading: HeadingLevel.HEADING_1,
                alignment: "center",
              }),
              new Paragraph({
                text: `Generated on: ${new Date().toLocaleDateString()}`,
                spacing: { after: 200 },
              }),
              new Paragraph({
                text: `Practice: ${title}`,
                heading: HeadingLevel.HEADING_2,
                spacing: { before: 400, after: 200 },
              }),
              new Paragraph({
                text: `Date: ${date} | Room: ${roomNo}`,
                spacing: { after: 200 },
              }),
              new Table({
                width: { size: 100, type: WidthType.PERCENTAGE },
                rows: [
                  new TableRow({
                    children: [
                      new TableCell({
                        children: [new Paragraph("Name")],
                        width: { size: 20, type: WidthType.PERCENTAGE },
                      }),
                      new TableCell({
                        children: [new Paragraph("Email")],
                        width: { size: 25, type: WidthType.PERCENTAGE },
                      }),
                      new TableCell({
                        children: [new Paragraph("Roll No")],
                        width: { size: 20, type: WidthType.PERCENTAGE },
                      }),
                      new TableCell({
                        children: [new Paragraph("Status")],
                        width: { size: 20, type: WidthType.PERCENTAGE },
                      }),
                      new TableCell({
                        children: [new Paragraph("Points")],
                        width: { size: 15, type: WidthType.PERCENTAGE },
                      }),
                    ],
                  }),
                  ...(attendanceRecord.attendance?.map(
                    (entry) =>
                      new TableRow({
                        children: [
                          new TableCell({
                            children: [
                              new Paragraph(entry.userId?.name || "N/A"),
                            ],
                          }),
                          new TableCell({
                            children: [
                              new Paragraph(entry.userId?.email || "N/A"),
                            ],
                          }),
                          new TableCell({
                            children: [
                              new Paragraph(entry.userId?.rollNo || "N/A"),
                            ],
                          }),
                          new TableCell({
                            children: [new Paragraph(entry.status || "N/A")],
                          }),
                          new TableCell({
                            children: [
                              new Paragraph(
                                entry.status === "present" ? "3" : "0"
                              ),
                            ],
                          }),
                        ],
                      })
                  ) || []),
                ],
              }),
              new Paragraph({
                text: `Stats: Present: ${attendanceRecord.stats?.presentCount || 0
                  }, Absent: ${attendanceRecord.stats?.absentCount || 0
                  }, Rate: ${attendanceRecord.stats?.attendanceRate?.toFixed(
                    2
                  ) || 0}%, Total Points: ${attendanceRecord.stats?.totalPoints || 0}`,
                spacing: { after: 200 },
              }),
            ],
          },
        ],
      });

      const buffer = await Packer.toBuffer(doc);
      const safeTitle = title.replace(/[^a-zA-Z0-9]/g, "_");
      const fileName = `Practice_Attendance_${clubName}_${safeTitle}_${date.replace(
        /[^a-zA-Z0-9]/g,
        "_"
      )}.docx`;

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      try {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: user.email,
          subject: `Practice Attendance Report for ${clubName} - ${title}`,
          text: `Attached is the practice attendance report for ${title} on ${date}.`,
          attachments: [
            {
              filename: fileName,
              content: buffer,
              contentType:
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            },
          ],
        });
      } catch (emailErr) {
        console.error("Error sending practice report email:", {
          message: emailErr.message,
          stack: emailErr.stack,
        });
      }

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${fileName}"`
      );
      res.send(buffer);
    } catch (err) {
      console.error("Report generation error for practice attendance:", {
        message: err.message,
        stack: err.stack,
        attendanceId: id,
        userId: req.user.id,
      });
      res.status(500).json({ error: "Server error in report generation" });
    }
  }
);

// Get User Attendance History
app.get("/api/attendance/user", authenticateToken, async (req, res) => {
  try {
    const { club, startDate, endDate } = req.query;
    let query = { "attendance.userId": req.user.id };

    if (club) {
      if (!mongoose.isValidObjectId(club)) {
        return res.status(400).json({ error: "Invalid club ID" });
      }
      query.club = club;
    }
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    const attendanceRecords = await Attendance.find(query)
      .populate("club", "name")
      .populate("event", "title")
      .select("event date attendance stats");

    const userAttendance = attendanceRecords.map((record) => {
      const userEntry = record.attendance.find(
        (entry) => entry.userId.toString() === req.user.id
      );
      return {
        event: record.event,
        club: record.club,
        date: record.date,
        status: userEntry ? userEntry.status : "unknown",
        points: userEntry && userEntry.status === "present" ? 5 : 0, // 5 points for present
        stats: {
          ...record.stats,
          totalPoints: record.stats.totalPoints, // Include total points
        },
      };
    });

    res.json(userAttendance);
  } catch (err) {
    console.error("Error fetching user attendance:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in fetching user attendance" });
  }
});

// Create Practice Attendance (Head Coordinator or Admin only)
app.post(
  "/api/practice-attendance",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { club, title, date, roomNo, attendance } = req.body;
    if (!club || !title || !date || !roomNo || !Array.isArray(attendance)) {
      return res
        .status(400)
        .json({
          error:
            "Club, title, date, room number, and attendance array are required",
        });
    }

    if (!mongoose.isValidObjectId(club)) {
      return res.status(400).json({ error: "Invalid club ID" });
    }

    if (!isValidDate(date)) {
      return res.status(400).json({ error: "Invalid date format" });
    }

    try {
      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user.isAdmin && !user.headCoordinatorClubs.includes(clubDoc.name)) {
        return res.status(403).json({
          error: "You are not authorized to create attendance for this club",
        });
      }

      const existingRecord = await PracticeAttendance.findOne({
        club,
        title,
        date: new Date(date),
        roomNo,
      });
      if (existingRecord) {
        return res
          .status(400)
          .json({
            error:
              "Attendance record already exists for this club, title, date, and room",
          });
      }

      const validAttendance = attendance.filter(
        (entry) =>
          mongoose.isValidObjectId(entry.userId) &&
          ["present", "absent"].includes(entry.status)
      );
      if (validAttendance.length === 0) {
        return res
          .status(400)
          .json({ error: "No valid attendance entries provided" });
      }

      const userIds = validAttendance.map((entry) => entry.userId);
      const users = await User.find({ _id: { $in: userIds } });
      if (users.length !== userIds.length) {
        return res
          .status(400)
          .json({ error: "One or more user IDs are invalid" });
      }

      if (!users.every((user) => clubDoc.members.includes(user._id))) {
        return res
          .status(400)
          .json({ error: "One or more users are not members of the club" });
      }

      const presentCount = validAttendance.filter(
        (entry) => entry.status === "present"
      ).length;
      const absentCount = validAttendance.length - presentCount;
      const attendanceRate =
        validAttendance.length > 0
          ? (presentCount / validAttendance.length) * 100
          : 0;
      const totalPoints = presentCount * 3; // 3 points per present student

      const practiceAttendance = new PracticeAttendance({
        club,
        title,
        date: new Date(date),
        roomNo,
        attendance: validAttendance,
        stats: {
          presentCount,
          absentCount,
          totalMarked: validAttendance.length,
          attendanceRate,
          totalPoints,
        },
        createdBy: req.user.id,
      });
      await practiceAttendance.save();

      const formattedDate = new Date(date).toLocaleDateString();
      for (const entry of validAttendance) {
        await Notification.create({
          userId: entry.userId,
          message: `Your attendance for "${title}" on ${formattedDate} in room ${roomNo} has been marked as ${entry.status} (${entry.status === "present" ? "3 points" : "0 points"}).`,
          type: "attendance",
        });
      }

      res.status(201).json({
        message: "Practice attendance recorded successfully",
        attendance: practiceAttendance,
      });
    } catch (err) {
      console.error("Practice attendance creation error:", {
        message: err.message,
        stack: err.stack,
      });
      if (err.code === 11000) {
        return res
          .status(400)
          .json({
            error:
              "Attendance record already exists for this club, title, date, and room",
          });
      }
      res
        .status(500)
        .json({ error: "Server error in practice attendance creation" });
    }
  }
);

// Get Practice Attendance
app.get("/api/practice-attendance", authenticateToken, async (req, res) => {
  try {
    const { club, startDate, endDate } = req.query;
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let query = {};
    if (club) {
      if (!mongoose.isValidObjectId(club)) {
        return res.status(400).json({ error: "Invalid club ID" });
      }
      query.club = club;
    }
    if (startDate || endDate) {
      if (startDate && !isValidDate(startDate)) {
        return res.status(400).json({ error: "Invalid start date format" });
      }
      if (endDate && !isValidDate(endDate)) {
        return res.status(400).json({ error: "Invalid end date format" });
      }
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    if (!superAdminEmails.includes(user.email)) {
      const clubs = await Club.find({
        $or: [
          { creator: user._id },
          { superAdmins: user._id },
          { name: { $in: user.headCoordinatorClubs } },
        ],
      }).distinct("_id");
      query.club = { $in: clubs };
    }

    const practiceAttendanceRecords = await PracticeAttendance.find(query)
      .populate("club", "name")
      .populate("attendance.userId", "name email rollNo");
    res.json(practiceAttendanceRecords);
  } catch (err) {
    console.error("Error fetching practice attendance:", {
      message: err.message,
      stack: err.stack,
    });
    res
      .status(500)
      .json({ error: "Server error in fetching practice attendance" });
  }
});

// Update Delete Practice Attendance
app.delete(
  "/api/practice-attendance/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ error: "Invalid attendance ID" });
      }

      const practiceAttendance = await PracticeAttendance.findById(
        req.params.id
      );
      if (!practiceAttendance) {
        return res
          .status(404)
          .json({ error: "Practice attendance record not found" });
      }

      const club = await Club.findById(practiceAttendance.club);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user.isAdmin && !user.headCoordinatorClubs.includes(club.name)) {
        return res.status(403).json({
          error: "You are not authorized to delete attendance for this club",
        });
      }

      const formattedDate = new Date(
        practiceAttendance.date
      ).toLocaleDateString();
      await practiceAttendance.deleteOne();

      const members = await User.find({ _id: { $in: club.members } });
      for (const member of members) {
        await Notification.create({
          userId: member._id,
          message: `Practice attendance record "${practiceAttendance.title}" for ${club.name} on ${formattedDate} has been deleted.`,
          type: "attendance",
        });
      }

      res.json({ message: "Practice attendance deleted successfully" });
    } catch (err) {
      console.error("Practice attendance deletion error:", {
        message: err.message,
        stack: err.stack,
      });
      res
        .status(500)
        .json({ error: "Server error in practice attendance deletion" });
    }
  }
);

// Update Get User Practice Attendance History
app.get(
  "/api/practice-attendance/user",
  authenticateToken,
  async (req, res) => {
    try {
      const { club, startDate, endDate } = req.query;
      let query = { "attendance.userId": req.user.id };

      if (club) {
        if (!mongoose.isValidObjectId(club)) {
          return res.status(400).json({ error: "Invalid club ID" });
        }
        query.club = club;
      }
      if (startDate || endDate) {
        if (startDate && !isValidDate(startDate)) {
          return res.status(400).json({ error: "Invalid start date format" });
        }
        if (endDate && !isValidDate(endDate)) {
          return res.status(400).json({ error: "Invalid end date format" });
        }
        query.date = {};
        if (startDate) query.date.$gte = new Date(startDate);
        if (endDate) query.date.$lte = new Date(endDate);
      }

      const practiceAttendanceRecords = await PracticeAttendance.find(query)
        .populate("club", "name")
        .select("title date roomNo attendance stats");

      const userAttendance = practiceAttendanceRecords.map((record) => {
        const userEntry = record.attendance.find(
          (entry) => entry.userId.toString() === req.user.id
        );
        return {
          title: record.title,
          club: record.club,
          date: record.date,
          roomNo: record.roomNo,
          status: userEntry ? userEntry.status : "unknown",
          points: userEntry && userEntry.status === "present" ? 3 : 0, // 3 points for present
          stats: {
            ...record.stats,
            totalPoints: record.stats.totalPoints, // Include total points
          },
        };
      });

      res.json(userAttendance);
    } catch (err) {
      console.error("Error fetching user practice attendance:", {
        message: err.message,
        stack: err.stack,
      });
      res
        .status(500)
        .json({ error: "Server error in fetching user practice attendance" });
    }
  }
);

// Update Practice Attendance (Head Coordinator or Admin only)
app.put(
  "/api/practice-attendance/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { id } = req.params;
    const { title, date, roomNo, attendance } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: "Invalid attendance ID" });
    }
    if (!title || !date || !roomNo || !Array.isArray(attendance)) {
      return res
        .status(400)
        .json({
          error: "Title, date, room number, and attendance array are required",
        });
    }
    if (!isValidDate(date)) {
      return res.status(400).json({ error: "Invalid date format" });
    }

    try {
      const practiceAttendance = await PracticeAttendance.findById(id);
      if (!practiceAttendance) {
        return res
          .status(404)
          .json({ error: "Practice attendance record not found" });
      }

      const club = await Club.findById(practiceAttendance.club);
      if (!club) {
        return res.status(404).json({ error: "Club not found" });
      }

      const user = await User.findById(req.user.id);
      if (!user.isAdmin && !user.headCoordinatorClubs.includes(club.name)) {
        return res.status(403).json({
          error: "You are not authorized to update attendance for this club",
        });
      }

      const existingRecord = await PracticeAttendance.findOne({
        club: practiceAttendance.club,
        title,
        date: new Date(date),
        roomNo,
        _id: { $ne: id },
      });
      if (existingRecord) {
        return res
          .status(400)
          .json({
            error:
              "Another attendance record already exists for this club, title, date, and room",
          });
      }

      const validAttendance = attendance.filter(
        (entry) =>
          mongoose.isValidObjectId(entry.userId) &&
          ["present", "absent"].includes(entry.status)
      );
      if (validAttendance.length === 0) {
        return res
          .status(400)
          .json({ error: "No valid attendance entries provided" });
      }

      const userIds = validAttendance.map((entry) => entry.userId);
      const users = await User.find({ _id: { $in: userIds } });
      if (users.length !== userIds.length) {
        return res
          .status(400)
          .json({ error: "One or more user IDs are invalid" });
      }

      if (!users.every((user) => club.members.includes(user._id))) {
        return res
          .status(400)
          .json({ error: "One or more users are not members of the club" });
      }

      const presentCount = validAttendance.filter(
        (entry) => entry.status === "present"
      ).length;
      const absentCount = validAttendance.length - presentCount;
      const attendanceRate =
        validAttendance.length > 0
          ? (presentCount / validAttendance.length) * 100
          : 0;
      const totalPoints = presentCount * 3; // 3 points per present student

      practiceAttendance.title = title;
      practiceAttendance.date = new Date(date);
      practiceAttendance.roomNo = roomNo;
      practiceAttendance.attendance = validAttendance;
      practiceAttendance.stats = {
        presentCount,
        absentCount,
        totalMarked: validAttendance.length,
        attendanceRate,
        totalPoints,
      };
      await practiceAttendance.save();

      const formattedDate = new Date(date).toLocaleDateString();
      for (const entry of validAttendance) {
        await Notification.create({
          userId: entry.userId,
          message: `Your attendance for "${title}" on ${formattedDate} in room ${roomNo} has been updated to ${entry.status} (${entry.status === "present" ? "3 points" : "0 points"}).`,
          type: "attendance",
        });
      }

      res.json({
        message: "Practice attendance updated successfully",
        attendance: practiceAttendance,
      });
    } catch (err) {
      console.error("Practice attendance update error:", {
        message: err.message,
        stack: err.stack,
      });
      if (err.code === 11000) {
        return res
          .status(400)
          .json({
            error:
              "Another attendance record already exists for this club, title, date, and room",
          });
      }
      res
        .status(500)
        .json({ error: "Server error in practice attendance update" });
    }
  }
);

// Delete Practice Attendance (Head Coordinator or Admin only)

// Generate Attendance Report (Head Coordinator or Admin only)
app.get(
  "/api/attendance/report",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { club, startDate, endDate } = req.query;
    if (!club) {
      return res.status(400).json({ error: "Club ID is required" });
    }
    if (!mongoose.isValidObjectId(club)) {
      return res.status(400).json({ error: "Invalid club ID" });
    }

    try {
      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      let query = { club };
      if (startDate || endDate) {
        query.date = {};
        if (startDate) query.date.$gte = new Date(startDate);
        if (endDate) query.date.$lte = new Date(endDate);
      }

      const eventAttendance = await Attendance.find(query)
        .populate("event", "title")
        .populate("attendance.userId", "name email rollNo");
      const practiceAttendance = await PracticeAttendance.find(query).populate(
        "attendance.userId",
        "name email rollNo"
      );

      const doc = new Document({
        sections: [
          {
            properties: {},
            children: [
              new Paragraph({
                text: `Attendance Report for ${clubDoc.name}`,
                heading: HeadingLevel.HEADING_1,
                alignment: "center",
              }),
              new Paragraph({
                text: `Generated on: ${new Date().toLocaleDateString()}`,
                spacing: { after: 200 },
              }),
              ...(startDate || endDate
                ? [
                  new Paragraph({
                    text: `Date Range: ${startDate || "N/A"} to ${endDate || "N/A"
                      }`,
                    spacing: { after: 200 },
                  }),
                ]
                : []),
              new Paragraph({
                text: "Event Attendance",
                heading: HeadingLevel.HEADING_2,
                spacing: { before: 400, after: 200 },
              }),
              ...eventAttendance.flatMap((record) => [
                new Paragraph({
                  text: `Event: ${record.event.title
                    } | Date: ${record.date.toLocaleDateString()}`,
                  heading: HeadingLevel.HEADING_3,
                }),
                new Table({
                  width: { size: 100, type: WidthType.PERCENTAGE },
                  rows: [
                    new TableRow({
                      children: [
                        new TableCell({
                          children: [new Paragraph("Name")],
                          width: { size: 20, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Email")],
                          width: { size: 25, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Roll No")],
                          width: { size: 20, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Status")],
                          width: { size: 20, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Points")],
                          width: { size: 15, type: WidthType.PERCENTAGE },
                        }),
                      ],
                    }),
                    ...record.attendance.map(
                      (entry) =>
                        new TableRow({
                          children: [
                            new TableCell({
                              children: [
                                new Paragraph(entry.userId.name || "N/A"),
                              ],
                            }),
                            new TableCell({
                              children: [
                                new Paragraph(entry.userId.email || "N/A"),
                              ],
                            }),
                            new TableCell({
                              children: [
                                new Paragraph(entry.userId.rollNo || "N/A"),
                              ],
                            }),
                            new TableCell({
                              children: [new Paragraph(entry.status)],
                            }),
                            new TableCell({
                              children: [
                                new Paragraph(
                                  entry.status === "present" ? "5" : "0"
                                ),
                              ],
                            }),
                          ],
                        })
                    ),
                  ],
                }),
                new Paragraph({
                  text: `Stats: Present: ${record.stats.presentCount
                    }, Absent: ${record.stats.absentCount
                    }, Rate: ${record.stats.attendanceRate.toFixed(
                      2
                    )}%, Total Points: ${record.stats.totalPoints}`,
                  spacing: { after: 200 },
                }),
              ]),
              new Paragraph({
                text: "Practice Attendance",
                heading: HeadingLevel.HEADING_2,
                spacing: { before: 400, after: 200 },
              }),
              ...practiceAttendance.flatMap((record) => [
                new Paragraph({
                  text: `Practice: ${record.title} | Date: ${record.date.toLocaleDateString()} | Room: ${record.roomNo}`,
                  heading: HeadingLevel.HEADING_3,
                }),
                new Table({
                  width: { size: 100, type: WidthType.PERCENTAGE },
                  rows: [
                    new TableRow({
                      children: [
                        new TableCell({
                          children: [new Paragraph("Name")],
                          width: { size: 20, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Email")],
                          width: { size: 25, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Roll No")],
                          width: { size: 20, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Status")],
                          width: { size: 20, type: WidthType.PERCENTAGE },
                        }),
                        new TableCell({
                          children: [new Paragraph("Points")],
                          width: { size: 15, type: WidthType.PERCENTAGE },
                        }),
                      ],
                    }),
                    ...record.attendance.map(
                      (entry) =>
                        new TableRow({
                          children: [
                            new TableCell({
                              children: [
                                new Paragraph(entry.userId.name || "N/A"),
                              ],
                            }),
                            new TableCell({
                              children: [
                                new Paragraph(entry.userId.email || "N/A"),
                              ],
                            }),
                            new TableCell({
                              children: [
                                new Paragraph(entry.userId.rollNo || "N/A"),
                              ],
                            }),
                            new TableCell({
                              children: [new Paragraph(entry.status)],
                            }),
                            new TableCell({
                              children: [
                                new Paragraph(
                                  entry.status === "present" ? "3" : "0"
                                ),
                              ],
                            }),
                          ],
                        })
                    ),
                  ],
                }),
                new Paragraph({
                  text: `Stats: Present: ${record.stats.presentCount
                    }, Absent: ${record.stats.absentCount
                    }, Rate: ${record.stats.attendanceRate.toFixed(
                      2
                    )}%, Total Points: ${record.stats.totalPoints}`,
                  spacing: { after: 200 },
                }),
              ]),
            ],
          },
        ],
      });

      const buffer = await Packer.toBuffer(doc);
      const fileName = `Attendance_Report_${clubDoc.name}_${Date.now()}.docx`;
      const filePath = path.join(__dirname, "Uploads", fileName);
      await fs.writeFile(filePath, buffer);

      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${fileName}"`
      );
      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
      );
      res.sendFile(filePath, async (err) => {
        if (err) {
          console.error("Error sending report:", {
            message: err.message,
            stack: err.stack,
          });
          return res.status(500).json({ error: "Error sending report" });
        }
        try {
          await fs.unlink(filePath);
        } catch (unlinkErr) {
          console.warn("Failed to delete report file:", {
            message: unlinkErr.message,
            path: filePath,
          });
        }
      });
    } catch (err) {
      console.error("Report generation error:", {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ error: "Server error in report generation" });
    }
  }
);

// Error Handling Middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `File upload error: ${err.message}` });
  }
  console.error("Unexpected error:", {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    userId: req.user?.id,
  });
  res.status(500).json({ error: "Internal server error" });
});

// Global Points Table Endpoint
app.get('/api/points-table', authenticateToken, async (req, res) => {
  try {
    // Aggregate event attendance points (5 points per present)
    const eventPoints = await Attendance.aggregate([
      { $unwind: '$attendance' },
      { $match: { 'attendance.status': 'present' } },
      {
        $group: {
          _id: '$attendance.userId',
          eventPoints: { $sum: 5 },
        },
      },
      { $project: { _id: 1, eventPoints: 1 } },
    ]);

    // Aggregate practice attendance points (3 points per present)
    const practicePoints = await PracticeAttendance.aggregate([
      { $unwind: '$attendance' },
      { $match: { 'attendance.status': 'present' } },
      {
        $group: {
          _id: '$attendance.userId',
          practicePoints: { $sum: 3 },
        },
      },
      { $project: { _id: 1, practicePoints: 1 } },
    ]);

    // Fetch all users with relevant fields, including clubName and avatar
    const users = await User.find({}, 'name email rollNo clubName avatar').lean();

    // Combine points and user details
    const pointsTable = users.map((user) => {
      const eventUserPoints = eventPoints.find((ep) => ep._id.toString() === user._id.toString())?.eventPoints || 0;
      const practiceUserPoints = practicePoints.find((pp) => pp._id.toString() === user._id.toString())?.practicePoints || 0;
      return {
        userId: user._id.toString(),
        name: user.name || 'Unknown',
        email: user.email || 'N/A',
        rollNo: user.rollNo || 'N/A',
        clubName: Array.isArray(user.clubName) ? user.clubName : user.clubName ? [user.clubName] : [], // Ensure clubName is an array
        totalPoints: eventUserPoints + practiceUserPoints,
        avatar: user.avatar || 'https://via.placeholder.com/60/60'
      };
    });

    // Sort by totalPoints in descending order
    pointsTable.sort((a, b) => b.totalPoints - a.totalPoints);

    // Log successful response
    console.log(`Global points table fetched, records: ${pointsTable.length}`);

    res.status(200).json(pointsTable);
  } catch (err) {
    console.error('Global points table error:', {
      message: err.message,
      stack: err.stack,
      userId: req.user?._id,
    });
    res.status(500).json({ error: 'Server error fetching points table' });
  }
});
// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
