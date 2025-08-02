const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const validator = require("validator");
const { v4: uuidv4 } = require("uuid");
const QRCode = require("qrcode");
const fs = require("fs").promises;
const { v2: cloudinary } = require("cloudinary");
const streamifier = require("streamifier");
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

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer configuration
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      file.originalname.toLowerCase().split(".").pop()
    );
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error("Only JPEG and PNG images are allowed"));
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Function to upload file to Cloudinary
const uploadToCloudinary = (buffer, folder = "ACEM") => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder,
        allowed_formats: ["jpeg", "jpg", "png"],
        public_id: `file-${Date.now()}-${Math.round(Math.random() * 1e9)}`,
      },
      (error, result) => {
        if (error) return reject(error);
        resolve(result.secure_url);
      }
    );
    streamifier.createReadStream(buffer).pipe(stream);
  });
};

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Schemas
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        "Please enter a valid email address",
      ],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
    },
    rollNo: {
      type: String,
      required: false,
      unique: true,
      sparse: true,
    },
    isACEMStudent: {
      type: Boolean,
      required: [true, "ACEM student status is required"],
    },
    collegeName: {
      type: String,
      required: false,
    },
    semester: {
      type: Number,
      min: [1, "Semester must be between 1 and 8"],
      max: [8, "Semester must be between 1 and 8"],
    },
    course: {
      type: String,
      enum: ["BTech", "BCA", "BBA", "MBA"],
    },
    specialization: {
      type: String,
    },
    isClubMember: {
      type: Boolean,
      default: false,
    },
    clubName: [
      {
        type: String,
      },
    ],
    clubs: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Club",
      },
    ],
    pendingClubs: [{ type: mongoose.Schema.Types.ObjectId, ref: "Club" }],
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isHeadCoordinator: {
      type: Boolean,
      default: false,
    },
    headCoordinatorClubs: [
      {
        type: String,
      },
    ],
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Add comparePassword method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

// Other schemas remain unchanged
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
  date: { type: Date, required: true }, // Changed to Date type for consistency
  time: { type: String, required: true },
  location: { type: String, required: true },
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club", required: true },
  banner: { type: String },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
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
  eventType: {
    type: String,
    enum: ["Intra-College", "Inter-College"],
    required: true,
  },
  hasRegistrationFee: { type: Boolean, default: false },
  acemFee: { type: Number, default: 0 },
  nonAcemFee: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});
eventSchema.index({ club: 1, date: 1 });

const Event = mongoose.model("Event", eventSchema);

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
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  clubId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Club",
    required: true,
  },
  status: {
    type: String,
    enum: ["pending", "approved", "rejected"],
    default: "pending",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
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
    totalPoints: { type: Number, default: 0 },
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
    totalPoints: { type: Number, default: 0 },
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

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    console.error("authenticateToken: No token provided", {
      method: req.method,
      url: req.originalUrl,
    });
    return res.status(401).json({ error: "Access token required" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    console.log("authenticateToken: Token verified", {
      userId: decoded.id,
      email: decoded.email,
      method: req.method,
      url: req.originalUrl,
    });
    next();
  } catch (err) {
    console.error("authenticateToken: Token verification error", {
      message: err.message,
      stack: err.stack,
      method: req.method,
      url: req.originalUrl,
    });
    return res.status(403).json({ error: "Invalid or expired token" });
  }
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
    const user = await User.findById(req.user.id);
    if (!user) {
      console.error("isSuperAdmin: User not found", {
        userId: req.user.id,
        method: req.method,
        url: req.originalUrl,
      });
      return res.status(404).json({ error: "User not found" });
    }

    let club;
    if (req.params.id) {
      // For routes like PATCH /api/membership-requests/:id
      const membershipRequest = await MembershipRequest.findById(req.params.id);
      if (!membershipRequest) {
        console.error("isSuperAdmin: Membership request not found", {
          requestId: req.params.id,
          userId: req.user.id,
          method: req.method,
          url: req.originalUrl,
        });
        return res.status(404).json({ error: "Membership request not found" });
      }
      if (!mongoose.isValidObjectId(membershipRequest.clubId)) {
        console.error("isSuperAdmin: Invalid clubId in membership request", {
          requestId: req.params.id,
          clubId: membershipRequest.clubId,
          userId: req.user.id,
          method: req.method,
          url: req.originalUrl,
        });
        return res
          .status(400)
          .json({ error: "Invalid club ID in membership request" });
      }
      club = await Club.findById(membershipRequest.clubId);
    } else if (req.body.clubId) {
      // For routes like POST /api/membership-requests
      if (!mongoose.isValidObjectId(req.body.clubId)) {
        console.error("isSuperAdmin: Invalid clubId in request body", {
          clubId: req.body.clubId,
          userId: req.user.id,
          method: req.method,
          url: req.originalUrl,
        });
        return res.status(400).json({ error: "Invalid club ID" });
      }
      club = await Club.findById(req.body.clubId);
    } else {
      console.error("isSuperAdmin: No clubId provided", {
        userId: req.user.id,
        method: req.method,
        url: req.originalUrl,
      });
      return res.status(400).json({ error: "Club ID required" });
    }

    if (!club) {
      console.error("isSuperAdmin: Club not found", {
        clubId: req.params.id || req.body.clubId,
        userId: req.user.id,
        method: req.method,
        url: req.originalUrl,
      });
      return res.status(404).json({ error: "Club not found" });
    }

    const isAuthorized = club.superAdmins.some((adminId) =>
      adminId.equals(req.user.id)
    );
    if (!isAuthorized) {
      console.error("isSuperAdmin: User not authorized", {
        userId: req.user.id,
        clubId: club._id,
        clubName: club.name,
        superAdmins: club.superAdmins.map((id) => id.toString()),
        method: req.method,
        url: req.originalUrl,
      });
      return res.status(403).json({
        error: "You are not authorized to perform this action on this club",
      });
    }

    console.log("isSuperAdmin: User authorized", {
      userId: req.user.id,
      clubId: club._id,
      clubName: club.name,
      method: req.method,
      url: req.originalUrl,
    });
    next();
  } catch (err) {
    console.error("isSuperAdmin: Server error", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
      clubId: req.params.id || req.body.clubId,
      method: req.method,
      url: req.originalUrl,
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
      console.error("isHeadCoordinatorOrAdmin: User not found for ID:", req.user.id);
      return res.status(404).json({ error: "User not found" });
    }

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];

    if (superAdminEmails.includes(user.email) || user.isAdmin) {
      console.log("isHeadCoordinatorOrAdmin: Authorized as super admin or global admin:", {
        userId: user._id,
        email: user.email,
      });
      return next();
    }

    let clubId;
    // For PATCH /api/membership-requests/:id, get clubId from MembershipRequest
    if (req.params.id && req.path.includes("/membership-requests")) {
      const request = await MembershipRequest.findById(req.params.id).populate("clubId");
      if (!request || !request.clubId) {
        console.error("isHeadCoordinatorOrAdmin: Membership request or club not found:", {
          requestId: req.params.id,
        });
        return res.status(404).json({ error: "Membership request or club not found" });
      }
      clubId = request.clubId._id;
    } else {
      // For other endpoints (e.g., POST /api/clubs/:id/join)
      clubId = req.params.id || req.body.club || req.body.event?.club || req.params.clubId;
    }

    if (!clubId || !mongoose.isValidObjectId(clubId)) {
      console.error("isHeadCoordinatorOrAdmin: Invalid or missing club ID:", clubId);
      return res.status(400).json({ error: "Valid club ID is required" });
    }

    const club = await Club.findById(clubId);
    if (!club) {
      console.error("isHeadCoordinatorOrAdmin: Club not found for ID:", clubId);
      return res.status(404).json({ error: "Club not found" });
    }

    if (user.headCoordinatorClubs.includes(club.name)) {
      console.log("isHeadCoordinatorOrAdmin: Authorized as head coordinator for club:", {
        userId: user._id,
        clubName: club.name,
      });
      return next();
    }

    console.error("isHeadCoordinatorOrAdmin: User not authorized for club:", {
      userId: user._id,
      clubName: club.name,
      headCoordinatorClubs: user.headCoordinatorClubs,
    });
    return res.status(403).json({ error: "Head coordinator or admin access required" });
  } catch (err) {
    console.error("isHeadCoordinatorOrAdmin: Error in authorization check:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
      clubId: req.params.id || req.body.club || req.body.event?.club || req.params.clubId,
    });
    return res.status(500).json({ error: "Server error in authorization check" });
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

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    // Check if comparePassword method exists
    if (!user.comparePassword) {
      console.error("comparePassword method not found on user object", {
        userId: user._id,
        email: user.email,
      });
      return res.status(500).json({ error: "Server configuration error" });
    }

    // Compare password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });
  } catch (err) {
    console.error("Login error:", {
      message: err.message,
      stack: err.stack,
      path: "/api/auth/login-password",
      method: "POST",
      userId: undefined,
    });
    res.status(500).json({ error: "Server error during login" });
  }
});

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, isACEMStudent, collegeName } = req.body;

  // Validate required fields
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
  if (!isACEMStudent && !collegeName) {
    return res
      .status(400)
      .json({ error: "College name is required for non-ACEM students" });
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
      password, // Password will be hashed by pre('save') hook
      isAdmin,
      isHeadCoordinator,
      headCoordinatorClubs,
      isACEMStudent,
      collegeName: !isACEMStudent ? collegeName : null,
    });
    await user.save();

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
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
        error: "Duplicate key error: email already exists",
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

// Send Password Reset OTP
app.post("/api/auth/reset-password-otp-request", async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email address" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log(`No user found for email: ${email}`);
      return res.status(404).json({ error: "User not found" });
    }

    const resetOtp = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetPasswordOtp = resetOtp;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiry
    await user.save();
    console.log(
      `OTP generated for ${email}: ${resetOtp}, Expires: ${new Date(
        user.resetPasswordExpires
      )}`
    );

    await transporter.sendMail({
      from: `"ACEM" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "ACEM Password Reset OTP",
      text: `Your OTP for password reset is: ${resetOtp}\nThis OTP is valid for 1 hour.\nIf you did not request this, please ignore this email.`,
      html: `<p>Your OTP for password reset is: <strong>${resetOtp}</strong></p>
             <p>This OTP is valid for 1 hour.</p>
             <p>If you did not request this, please ignore this email.</p>`,
    });

    console.log(`Password reset OTP sent to ${email}`);
    res.json({ message: "Password reset OTP sent successfully" });
  } catch (err) {
    console.error("Password reset OTP request error:", {
      message: err.message,
      stack: err.stack,
      email,
    });
    res.status(500).json({ error: "Failed to send password reset OTP" });
  }
});

// Verify Reset OTP
app.post("/api/auth/verify-reset-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    console.log(`Missing email or OTP: email=${email}, otp=${otp}`);
    return res.status(400).json({ error: "Email and OTP are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log(`No user found for email: ${email}`);
      return res.status(404).json({ error: "User not found" });
    }

    console.log(
      `Verifying OTP for ${email}: provided=${otp}, stored=${user.resetPasswordOtp
      }, expires=${user.resetPasswordExpires}, now=${Date.now()}`
    );
    if (
      user.resetPasswordOtp !== otp ||
      user.resetPasswordExpires < Date.now()
    ) {
      console.log(
        `OTP verification failed: provided=${otp}, stored=${user.resetPasswordOtp
        }, expired=${user.resetPasswordExpires < Date.now()}`
      );
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    res.json({ message: "OTP verified successfully", email: user.email });
  } catch (err) {
    console.error("Reset OTP verification error:", {
      message: err.message,
      stack: err.stack,
      email,
      otp,
    });
    res.status(500).json({ error: "Failed to verify OTP" });
  }
});

// Reset Password
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    console.log(
      `Missing fields: email=${email}, otp=${otp}, newPassword=${newPassword ? "[provided]" : "missing"
      }`
    );
    return res
      .status(400)
      .json({ error: "Email, OTP, and new password are required" });
  }
  if (newPassword.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log(`No user found for email: ${email}`);
      return res.status(404).json({ error: "User not found" });
    }

    console.log(
      `Resetting password for ${email}: provided OTP=${otp}, stored OTP=${user.resetPasswordOtp
      }, expires=${user.resetPasswordExpires}, now=${Date.now()}`
    );
    if (
      user.resetPasswordOtp !== otp ||
      user.resetPasswordExpires < Date.now()
    ) {
      console.log(
        `Password reset failed: provided OTP=${otp}, stored OTP=${user.resetPasswordOtp
        }, expired=${user.resetPasswordExpires < Date.now()}`
      );
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    user.password = newPassword; // bcrypt hashing handled by pre-save middleware
    user.resetPasswordOtp = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    await transporter.sendMail({
      from: `"ACEM" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "ACEM Password Reset Successful",
      text: `Your password has been successfully reset. If you did not perform this action, please contact support immediately.`,
    });

    console.log(`Password reset successfully for ${email}`);
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("Password reset error:", {
      message: err.message,
      stack: err.stack,
      email,
    });
    res.status(500).json({ error: "Failed to reset password" });
  }
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
  try {
    const {
      semester,
      course,
      specialization,
      rollNo,
      isACEMStudent,
      collegeName,
      isClubMember,
      clubName,
    } = req.body;

    // Validate required fields
    if (
      !semester ||
      !course ||
      !specialization ||
      isACEMStudent === undefined
    ) {
      return res.status(400).json({
        error:
          "Semester, course, specialization, and ACEM student status are required",
      });
    }
    if (isACEMStudent && !rollNo) {
      return res.status(400).json({
        error: "Roll number is required for ACEM students",
      });
    }
    if (!isACEMStudent && !collegeName) {
      return res.status(400).json({
        error: "College name is required for non-ACEM students",
      });
    }

    const userId = req.user.id;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update user fields
    user.semester = semester;
    user.course = course;
    user.specialization = specialization;
    user.rollNo = isACEMStudent ? rollNo : null;
    user.isACEMStudent = isACEMStudent;
    user.collegeName = !isACEMStudent ? collegeName : null;
    user.isClubMember = isClubMember || false;
    user.clubName = clubName || [];

    // Update clubs if clubName is provided
    if (clubName && clubName.length > 0) {
      const clubs = await Club.find({ name: { $in: clubName } });
      user.clubs = clubs.map((club) => club._id);
    } else {
      user.clubs = [];
    }

    await user.save();

    res.json({ message: "User details updated successfully" });
  } catch (err) {
    console.error("Error updating user details:", {
      message: err.message,
      stack: err.stack,
    });
    if (err.name === "ValidationError") {
      return res
        .status(400)
        .json({ error: `Validation error: ${err.message}` });
    }
    if (err.code === 11000) {
      return res
        .status(400)
        .json({ error: "Duplicate key error: roll number already exists" });
    }
    res.status(500).json({ error: "Server error in updating user details" });
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

app.delete("/api/auth/delete-account", authenticateToken, async (req, res) => {
  try {
    console.log("Delete account request received for user ID:", req.user.id);

    // Verify user exists
    const user = await User.findById(req.user.id);
    if (!user) {
      console.error("User not found for ID:", req.user.id);
      return res.status(404).json({ error: "User not found" });
    }

    console.log("User found:", { id: user._id, email: user.email });

    // Optional: Clean up related data
    await Event.deleteMany({ createdBy: user._id });
    await Activity.deleteMany({ createdBy: user._id });
    await Attendance.deleteMany({ createdBy: user._id });
    await PracticeAttendance.deleteMany({ createdBy: user._id });
    await Notification.deleteMany({ userId: user._id });
    await MembershipRequest.deleteMany({ userId: user._id });
    await Club.updateMany(
      { members: user._id },
      { $pull: { members: user._id }, $inc: { memberCount: -1 } }
    );

    // Delete the user
    await User.findByIdAndDelete(user._id);
    console.log("User deleted successfully:", user._id);

    res.status(200).json({ message: "Account deleted successfully" });
  } catch (err) {
    console.error("Delete account error:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
    });
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    res.status(500).json({ error: "Failed to delete account" });
  }
});

// Get User Data
app.get("/api/auth/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select(
        "name email semester course specialization phone isClubMember clubName isAdmin isHeadCoordinator headCoordinatorClubs rollNo isACEMStudent collegeName"
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
          icon: club.icon || null,
          banner: club.banner || null,
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
  '/api/clubs',
  authenticateToken,
  isAdmin,
  upload.fields([
    { name: 'icon', maxCount: 1 },
    { name: 'banner', maxCount: 1 },
  ]),
  async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
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
          .json({ error: 'Name, description, category, and icon are required' });
      }

      if (!['Technical', 'Cultural', 'Literary', 'Entrepreneurial'].includes(category)) {
        return res.status(400).json({ error: 'Invalid category' });
      }

      if (description.length > 500) {
        return res
          .status(400)
          .json({ error: 'Description must be 500 characters or less' });
      }

      if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
        return res.status(400).json({ error: 'Invalid contact email' });
      }

      let iconUrl = null;
      let bannerUrl = null;
      if (req.files?.icon) {
        iconUrl = await uploadToCloudinary(req.files.icon[0].buffer);
      }
      if (req.files?.banner) {
        bannerUrl = await uploadToCloudinary(req.files.banner[0].buffer);
      }

      let validHeadCoordinators = [];
      if (headCoordinators) {
        let emails;
        try {
          emails = typeof headCoordinators === 'string' ? JSON.parse(headCoordinators) : headCoordinators;
          if (!Array.isArray(emails)) {
            return res.status(400).json({ error: 'headCoordinators must be an array' });
          }
        } catch (e) {
          return res.status(400).json({ error: 'Invalid headCoordinators format' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        validHeadCoordinators = emails.filter((email) => emailRegex.test(email));
        if (validHeadCoordinators.length > 0) {
          await User.updateMany(
            { email: { $in: validHeadCoordinators } },
            {
              $set: { isHeadCoordinator: true },
              $addToSet: { headCoordinatorClubs: name },
            },
            { session }
          );
        }
      }

      let validSuperAdmins = [req.user.id];
      if (superAdmins) {
        let adminIds;
        try {
          adminIds = typeof superAdmins === 'string' ? JSON.parse(superAdmins) : superAdmins;
          if (!Array.isArray(adminIds)) {
            return res.status(400).json({ error: 'superAdmins must be an array' });
          }
        } catch (e) {
          return res.status(400).json({ error: 'Invalid superAdmins format' });
        }
        adminIds = adminIds.filter((id) => id && id !== req.user.id && mongoose.isValidObjectId(id));
        if (adminIds.length + 1 > 2) {
          return res.status(400).json({ error: 'A club can have at most 2 super admins' });
        }
        const users = await User.find({ _id: { $in: adminIds } }).session(session);
        validSuperAdmins = [...validSuperAdmins, ...users.map((user) => user._id)];
        if (validSuperAdmins.length !== adminIds.length + 1) {
          return res.status(400).json({ error: 'One or more super admin IDs are invalid' });
        }
      }

      const creator = await User.findById(req.user.id).session(session);
      if (!creator) {
        return res.status(404).json({ error: 'Creator not found' });
      }

      const club = new Club({
        name,
        icon: iconUrl,
        banner: bannerUrl || null,
        description,
        category,
        contactEmail,
        headCoordinators: validHeadCoordinators,
        superAdmins: validSuperAdmins,
        creator: req.user.id,
        memberCount: 1,
        eventsCount: 0,
        members: [req.user.id],
      });
      await club.save({ session });

      creator.clubName = [...new Set([...(creator.clubName || []), name])];
      creator.clubs = [...new Set([...(creator.clubs || []), club._id])];
      creator.isClubMember = true;
      await creator.save({ session });

      await Notification.create(
        [{
          userId: creator._id,
          message: `You have successfully created and joined ${name} as a member.`,
          type: 'membership',
        }],
        { session }
      );

      await session.commitTransaction();
      const populatedClub = await Club.findById(club._id)
        .populate('superAdmins', 'name email')
        .populate('members', 'name email')
        .populate('creator', 'name email')
        .session(session);
      res.status(201).json({
        message: 'Club created successfully',
        club: {
          ...populatedClub._doc,
          icon: populatedClub.icon || null,
          banner: populatedClub.banner || null,
        },
      });
    } catch (err) {
      await session.abortTransaction();
      console.error('Club creation error:', { message: err.message, stack: err.stack });
      if (err.code === 11000) {
        return res.status(400).json({ error: 'Club name already exists' });
      }
      if (err.name === 'ValidationError') {
        return res.status(400).json({ error: `Validation error: ${err.message}` });
      }
      res.status(500).json({ error: err.message || 'Server error' });
    } finally {
      session.endSession();
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

      let iconUrl = club.icon;
      let bannerUrl = club.banner;

      if (req.files.icon) {
        if (club.icon) {
          const publicId = club.icon.split("/").pop().split(".")[0];
          await cloudinary.uploader.destroy(`ACEM/${publicId}`);
        }
        iconUrl = await uploadToCloudinary(req.files.icon[0].buffer);
      }
      if (req.files.banner) {
        if (club.banner) {
          const publicId = club.banner.split("/").pop().split(".")[0];
          await cloudinary.uploader.destroy(`ACEM/${publicId}`);
        }
        bannerUrl = await uploadToCloudinary(req.files.banner[0].buffer);
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
          }
        );
        await User.updateMany(
          {
            email: { $in: club.headCoordinators },
          },
          [
            {
              $set: {
                isHeadCoordinator: {
                  $cond: {
                    if: { $eq: ["$headCoordinatorClubs", []] },
                    then: false,
                    else: true,
                  },
                },
              },
            },
          ]
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

      club.icon = iconUrl;
      club.banner = bannerUrl;
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

      const transformedClub = {
        ...club._doc,
        icon: club.icon || null,
        banner: club.banner || null,
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

      // Remove club references from users
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
        }
      );

      // Update isClubMember for each affected user
      for (const member of members) {
        const updatedUser = await User.findById(member._id);
        updatedUser.isClubMember = updatedUser.clubName.length > 0;
        await updatedUser.save();
      }

      await MembershipRequest.deleteMany({ clubName: club.name });
      await Event.deleteMany({ club: club._id });
      await Attendance.deleteMany({ club: club._id });
      await PracticeAttendance.deleteMany({ club: club._id });

      if (club.icon) {
        try {
          const publicId = club.icon.split("/").pop().split(".")[0];
          await cloudinary.uploader.destroy(`ACEM/${publicId}`);
        } catch (err) {
          console.warn("Failed to delete club icon:", {
            message: err.message,
            path: club.icon,
          });
        }
      }
      if (club.banner) {
        try {
          const publicId = club.banner.split("/").pop().split(".")[0];
          await cloudinary.uploader.destroy(`ACEM/${publicId}`);
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

// POST /api/clubs/:id/join
app.post("/api/clubs/:id/join", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    if (!mongoose.isValidObjectId(id)) {
      console.error("POST /api/clubs/:id/join: Invalid club ID:", id);
      return res.status(400).json({ error: "Invalid club ID" });
    }

    const club = await Club.findById(id);
    if (!club) {
      console.error("POST /api/clubs/:id/join: Club not found for ID:", id);
      return res.status(404).json({ error: "Club not found" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      console.error("POST /api/clubs/:id/join: User not found for ID:", req.user.id);
      return res.status(404).json({ error: "User not found" });
    }

    // Initialize pendingClubs if undefined
    if (!user.pendingClubs) {
      user.pendingClubs = [];
    }

    if (user.clubs.some((clubId) => clubId.equals(club._id))) {
      console.error("POST /api/clubs/:id/join: User already a member of club:", {
        userId: user._id,
        clubId: club._id,
      });
      return res.status(400).json({ error: "You are already a member of this club" });
    }

    const existingRequest = await MembershipRequest.findOne({
      userId: user._id,
      clubId: club._id,
      status: "pending",
    });
    if (existingRequest) {
      console.error("POST /api/clubs/:id/join: Existing pending request found:", {
        userId: user._id,
        clubId: club._id,
      });
      return res.status(400).json({ error: "You already have a pending request for this club" });
    }

    const membershipRequest = new MembershipRequest({
      userId: user._id,
      clubId: club._id,
      status: "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await membershipRequest.save();

    user.pendingClubs.push(club._id);
    await user.save();

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    const recipients = [...(club.headCoordinators || []), ...superAdminEmails];
    if (recipients.length > 0) {
      try {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: recipients,
          subject: `New Membership Request for ${club.name}`,
          text: `User ${user.name} (${user.email}) has requested to join ${club.name}.`,
        });
        console.log("POST /api/clubs/:id/join: Notification email sent to:", recipients);
      } catch (err) {
        console.error("POST /api/clubs/:id/join: Error sending membership request email:", {
          message: err.message,
          stack: err.stack,
          userId: user._id,
          clubId: id,
        });
      }
    }

    await Notification.create({
      userId: user._id,
      message: `Your request to join ${club.name} has been submitted.`,
      type: "membership",
    });

    console.log("POST /api/clubs/:id/join: Membership request created:", {
      requestId: membershipRequest._id,
      userId: user._id,
      clubId: club._id,
    });
    res.json({ message: "Membership request submitted successfully" });
  } catch (err) {
    console.error("POST /api/clubs/:id/join: Error submitting membership request:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
      clubId: id,
    });
    res.status(500).json({ error: "Server error in membership request" });
  }
});

// GET /api/membership-requests
app.get("/api/membership-requests", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.error("GET /api/membership-requests: User not found for ID:", req.user.id);
      return res.status(404).json({ error: "User not found" });
    }

    const { all } = req.query;
    const query = all ? {} : { status: "pending" };

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    if (!superAdminEmails.includes(user.email) && !user.isAdmin) {
      const managedClubs = await Club.find({
        $or: [
          { creator: user._id },
          { superAdmins: user._id },
          { name: { $in: user.headCoordinatorClubs || [] } },
        ],
      }).distinct("_id");
      if (managedClubs.length === 0) {
        console.log("GET /api/membership-requests: No managed clubs for user:", {
          userId: user._id,
          email: user.email,
        });
        return res.json([]);
      }
      query.clubId = { $in: managedClubs };
    }

    const requests = await MembershipRequest.find(query)
      .populate("userId", "name email")
      .populate("clubId", "name")
      .lean();

    console.log("GET /api/membership-requests: Fetched requests:", {
      count: requests.length,
      userId: user._id,
      isAdmin: user.isAdmin,
      headCoordinatorClubs: user.headCoordinatorClubs,
      query,
    });

    res.json(requests);
  } catch (err) {
    console.error("GET /api/membership-requests: Error fetching membership requests:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?.id,
    });
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/membership-requests/:id
app.patch(
  "/api/membership-requests/:id",
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    console.log("PATCH /api/membership-requests/:id: Processing request:", {
      requestId: id,
      status,
      userId: req.user.id,
    });

    if (!mongoose.isValidObjectId(id)) {
      console.error("PATCH /api/membership-requests/:id: Invalid request ID:", id);
      return res.status(400).json({ error: "Invalid request ID" });
    }

    if (!["approved", "rejected"].includes(status)) {
      console.error("PATCH /api/membership-requests/:id: Invalid status:", status);
      return res.status(400).json({ error: "Invalid status" });
    }

    try {
      const request = await MembershipRequest.findById(id).populate("clubId userId");
      if (!request) {
        console.error("PATCH /api/membership-requests/:id: Membership request not found:", id);
        return res.status(404).json({ error: "Membership request not found" });
      }

      const club = await Club.findById(request.clubId._id);
      if (!club) {
        console.error("PATCH /api/membership-requests/:id: Club not found:", request.clubId._id);
        await MembershipRequest.deleteOne({ _id: id });
        return res.status(404).json({
          error: "Club not found. The membership request has been removed.",
        });
      }

      const targetUser = await User.findById(request.userId._id);
      if (!targetUser) {
        console.error("PATCH /api/membership-requests/:id: Target user not found:", request.userId._id);
        await MembershipRequest.deleteOne({ _id: id });
        return res.status(404).json({ error: "Target user not found" });
      }

      request.status = status;
      await request.save();

      if (status === "approved") {
        if (!targetUser.clubs.some((clubId) => clubId.equals(club._id))) {
          targetUser.clubs.push(club._id);
          targetUser.clubName.push(club.name);
          targetUser.isClubMember = true;
        }
        targetUser.pendingClubs = targetUser.pendingClubs.filter(
          (clubId) => !clubId.equals(club._id)
        );
        if (!club.members.some((memberId) => memberId.equals(targetUser._id))) {
          club.members.push(targetUser._id);
          club.memberCount = club.members.length;
        }
        await targetUser.save();
        await club.save();

        try {
          await transporter.sendMail({
            from: `"ACEM" <${process.env.EMAIL_USER}>`,
            to: targetUser.email,
            subject: `Membership Request Approved for ${club.name}`,
            text: `Congratulations! Your request to join ${club.name} has been approved.`,
          });
          console.log("PATCH /api/membership-requests/:id: Approval email sent to:", targetUser.email);
        } catch (err) {
          console.error("PATCH /api/membership-requests/:id: Error sending approval email:", {
            message: err.message,
            stack: err.stack,
            userId: targetUser._id,
            clubId: club._id,
          });
        }

        await Notification.create({
          userId: targetUser._id,
          message: `Your request to join ${club.name} has been approved.`,
          type: "membership",
        });
      } else {
        targetUser.pendingClubs = targetUser.pendingClubs.filter(
          (clubId) => !clubId.equals(club._id)
        );
        await targetUser.save();

        try {
          await transporter.sendMail({
            from: `"ACEM" <${process.env.EMAIL_USER}>`,
            to: targetUser.email,
            subject: `Membership Request Rejected for ${club.name}`,
            text: `We regret to inform you that your request to join ${club.name} has been rejected.`,
          });
          console.log("PATCH /api/membership-requests/:id: Rejection email sent to:", targetUser.email);
        } catch (err) {
          console.error("PATCH /api/membership-requests/:id: Error sending rejection email:", {
            message: err.message,
            stack: err.stack,
            userId: targetUser._id,
            clubId: club._id,
          });
        }

        await Notification.create({
          userId: targetUser._id,
          message: `Your request to join ${club.name} has been rejected.`,
          type: "membership",
        });
      }

      // Delete the request after approval/rejection
      await MembershipRequest.deleteOne({ _id: id });

      console.log("PATCH /api/membership-requests/:id: Membership request updated:", {
        requestId: id,
        status,
        userId: req.user.id,
        targetUserId: targetUser._id,
        clubId: club._id,
      });

      res.json({ message: `Membership request ${status} successfully` });
    } catch (err) {
      console.error("PATCH /api/membership-requests/:id: Error updating membership request:", {
        message: err.message,
        stack: err.stack,
        requestId: id,
        userId: req.user?.id,
      });
      res.status(500).json({ error: "Server error in updating membership request" });
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
      icon: club.icon || null,
      banner: club.banner || null,
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

app.post("/api/clubs/:id/leave", authenticateToken, async (req, res) => {
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

    if (!user.clubs.includes(club._id) || !user.clubName.includes(club.name)) {
      return res
        .status(400)
        .json({ error: "You are not a member of this club" });
    }

    const isSuperAdmin = club.superAdmins.includes(user._id);
    const isHeadCoordinator =
      user.isHeadCoordinator && user.headCoordinatorClubs.includes(club.name);
    if (isSuperAdmin || isHeadCoordinator) {
      return res
        .status(403)
        .json({ error: "Admins and head coordinators cannot leave the club" });
    }

    user.clubs = user.clubs.filter(
      (clubId) => clubId.toString() !== club._id.toString()
    );
    user.clubName = user.clubName.filter((name) => name !== club.name);
    user.isClubMember = user.clubName.length > 0;
    club.members = club.members.filter(
      (memberId) => memberId.toString() !== user._id.toString()
    );
    club.memberCount = club.members.length;

    await user.save();
    await club.save();

    await Notification.create({
      userId: user._id,
      message: `You have left ${club.name}.`,
      type: "membership",
    });

    const superAdminEmails = process.env.SUPER_ADMIN_EMAILS
      ? process.env.SUPER_ADMIN_EMAILS.split(",").map((email) => email.trim())
      : [];
    const recipients = [...club.headCoordinators, ...superAdminEmails];
    if (recipients.length > 0) {
      try {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: recipients,
          subject: `Member Left: ${club.name}`,
          text: `User ${user.name} (${user.email}) has left ${club.name}.`,
        });
      } catch (err) {
        console.error("Error sending leave notification email:", {
          message: err.message,
          stack: err.stack,
        });
      }
    }

    res.json({ message: "You have left the club successfully" });
  } catch (err) {
    console.error("Error leaving club:", {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Server error in leaving club" });
  }
});

// Create Event (Creator, Super Admin, or Head Coordinator only)
app.post(
  '/api/events',
  authenticateToken,
  isHeadCoordinatorOrAdmin,
  upload.single('banner'),
  async (req, res) => {
    try {
      const {
        title,
        description,
        date,
        time,
        location,
        club,
        category,
        eventType,
        hasRegistrationFee,
        acemFee,
        nonAcemFee,
      } = req.body;

      if (
        !title ||
        !description ||
        !date ||
        !time ||
        !location ||
        !club ||
        !category ||
        !eventType
      ) {
        return res.status(400).json({ error: 'All required fields must be provided' });
      }

      if (!mongoose.isValidObjectId(club)) {
        return res.status(400).json({ error: 'Invalid club ID' });
      }

      if (!['Seminar', 'Competition'].includes(category)) {
        return res.status(400).json({ error: 'Invalid event category' });
      }

      if (!['Intra-College', 'Inter-College'].includes(eventType)) {
        return res.status(400).json({ error: 'Invalid event type' });
      }

      const parsedDate = new Date(date);
      if (isNaN(parsedDate.getTime())) {
        return res.status(400).json({ error: 'Invalid date format' });
      }

      const isFeeRequired = eventType === 'Inter-College' && hasRegistrationFee === 'true';
      if (isFeeRequired) {
        if (
          !acemFee ||
          !nonAcemFee ||
          isNaN(acemFee) ||
          isNaN(nonAcemFee) ||
          parseFloat(acemFee) < 0 ||
          parseFloat(nonAcemFee) < 0
        ) {
          return res.status(400).json({
            error: 'Valid registration fees are required for Inter-College events',
          });
        }
      }

      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const clubDoc = await Club.findById(club);
      if (!clubDoc) return res.status(404).json({ error: 'Club not found' });

      const isAuthorized =
        user.isAdmin ||
        clubDoc.creator.equals(req.user.id) ||
        clubDoc.superAdmins.some((admin) => admin.equals(req.user.id)) ||
        user.headCoordinatorClubs.includes(clubDoc.name);

      if (!isAuthorized) {
        return res.status(403).json({
          error: 'Not authorized to create events for this club',
        });
      }

      let bannerUrl = null;
      if (req.file) {
        if (!['image/jpeg', 'image/png'].includes(req.file.mimetype)) {
          return res.status(400).json({ error: 'Banner must be a JPEG or PNG image' });
        }
        if (req.file.size > 5 * 1024 * 1024) {
          return res.status(400).json({ error: 'Banner size must be less than 5MB' });
        }
        bannerUrl = await uploadToCloudinary(req.file.buffer);
      }

      const event = new Event({
        title,
        description,
        date: parsedDate,
        time,
        location,
        club,
        banner: bannerUrl,
        createdBy: req.user.id,
        category,
        eventType,
        hasRegistrationFee: isFeeRequired,
        acemFee: isFeeRequired ? parseFloat(acemFee) : 0,
        nonAcemFee: isFeeRequired ? parseFloat(nonAcemFee) : 0,
        registeredUsers: [],
      });

      await event.save();
      clubDoc.eventsCount = await Event.countDocuments({ club: clubDoc._id });
      await clubDoc.save();

      await Notification.create({
        userId: req.user.id,
        message: `Event "${title}" created successfully for ${clubDoc.name}.`,
        type: 'event',
      });

      res.status(201).json({
        message: 'Event created successfully',
        event: {
          ...event._doc,
          banner: event.banner || null,
        },
      });
    } catch (err) {
      console.error('Event creation error:', { message: err.message, stack: err.stack });
      if (err.code === 11000) {
        return res.status(400).json({ error: 'Event with this title already exists for this club' });
      }
      if (err.name === 'ValidationError') {
        return res.status(400).json({ error: `Validation error: ${err.message}` });
      }
      if (err.name === 'CastError') {
        return res.status(400).json({ error: 'Invalid data format' });
      }
      res.status(500).json({ error: err.message || 'Failed to create event' });
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
      banner: event.banner || null,
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
      banner: event.banner || null,
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

//delete event :
app.delete("/api/events/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    if (!req.user || !req.user.id) { // Use 'id' instead of '_id' if needed
      return res.status(401).json({ error: "User not authenticated" });
    }
    const event = await Event.findById(req.params.id).populate("club");
    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }
    console.log("Event:", {
      _id: event._id,
      club: event.club ? { _id: event.club._id, name: event.club.name, superAdmins: event.club.superAdmins } : null,
    });
    console.log("User:", {
      _id: req.user.id, // Use 'id' instead of '_id'
      isAdmin: req.user.isAdmin,
      headCoordinatorClubs: req.user.headCoordinatorClubs,
    });
    const isAdmin = req.user.isAdmin || false;
    const isHeadCoordinator = Array.isArray(req.user.headCoordinatorClubs) && 
      event.club?.name && 
      req.user.headCoordinatorClubs.includes(event.club.name);
    const isSuperAdmin = Array.isArray(event.club?.superAdmins) && 
      event.club.superAdmins.some(
        (admin) => admin && admin._id && admin._id.toString() === req.user.id.toString() // Use 'id'
      );
    if (!isAdmin && !isHeadCoordinator && !isSuperAdmin) {
      return res.status(403).json({ error: "Unauthorized to delete this event" });
    }
    await Event.findByIdAndDelete(req.params.id);
    res.json({ message: "Event deleted successfully" });
  } catch (err) {
    console.error("Error deleting event:", {
      message: err.message,
      stack: err.stack,
      eventId: req.params.id,
      user: req.user,
    });
    res.status(500).json({ error: `Server error while deleting event: ${err.message}` });
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
      const event = await Event.findById(id);
      if (!event) {
        return res.status(404).json({ error: "Event not found" });
      }

      const clubDoc = await Club.findById(club);
      if (!clubDoc) {
        return res.status(404).json({ error: "Club not found" });
      }

      let bannerUrl = event.banner;
      if (req.file) {
        if (event.banner) {
          const publicId = event.banner.split("/").pop().split(".")[0];
          await cloudinary.uploader.destroy(`ACEM/${publicId}`);
        }
        bannerUrl = await uploadToCloudinary(req.file.buffer);
      }

      event.title = title;
      event.description = description;
      event.date = date;
      event.time = time;
      event.location = location;
      event.club = club;
      event.banner = bannerUrl;
      event.category = category;
      await event.save();

      const transformedEvent = {
        ...event._doc,
        banner: event.banner || null,
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
// Delete Event (Creator, Super Admin, or Head Coordinator only)
app.post('/api/events/:id/register', authenticateToken, async (req, res) => {
  const session = await mongoose.startSession();
  console.log('Starting registration for event:', req.params.id, 'User:', req.user?.id);
  session.startTransaction();
  try {
    const { name, email, rollNo, isACEMStudent } = req.body;
    console.log('Received payload:', { name, email, rollNo, isACEMStudent });

    // Validate input
    if (!name || !email || isACEMStudent === undefined) {
      console.error('Validation failed: Missing required fields', { name, email, isACEMStudent });
      return res.status(400).json({ error: 'Name, email, and ACEM student status are required' });
    }

    if (isACEMStudent && !rollNo) {
      console.error('Validation failed: Roll number required for ACEM students', { rollNo });
      return res.status(400).json({ error: 'Roll number is required for ACEM students' });
    }

    if (!validator.isEmail(email)) {
      console.error('Validation failed: Invalid email', { email });
      return res.status(400).json({ error: 'Invalid email address' });
    }

    if (!mongoose.isValidObjectId(req.params.id)) {
      console.error('Validation failed: Invalid event ID', { eventId: req.params.id });
      return res.status(400).json({ error: 'Invalid event ID' });
    }

    // Fetch event
    console.log('Fetching event:', req.params.id);
    const event = await Event.findById(req.params.id).populate('club').session(session);
    if (!event) {
      console.error('Event not found:', req.params.id);
      return res.status(404).json({ error: 'Event not found' });
    }

    if (!event.club || !mongoose.isValidObjectId(event.club._id)) {
      console.error('Club not found or invalid for event:', req.params.id, { club: event.club });
      return res.status(400).json({ error: 'Invalid club reference for this event' });
    }

    // Fetch user
    console.log('Fetching user:', req.user.id);
    const user = await User.findById(req.user.id).session(session);
    if (!user) {
      console.error('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }

    // Check for duplicate registration
    if (!Array.isArray(event.registeredUsers)) {
      event.registeredUsers = [];
    }
    if (event.registeredUsers.some((reg) => reg.userId.toString() === req.user.id)) {
      console.error('Duplicate registration for user:', req.user.id, 'Event:', req.params.id);
      return res.status(400).json({ error: 'User already registered for this event' });
    }

    // Check event type restriction
    if (event.eventType === 'Intra-College' && !isACEMStudent) {
      console.error('Intra-College restriction violated for user:', req.user.id);
      return res.status(403).json({ error: 'Only ACEM students can register for Intra-College events' });
    }

    // Handle payment (simulated)
    let paymentStatus = 'not_required';
    let transactionId = null;
    if (event.eventType === 'Inter-College' && event.hasRegistrationFee) {
      const amount = isACEMStudent ? event.acemFee : event.nonAcemFee;
      transactionId = `TXN_${uuidv4()}`;
      paymentStatus = 'success'; // Simulate successful payment
      if (paymentStatus !== 'success') {
        console.error('Payment failed for event:', event._id);
        return res.status(400).json({ error: 'Payment failed' });
      }
    }

    // Use rollNo from request or user
    const effectiveRollNo = isACEMStudent ? rollNo || user.rollNo : null;

    // Handle club membership for ACEM students
    if (isACEMStudent) {
      console.log('Checking club membership for club:', event.club._id);
      const club = await Club.findById(event.club._id).session(session);
      if (!club) {
        console.error('Club not found:', event.club._id);
        return res.status(400).json({ error: 'Club not found' });
      }
      if (!club.members.includes(req.user.id)) {
        console.log('Adding user to club:', club._id);
        club.members = club.members || [];
        club.members.push(req.user.id);
        club.memberCount = await User.countDocuments({ clubName: club.name });
        await club.save({ session });
        user.clubName = [...new Set([...(user.clubName || []), club.name])];
        user.clubs = [...new Set([...(user.clubs || []), club._id])];
        user.isClubMember = true;
        await user.save({ session });
      }
    }

    // Register user
    console.log('Registering user for event:', event._id);
    event.registeredUsers.push({
      userId: req.user.id,
      name,
      email,
      rollNo: effectiveRollNo,
      isACEMStudent,
    });
    await event.save({ session });

    // Generate QR code for non-ACEM Inter-College events
    let qrCode = null;
    if (!isACEMStudent && event.eventType === 'Inter-College') {
      console.log('Generating QR code for user:', req.user.id);
      const qrData = JSON.stringify({
        userId: req.user.id,
        eventId: event._id,
        transactionId: transactionId || uuidv4(),
        eventTitle: event.title,
        userName: name,
      });
      try {
        qrCode = await QRCode.toDataURL(qrData);
      } catch (qrError) {
        console.error('QR code generation failed:', {
          message: qrError.message,
          stack: qrError.stack,
        });
        throw new Error('Failed to generate QR code');
      }
    }

    // Create notification
    console.log('Creating notification for user:', req.user.id);
    await Notification.create(
      [{
        userId: req.user.id,
        message: `You have successfully registered for the ${event.category.toLowerCase()} "${event.title}" in ${event.club.name}.`,
        type: 'event',
      }],
      { session }
    );

    // Send email with QR code
    if (qrCode) {
      console.log('Sending email with QR code to:', email);
      try {
        await transporter.sendMail({
          from: `"ACEM" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: `Registration Confirmation for ${event.title}`,
          html: `
              <h3>Registration Successful</h3>
              <p>Thank you for registering for ${event.title}!</p>
              <p>Event Date: ${new Date(event.date).toLocaleDateString()}</p>
              <p>Event Time: ${event.time}</p>
              <p>Location: ${event.location}</p>
              ${event.hasRegistrationFee ? `<p>Payment Amount: ${isACEMStudent ? event.acemFee : event.nonAcemFee} INR</p>` : ''}
              <p>Scan the QR code below to verify your registration:</p>
              <img src="${qrCode}" alt="Registration QR Code" />
            `,
        });
      } catch (emailError) {
        console.error('Email sending failed:', {
          message: emailError.message,
          stack: emailError.stack,
        });
        throw new Error('Failed to send registration email');
      }
    }

    await session.commitTransaction();
    console.log('Registration successful for event:', event._id, 'User:', req.user.id);
    res.json({
      message: isACEMStudent
        ? 'Successfully joined the club and registered for the event'
        : 'Registration successful',
      qrCode,
      paymentStatus,
      transactionId,
    });
  } catch (err) {
    console.error('Error in registration route:', {
      message: err.message,
      stack: err.stack,
      code: err.code,
      eventId: req.params.id,
      userId: req.user?.id,
    });
    await session.abortTransaction();
    res.status(500).json({ error: `Server error: ${err.message}` });
  } finally {
    session.endSession();
  }
});

// Register for Event
app.post('/api/events/:id/register', authenticateToken, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const { name, email, rollNo, isACEMStudent } = req.body;

    if (!name || !email || isACEMStudent === undefined) {
      return res.status(400).json({ error: 'Name, email, and ACEM student status are required' });
    }

    if (isACEMStudent && !rollNo) {
      return res.status(400).json({ error: 'Roll number is required for ACEM students' });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }

    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid event ID' });
    }

    const event = await Event.findById(req.params.id).populate('club').session(session);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const userId = req.user.id;
    const user = await User.findById(userId).session(session);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (event.registeredUsers?.some((reg) => reg.userId.toString() === userId)) {
      return res.status(400).json({ error: 'User already registered for this event' });
    }

    if (event.eventType === 'Intra-College' && !isACEMStudent) {
      return res.status(403).json({ error: 'Only ACEM students can register for Intra-College events' });
    }

    let paymentStatus = 'not_required';
    let transactionId = null;
    if (event.eventType === 'Inter-College' && event.hasRegistrationFee) {
      const amount = isACEMStudent ? event.acemFee : event.nonAcemFee;
      if (!amount || isNaN(amount) || amount < 0) {
        return res.status(400).json({ error: 'Invalid registration fee amount' });
      }
      transactionId = `TXN_${uuidv4()}`;
      paymentStatus = 'success'; // Replace with real payment gateway integration
      if (paymentStatus !== 'success') {
        return res.status(400).json({ error: 'Payment failed' });
      }
    }

    const effectiveRollNo = isACEMStudent ? rollNo || user.rollNo : null;

    if (isACEMStudent) {
      const club = await Club.findById(event.club._id).session(session);
      if (!club) {
        return res.status(404).json({ error: 'Club not found' });
      }
      if (!club.members.includes(userId)) {
        club.members = club.members || [];
        club.members.push(userId);
        club.memberCount = await User.countDocuments({ clubName: club.name });
        await club.save({ session });
        user.clubName = [...new Set([...(user.clubName || []), club.name])];
        user.clubs = [...new Set([...(user.clubs || []), club._id])];
        user.isClubMember = true;
        await user.save({ session });
      }
    }

    event.registeredUsers = event.registeredUsers || [];
    event.registeredUsers.push({
      userId,
      name,
      email,
      rollNo: effectiveRollNo,
      isACEMStudent,
    });
    await event.save({ session });

    let qrCode = null;
    if (!isACEMStudent && event.eventType === 'Inter-College') {
      const qrData = JSON.stringify({
        userId,
        eventId: event._id,
        transactionId: transactionId || uuidv4(),
        eventTitle: event.title,
        userName: name,
      });
      qrCode = await QRCode.toDataURL(qrData);
    }

    await Notification.create(
      [{
        userId,
        message: `You have successfully registered for the ${event.category.toLowerCase()} "${event.title}" in ${event.club.name}.`,
        type: 'event',
      }],
      { session }
    );

    if (qrCode) {
      await transporter.sendMail({
        from: `"ACEM" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: `Registration Confirmation for ${event.title}`,
        html: `
            <h3>Registration Successful</h3>
            <p>Thank you for registering for ${event.title}!</p>
            <p>Event Date: ${new Date(event.date).toLocaleDateString()}</p>
            <p>Event Time: ${event.time}</p>
            <p>Location: ${event.location}</p>
            ${event.hasRegistrationFee ? `<p>Payment Amount: ${isACEMStudent ? event.acemFee : event.nonAcemFee} INR</p>` : ''}
            <p>Scan the QR code below to verify your registration:</p>
            <img src="${qrCode}" alt="Registration QR Code" />
          `,
      });
    }

    await session.commitTransaction();
    res.json({
      message: isACEMStudent
        ? 'Successfully joined the club and registered for the event'
        : 'Registration successful',
      qrCode,
      paymentStatus,
      transactionId,
    });
  } catch (err) {
    await session.abortTransaction();
    console.error('Error registering for event:', { message: err.message, stack: err.stack });
    res.status(500).json({ error: err.message || 'Failed to register for event' });
  } finally {
    session.endSession();
  }
});

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
      return res.status(400).json({
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
          message: `Your attendance for "${eventDoc.title
            }" on ${date} has been marked as ${entry.status} (${entry.status === "present" ? "5 points" : "0 points"
            }).`,
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
            } has been updated to ${entry.status} (${entry.status === "present" ? "5 points" : "0 points"
            }).`,
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
        Rancho;
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
    if (isACEMStudent && !rollNo) {
      return res
        .status(400)
        .json({ error: "Roll number is required for ACEM students" });
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

      if (!club.creator || !mongoose.isValidObjectId(club.creator)) {
        club.creator = req.user.id;
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
          rollNo: isACEMStudent ? rollNo : null,
          isACEMStudent,
          collegeName: !isACEMStudent ? user?.collegeName : null, // Use existing collegeName
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
          collegeName: user.collegeName,
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
                  }, Absent: ${attendanceRecord.stats?.absentCount || 0}, Rate: ${attendanceRecord.stats?.attendanceRate?.toFixed(2) || 0
                  }%, Total Points: ${attendanceRecord.stats?.totalPoints || 0}`,
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
      return res.status(400).json({
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
        return res.status(400).json({
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
          message: `Your attendance for "${title}" on ${formattedDate} in room ${roomNo} has been marked as ${entry.status
            } (${entry.status === "present" ? "3 points" : "0 points"}).`,
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
        return res.status(400).json({
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
      return res.status(400).json({
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
        return res.status(400).json({
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
          message: `Your attendance for "${title}" on ${formattedDate} in room ${roomNo} has been updated to ${entry.status
            } (${entry.status === "present" ? "3 points" : "0 points"}).`,
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
        return res.status(400).json({
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
                  text: `Practice: ${record.title
                    } | Date: ${record.date.toLocaleDateString()} | Room: ${record.roomNo
                    }`,
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

app.get("/api/points-table", authenticateToken, async (req, res) => {
  try {
    // Aggregate event attendance points (5 points per present)
    const eventPoints = await Attendance.aggregate([
      { $unwind: "$attendance" },
      { $match: { "attendance.status": "present" } },
      {
        $group: {
          _id: "$attendance.userId",
          eventPoints: { $sum: 5 },
        },
      },
      { $project: { _id: 1, eventPoints: 1 } },
    ]);

    // Aggregate practice attendance points (3 points per present)
    const practicePoints = await PracticeAttendance.aggregate([
      { $unwind: "$attendance" },
      { $match: { "attendance.status": "present" } },
      {
        $group: {
          _id: "$attendance.userId",
          practicePoints: { $sum: 3 },
        },
      },
      { $project: { _id: 1, practicePoints: 1 } },
    ]);

    // Fetch all users with relevant fields, including clubName, clubRoles, and avatar
    const users = await User.find(
      {},
      "name email rollNo clubName clubRoles avatar"
    ).lean();

    // Combine points, user details, and filter by member roles
    const pointsTable = users
      .map((user) => {
        // Ensure clubName is an array
        const clubNames = Array.isArray(user.clubName)
          ? user.clubName
          : user.clubName
            ? [user.clubName]
            : [];

        // Construct clubRoles if not provided, defaulting to 'member' for each club
        const clubRoles =
          user.clubRoles ||
          clubNames.map((clubName) => ({
            clubName,
            roles: ["member"],
          }));

        // Filter clubs where the user is only a member (exclude headCoordinator, admin, superAdmin)
        const memberClubs = clubRoles
          .filter(
            (clubRole) =>
              clubRole.roles.includes("member") &&
              !clubRole.roles.includes("headCoordinator") &&
              !clubRole.roles.includes("admin") &&
              !clubRole.roles.includes("superAdmin")
          )
          .map((clubRole) => clubRole.clubName);

        // Skip users with no member clubs
        if (memberClubs.length === 0) return null;

        const eventUserPoints =
          eventPoints.find((ep) => ep._id.toString() === user._id.toString())
            ?.eventPoints || 0;
        const practiceUserPoints =
          practicePoints.find((pp) => pp._id.toString() === user._id.toString())
            ?.practicePoints || 0;

        return {
          userId: user._id.toString(),
          name: user.name || "Unknown",
          email: user.email || "N/A",
          rollNo: user.rollNo || "N/A",
          clubName: memberClubs,
          clubRoles: clubRoles.map((role) => ({
            clubName: role.clubName,
            roles: Array.isArray(role.roles) ? role.roles : [role.roles],
          })),
          totalPoints: eventUserPoints + practiceUserPoints,
          avatar: user.avatar || "https://via.placeholder.com/60/60",
        };
      })
      .filter((user) => user !== null); // Remove users with no member clubs

    // Sort by totalPoints in descending order
    pointsTable.sort((a, b) => b.totalPoints - a.totalPoints);

    // Log successful response
    console.log(`Member points table fetched, records: ${pointsTable.length}`);

    res.status(200).json(pointsTable);
  } catch (err) {
    console.error("Member points table error:", {
      message: err.message,
      stack: err.stack,
      userId: req.user?._id,
    });
    res.status(500).json({ error: "Server error fetching points table" });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
