require("dotenv").config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/user');
const Admin = require('./models/admin')
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const Category = require("./models/Category");
const SubCategory = require("./models/SubCategory");
const Policy = require("./models/Policy");
const UserPolicy = require("./models/UserPolicy");
const Ticket = require("./models/Ticket");
const nodemailer = require('nodemailer')





const app = express()
app.use(bodyParser.json());
app.use(cookieParser());

app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));

mongoose.connect(process.env.MONGO_URL) 
  .then(() => console.log('MongoDB is Connected'))
  .catch(err => console.log(err));

/* ---------------- Mail Transporter ---------------- */
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.get('/', (req, res) => res.send('mainpg'));

app.post("/test", (req, res) => {
  res.json({ message: "backend working" });
});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password, number } = req.body;
    if (!name || !email || !password || !number) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const userExists = await User.findOne({
      $or: [{ email }, { number }]
    });

    if (userExists) {
      return res.status(400).json({ message: "Email or phone already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      number,
      password: hashedPassword
    });

    await user.save();

    res.status(201).json({ message: "User registered successfully" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================
   FORGOT PASSWORD → SEND OTP
========================================== */
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email)
      return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({ email });

    if (!user)
      return res.status(404).json({ message: "User not found" });

    // Generate 6 digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const hashedOTP = await bcrypt.hash(otp, 10);

    user.resetOTP = hashedOTP;
    user.otpExpiry = Date.now() + 5 * 60 * 1000;

    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP",
      html: `
        <h3>Password Reset Request</h3>
        <p>Your OTP is: <b>${otp}</b></p>
        <p>This OTP is valid for 5 minutes.</p>
      `
    });

    res.status(200).json({ message: "OTP sent successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

/* ==========================================
   RESET PASSWORD
========================================== */
app.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword)
      return res.status(400).json({ message: "All fields required" });

    if (newPassword.length < 8)
      return res.status(400).json({ message: "Password must be 8+ characters" });

    const user = await User.findOne({ email });

    if (!user)
      return res.status(404).json({ message: "User not found" });

    if (!user.resetOTP || !user.otpExpiry)
      return res.status(400).json({ message: "No OTP request found" });

    if (user.otpExpiry < Date.now())
      return res.status(400).json({ message: "OTP expired" });

    const isMatch = await bcrypt.compare(otp, user.resetOTP);

    if (!isMatch)
      return res.status(400).json({ message: "Invalid OTP" });

    user.password = await bcrypt.hash(newPassword, 10);

    user.resetOTP = undefined;
    user.otpExpiry = undefined;

    await user.save();

    res.status(200).json({ message: "Password reset successful" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Reset failed" });
  }
});

// User Part
app.get('/login', (req, res) => res.json('login'));
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, role: "user" }).select("+password");
    if (!user)
      return res.status(400).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: "user" },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "none",
      secure: true,
      maxAge: 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      message: "User login successful",
      role: "user",
      user: {
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const verifyUser = (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: "User not authenticated" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "user") {
      return res.status(403).json({ message: "Access denied" });
    }

    req.user = decoded; // { id, role }
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

app.get("/dashboard", verifyUser, async (req, res) => {
  try {
    const userId = req.user.id;

    let totalPolicies = 0;
    let approvedPolicies = 0;
    let rejectedPolicies = 0;
    let pendingPolicies = 0;

    let totalTickets = 0;
    let openTickets = 0;
    let resolvedTickets = 0;

    try {
      totalPolicies = await mongoose.connection
        .collection("policies")
        .countDocuments({ userId });

      approvedPolicies = await mongoose.connection
        .collection("policies")
        .countDocuments({ userId, status: "approved" });

      rejectedPolicies = await mongoose.connection
        .collection("policies")
        .countDocuments({ userId, status: "rejected" });

      pendingPolicies = await mongoose.connection
        .collection("policies")
        .countDocuments({ userId, status: "pending" });
    } catch {}

    try {
      totalTickets = await mongoose.connection
        .collection("tickets")
        .countDocuments({ userId });

      openTickets = await mongoose.connection
        .collection("tickets")
        .countDocuments({ userId, status: "open" });

      resolvedTickets = await mongoose.connection
        .collection("tickets")
        .countDocuments({ userId, status: "resolved" });
    } catch {}

    const user = await User.findById(userId).select("name email");

    res.status(200).json({
      success: true,
      user,
      stats: {
        totalPolicies,
        approvedPolicies,
        rejectedPolicies,
        pendingPolicies,
        totalTickets,
        openTickets,
        resolvedTickets
      }
    });
  } catch (error) {
    console.error("User Dashboard API Error:", error);
    res.status(500).json({ message: "Failed to load user dashboard" });
  }
});

// GET USER PROFILE
app.get("/profile", verifyUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// UPDATE PROFILE
app.put("/profile", verifyUser, async (req, res) => {
  try {
    const { name, number, gender } = req.body;

    const updated = await User.findByIdAndUpdate(
      req.user.id,
      { name, number, gender },
      { new: true }
    ).select("-password");

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: updated
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// USER CHANGE PASSWORD
app.put("/change-password", verifyUser, async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    // required fields
    if (!oldPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // ✅ 8 character rule
    if (newPassword.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long" });
    }

    // match check
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    // get user
    const user = await User.findById(req.user.id).select("+password");

    const match = await bcrypt.compare(oldPassword, user.password);

    if (!match) {
      return res.status(400).json({ message: "Old password incorrect" });
    }

    // save new password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ==========================================
   USER → GET ALL POLICIES
========================================== */
app.get("/policies", verifyUser, async (req, res) => {
  try {
    const policies = await Policy.find();
    res.status(200).json(policies);
  } catch (err) {
    res.status(500).json({ message: "Error fetching policies" });
  }
});

/* ==========================================
   USER → APPLY POLICY
========================================== */
app.post("/apply-policy/:policyId", verifyUser, async (req, res) => {
  try {
    const exists = await UserPolicy.findOne({
      user: req.user.id,
      policy: req.params.policyId,
    });

    if (exists) {
      return res.status(400).json({ message: "Already applied" });
    }

    const application = await UserPolicy.create({
      user: req.user.id,
      policy: req.params.policyId,
    });

    res.status(201).json({
      success: true,
      message: "Policy applied successfully",
      application,
    });
  } catch (err) {
    res.status(500).json({ message: "Application failed" });
  }
});

/* ==========================================
   USER → GET POLICY HISTORY
========================================== */

app.get("/my-policies/history", verifyUser, async (req, res) => {
  try {
    console.log("📥 Fetching policy history...");
    console.log("User ID:", req.user.id);

    const data = await UserPolicy.find({ user: req.user.id })
      .populate({
        path: "policy",
        populate: [
          { path: "category", select: "name" },
          { path: "subCategory", select: "name" },
        ],
      })
      .sort({ createdAt: -1 });

    console.log("✅ Policies found:", data.length);

    res.json(data);
  } catch (err) {
    console.error("❌ Error fetching policy history:");
    console.error(err);

    res.status(500).json({ message: "Failed to fetch policy history" });
  }
});

/* ==========================================
   USER → DISAPPROVE OWN POLICY
========================================== */
app.put("/my-policies/disapprove/:id", verifyUser, async (req, res) => {
  try {
    const policy = await UserPolicy.findOne({
      _id: req.params.id,
      user: req.user.id
    });

    if (!policy) {
      return res.status(404).json({ success: false, message: "Policy not found" });
    }

    policy.status = "disapproved";
    await policy.save();

    res.json({ success: true, message: "Policy disapproved successfully", policy });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to disapprove policy" });
  }
});

/* ==========================================
   USER → DELETE OWN POLICY
========================================== */
app.delete("/my-policies/delete/:id", verifyUser, async (req, res) => {
  try {
    const policy = await UserPolicy.findOne({
      _id: req.params.id,
      user: req.user.id
    });

    if (!policy) {
      return res.status(404).json({ success: false, message: "Policy not found" });
    }

    await UserPolicy.deleteOne({ _id: req.params.id });
    res.json({ success: true, message: "Policy deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to delete policy" });
  }
});

/* ==========================================
   USER → CREATE TICKET
========================================== */
app.post("/user/tickets", verifyUser, async (req, res) => {
  try {
    const { subject, message, category } = req.body;

    if (!subject || !message || !category) {
      return res.status(400).json({ message: "All fields required" });
    }

    const newTicket = await Ticket.create({
      user: req.user.id,
      subject,
      message,
      category,
      status: "open"
    });

    res.status(201).json({
      success: true,
      message: "Ticket created successfully",
      ticket: newTicket
    });

  } catch (error) {
    console.error("Ticket creation error:", error);
    res.status(500).json({ message: "Server error" });
  }
});


/* ==========================================
   USER → GET OWN TICKETS
========================================== */
app.get("/user/tickets", verifyUser, async (req, res) => {
  try {
    const tickets = await Ticket.find({ user: req.user.id })
      .sort({ createdAt: -1 });

    res.status(200).json(tickets);

  } catch (error) {
    console.error("Fetch tickets error:", error);
    res.status(500).json({ message: "Server error" });
  }
});









// Admin Part
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "All fields are required" });

  try {
    const admin = await Admin.findOne({ email });
    if (!admin)
      return res.status(401).json({ message: "Admin not authenticated" });

    const match = await bcrypt.compare(password, admin.password);
    if (!match)
      return res.status(401).json({ message: "Admin not authenticated" });

    // create JWT token
    const token = jwt.sign(
      { id: admin._id, role: "admin" },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // send cookie
    res.cookie("adminToken", token, {
      httpOnly: true,
      sameSite:"none",
      secure: true,
      maxAge: 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      success: true,
      message: "Admin logged in",
      admin: { name: admin.name, email: admin.email }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ------------------ VERIFY ADMIN ------------------
const verifyAdmin = (req, res, next) => {
  try {
    const token = req.cookies.adminToken;

    if (!token)
      return res.status(401).json({ message: "Admin not authenticated" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin")
      return res.status(403).json({ message: "Access denied" });

    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ------------------ ADMIN DASHBOARD ------------------
app.get("/admin/dashboard", verifyAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalPolicies = await mongoose.connection
      .collection("policies")
      .countDocuments();
    const openTickets = await mongoose.connection
      .collection("tickets")
      .countDocuments({ status: "open" });

    res.status(200).json({
      success: true,
      stats: { totalUsers, totalPolicies, openTickets }
    });
  } catch (error) {
    console.error("Admin Dashboard Error:", error);
    res.status(500).json({ message: "Failed to load admin dashboard" });
  }
});

app.get("/admin/profile", verifyAdmin, async (req, res) => {
  const admin = await Admin.findById(req.admin.id).select("name email");
  res.json({ admin });
});


// ADMIN CHANGE PASSWORD

app.put("/admin/change-password", verifyAdmin, async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    if (!oldPassword || !newPassword || !confirmPassword)
      return res.status(400).json({ message: "All fields are required" });

    if (newPassword.length < 8)
      return res.status(400).json({ message: "Password must be 8+ characters" });

    if (newPassword !== confirmPassword)
      return res.status(400).json({ message: "Passwords do not match" });

    // IMPORTANT because password has select:false
    const admin = await Admin.findById(req.admin.id).select("+password");

    const match = await bcrypt.compare(oldPassword, admin.password);
    if (!match)
      return res.status(400).json({ message: "Old password incorrect" });

    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();

    res.json({ success: true, message: "Password updated successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   ADD CATEGORY
========================= */
app.post("/admin/categories", verifyAdmin, async (req, res) => {
  try {
    let { name } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ message: "Category name is required" });
    }

    name = name.trim().toLowerCase();

    const exists = await Category.findOne({ name });

    if (exists) {
      return res.status(409).json({ message: "Category already exists" });
    }

    const category = await Category.create({ name });

    res.status(201).json(category);
  } catch (err) {
    res.status(500).json({ message: "Failed to add category" });
  }
});


/* =========================
   GET ALL CATEGORIES
========================= */
app.get("/admin/categories", verifyAdmin, async (req, res) => {
  try {
    const categories = await Category.find().sort({ createdAt: -1 });

    res.json(categories);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch categories" });
  }
});


/* =========================
   UPDATE CATEGORY
========================= */
app.put("/admin/categories/:id", verifyAdmin, async (req, res) => {
  try {
    let { name } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ message: "Category name is required" });
    }

    name = name.trim().toLowerCase();

    // prevent duplicate names
    const exists = await Category.findOne({
      name,
      _id: { $ne: req.params.id },
    });

    if (exists) {
      return res.status(409).json({ message: "Category already exists" });
    }

    const updated = await Category.findByIdAndUpdate(
      req.params.id,
      { name },
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: "Failed to update category" });
  }
});


/* =========================
   DELETE CATEGORY
========================= */
app.delete("/admin/categories/:id", verifyAdmin, async (req, res) => {
  try {
    const deleted = await Category.findByIdAndDelete(req.params.id);

    if (!deleted) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete category" });
  }
});

app.post("/admin/sub-categories", verifyAdmin, async (req, res) => {
  try {
    const { name, categoryId } = req.body;

    if (!name || !categoryId)
      return res.status(400).json({ message: "All fields required" });

    const exists = await SubCategory.findOne({
      name,
      category: categoryId,
    });

    if (exists)
      return res.status(409).json({ message: "Already exists" });

    const sub = await SubCategory.create({
      name,
      category: categoryId,
    });

    res.status(201).json(sub);
  } catch (err) {
    res.status(500).json({ message: "Failed to add" });
  }
});

app.get("/admin/sub-categories", verifyAdmin, async (req, res) => {
  const data = await SubCategory.find()
    .populate("category", "name")
    .sort({ createdAt: -1 });

  res.json(data);
});

app.put("/admin/sub-categories/:id", verifyAdmin, async (req, res) => {
  const { name } = req.body;

  const updated = await SubCategory.findByIdAndUpdate(
    req.params.id,
    { name },
    { new: true }
  );

  res.json(updated);
});

app.delete("/admin/sub-categories/:id", verifyAdmin, async (req, res) => {
  await SubCategory.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});


/* =========================
   ADD POLICY
========================= */
app.post("/admin/policies", verifyAdmin, async (req, res) => {
  try {
    const {
      category,
      subCategory,
      name,
      sumAssured,
      premium,
      tenure,
      details,
    } = req.body;

    const policy = await Policy.create({
      category,
      subCategory,
      name,

      // ⭐ FIX: convert to number
      sumAssured: Number(sumAssured),
      premium: Number(premium),
      tenure: Number(tenure),

      details,
    });

    res.status(201).json(policy);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to add policy" });
  }
});


/* =========================
   GET ALL POLICIES
========================= */
app.get("/admin/policies", verifyAdmin, async (req, res) => {
  try {
    const policies = await Policy.find()
      .populate("category", "name")
      .populate("subCategory", "name")
      .sort({ createdAt: -1 });

    res.json(policies);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch policies" });
  }
});


/* =========================
   GET SINGLE POLICY (EDIT)
========================= */
app.get("/admin/policies/:id", verifyAdmin, async (req, res) => {
  try {
    // ⭐ FIX: populate here also
    const policy = await Policy.findById(req.params.id)
      .populate("category", "name")
      .populate("subCategory", "name");

    res.json(policy);
  } catch {
    res.status(404).json({ message: "Policy not found" });
  }
});


/* =========================
   UPDATE POLICY
========================= */
app.put("/admin/policies/:id", verifyAdmin, async (req, res) => {
  try {
    const updated = await Policy.findByIdAndUpdate(
      req.params.id,
      {
        ...req.body,

        // ⭐ FIX: ensure numbers
        sumAssured: Number(req.body.sumAssured),
        premium: Number(req.body.premium),
        tenure: Number(req.body.tenure),
      },
      { new: true }
    );

    res.json(updated);
  } catch {
    res.status(500).json({ message: "Failed to update policy" });
  }
});


/* =========================
   DELETE POLICY
========================= */
app.delete("/admin/policies/:id", verifyAdmin, async (req, res) => {
  try {
    await Policy.findByIdAndDelete(req.params.id);

    res.json({ message: "Policy deleted successfully" });
  } catch {
    res.status(500).json({ message: "Failed to delete policy" });
  }
});

/* ======================================================
   ADMIN → GET ALL USERS
   Hide password for security
====================================================== */
app.get("/admin/users", verifyAdmin, async (req, res) => {
  try {
    const users = await User.find()
      .select("-password") // hide password
      .sort({ createdAt: -1 });

    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch users" });
  }
});


/* ======================================================
   ADMIN → UPDATE USER
   ❌ email + password cannot be changed
   ✅ only whitelist fields
====================================================== */
app.put("/admin/users/:id", verifyAdmin, async (req, res) => {
  try {
    const {
      name,
      number,
      gender,
      Date_of_Birth,
      role
    } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        name,
        number,
        gender,
        Date_of_Birth,
        role
      },
      { new: true }
    ).select("-password");

    if (!updatedUser)
      return res.status(404).json({ message: "User not found" });

    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ message: "Update failed" });
  }
});


/* ======================================================
   ADMIN → DELETE USER
====================================================== */
app.delete("/admin/users/:id", verifyAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);

    res.json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Delete failed" });
  }
});



app.get("/admin/policy-holders/pending", verifyAdmin, async (req, res) => {
  const data = await UserPolicy.find({ status: "pending" })
    .populate("user", "name email")
    .populate({
      path: "policy",
      populate: [
        { path: "category", select: "name" },
        { path: "subCategory", select: "name" },
      ],
    })
    .sort({ createdAt: -1 });

  res.json(data);
});

app.get("/admin/policy-holders/approved", verifyAdmin, async (req, res) => {
  const data = await UserPolicy.find({ status: "approved" })
    .populate("user", "name email")
    .populate("policy")
    .sort({ createdAt: -1 });

  res.json(data);
});

app.get("/admin/policy-holders/disapproved", verifyAdmin, async (req, res) => {
  const data = await UserPolicy.find({ status: "disapproved" })
    .populate("user", "name email")
    .populate("policy")
    .sort({ createdAt: -1 });

  res.json(data);
});

app.get("/admin/policy-holders/all", verifyAdmin, async (req, res) => {
  const data = await UserPolicy.find()
    .populate("user", "name email")
    .populate("policy")
    .sort({ createdAt: -1 });

  res.json(data);
});

app.put("/admin/policy-holders/approve/:id", verifyAdmin, async (req, res) => {
  const updated = await UserPolicy.findByIdAndUpdate(
    req.params.id,
    { status: "approved" },
    { new: true }
  );

  res.json({ message: "Policy approved", updated });
});

app.put("/admin/policy-holders/disapprove/:id", verifyAdmin, async (req, res) => {
  const updated = await UserPolicy.findByIdAndUpdate(
    req.params.id,
    { status: "disapproved" },
    { new: true }
  );

  res.json({ message: "Policy disapproved", updated });
});

app.get("/my-policies/history", verifyUser, async (req, res) => {
  try {
    const data = await UserPolicy.find({
      user: req.user.id
    })
    .populate("policy")
    .sort({ createdAt: -1 });

    res.json(data);
  } catch (err) {
    res.status(500).json({ message: "Failed" });
  }
});

app.get("/admin/tickets/open", verifyAdmin, async (req, res) => {
  try {
    const tickets = await Ticket.find({ status: "open" });

    console.log("Open tickets:", tickets);  // 🔥 ADD THIS

    res.json(tickets);

  } catch (err) {
    console.log("Admin fetch error:", err);
    res.status(500).json({ message: "Failed to fetch tickets" });
  }
});

app.get("/admin/tickets/unresolved", verifyAdmin, async (req, res) => {
  try {
    const tickets = await Ticket.find({ status: "open" })
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    res.status(200).json(tickets);
  } catch (err) {
    res.status(500).json({ message: "Error fetching tickets" });
  }
});

app.get("/admin/tickets/resolved", verifyAdmin, async (req, res) => {
  try {
    const tickets = await Ticket.find({ status: "resolved" })
      .populate("user", "name email")
      .sort({ createdAt: -1 });

    res.json(tickets);

  } catch (err) {
    res.status(500).json({ message: "Failed to fetch tickets" });
  }
});

app.put("/admin/tickets/:id/reply", verifyAdmin, async (req, res) => {
  try {
    const { reply } = req.body;

    if (!reply) {
      return res.status(400).json({ message: "Reply required" });
    }

    const updatedTicket = await Ticket.findByIdAndUpdate(
      req.params.id,
      {
        adminReply: reply,
        status: "resolved"
      },
      { new: true }
    );

    res.json(updatedTicket);

  } catch (err) {
    res.status(500).json({ message: "Failed to reply" });
  }
});

// ------------------ LOGOUT ------------------
app.get("/admin/logout", (req, res) => {
  res.clearCookie("adminToken", {
    httpOnly: true,
    sameSite: "lax",
    secure: false
  });

  res.status(200).json({ message: "Logged out successfully" });
});



const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`server is started on ${PORT}`);
});