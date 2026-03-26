const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const path = require("path");
const crypto = require("crypto");
const { promisify } = require("util");

const Order = require("./models/Order");
const User = require("./models/User");
const ChatMessage = require("./models/ChatMessage");

require("./config/passport");

const app = express();
const scryptAsync = promisify(crypto.scrypt);

const chatStreams = [];

function streamChatMessage(message) {
  const payload = {
    userId: String(message.user),
    sender: message.sender,
    text: message.text,
    createdAt: message.createdAt
  };
  chatStreams.forEach(entry => {
    if(entry.isAdmin || entry.userId === payload.userId) {
      try {
        entry.res.write(`data: ${JSON.stringify(payload)}\n\n`);
      } catch (err) {
        console.log("SSE write error", err);
      }
    }
  });
}

function registerChatStream(req, res, { userId, isAdmin }) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive"
  });
  res.write("\n");
  if(typeof res.flushHeaders === "function"){
    res.flushHeaders();
  }

  const entry = { res, userId: userId ? String(userId) : null, isAdmin };
  chatStreams.push(entry);

  req.on("close", () => {
    const index = chatStreams.indexOf(entry);
    if(index !== -1) {
      chatStreams.splice(index, 1);
    }
  });
}

function normalizeEmail(email = "") {
  return String(email || "").trim().toLowerCase();
}

function isAdminCredentials(email, password) {
  const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
  const adminPassword = process.env.ADMIN_PASSWORD || "";
  return email === adminEmail && password === adminPassword;
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const key = await scryptAsync(password, salt, 64);
  return {
    salt,
    hash: key.toString("hex")
  };
}

async function verifyPassword(password, salt, hash) {
  if (!salt || !hash) return false;
  const { hash: derived } = await hashPassword(password, salt);
  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(derived, "hex")
  );
}

function serializeAuthUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    fullName: user.fullName || user.name || "",
    email: user.email,
    address: user.address || "",
    role: user.role || "user"
  };
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Authentication required" });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(401).json({ error: "Admin login required" });
  }

  next();
}

/* ================= DATABASE ================= */

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log("MongoDB Error:", err));

/* ================= MIDDLEWARE ================= */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "burriSecret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, "public")));

/* ================= GOOGLE AUTH ================= */

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {

    console.log("User logged in:", req.user.email);

    res.redirect("/");
 }
);

app.get("/auth/me", (req, res) => {
  const user = serializeAuthUser(req.user);
  res.json({ user });
});

app.post("/auth/register", async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const email = normalizeEmail(req.body.email);
    const address = String(req.body.address || "").trim();
    const password = String(req.body.password || "");

    if (!fullName || !email || !address || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: "Email is already registered" });
    }

    const { salt, hash } = await hashPassword(password);
    const role = isAdminCredentials(email, password) ? "admin" : "user";

    const user = await User.create({
      fullName,
      email,
      address,
      passwordHash: hash,
      passwordSalt: salt,
      role
    });

    req.login(user, (error) => {
      if (error) {
        console.log("Registration login error:", error);
        return res.status(500).json({ error: "Failed to start session" });
      }

      return res.status(201).json({ user: serializeAuthUser(user) });
    });
  } catch (error) {
    console.log("Register error:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const adminLogin = isAdminCredentials(email, password);
    let user = await User.findOne({ email });

    if (!user && adminLogin) {
      const { salt, hash } = await hashPassword(password);
      user = await User.create({
        fullName: "Admin",
        email,
        address: "",
        passwordHash: hash,
        passwordSalt: salt,
        role: "admin"
      });
    }

    if (!user || !user.passwordHash || !user.passwordSalt) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const passwordOk = await verifyPassword(password, user.passwordSalt, user.passwordHash);
    if (!passwordOk) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    if (adminLogin && user.role !== "admin") {
      user.role = "admin";
      await user.save();
    }

    req.login(user, (error) => {
      if (error) {
        console.log("Login session error:", error);
        return res.status(500).json({ error: "Failed to start session" });
      }

      return res.json({ user: serializeAuthUser(user) });
    });
  } catch (error) {
    console.log("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/auth/logout", (req, res) => {
  req.logout((error) => {
    if (error) {
      return res.status(500).json({ error: "Logout failed" });
    }

    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.json({ ok: true });
    });
  });
});

app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).lean();
    res.json({ orders });
  } catch (error) {
    console.log("Admin orders error:", error);
    res.status(500).json({ error: "Failed to load orders" });
  }
});

/* ================= PAGE ROUTE ================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

/* ================= SAVE ORDER ================= */

/* ================= SUBMIT ORDER ================= */

app.post("/submit-order", async (req, res) => {

  try {

    console.log("DATA RECEIVED:", req.body);

    const newOrder = new Order({
      fullName: req.body.fullName,
       email: normalizeEmail(req.body.email),
      address: req.body.address,
    items: Array.isArray(req.body.items) ? req.body.items : [],
    total: Number(req.body.total) || 0,
    referenceImage: typeof req.body.referenceImage === "string" ? req.body.referenceImage : null
  });

    await newOrder.save();

    console.log("Order saved:", newOrder);

    res.json({ message: "Order saved successfully" });

  } catch (error) {

    console.log("Save error:", error);
    res.status(500).json({ error: "Failed to save order" });

  }

});

app.post("/api/chat/messages", requireAuth, async (req, res) => {
  try {
    const text = String(req.body.text || "").trim();
    if (!text) {
      return res.status(400).json({ error: "Message text required" });
    }

    const userId = req.user._id;

    const message = await ChatMessage.create({
      user: userId,
      sender: "user",
      text
    });

    const autoReply = await ChatMessage.create({
      user: userId,
      sender: "auto",
      text: "Thanks for the update! Our shopper will reply shortly."
    });

    streamChatMessage(message);
    streamChatMessage(autoReply);

    res.json({ message, autoReply });
  } catch (error) {
    console.log("Chat post error:", error);
    res.status(500).json({ error: "Failed to send message" });
  }
});

app.get("/api/chat/messages", requireAuth, async (req, res) => {
  try {
    const messages = await ChatMessage.find({ user: req.user._id })
      .sort({ createdAt: 1 })
      .lean();
    res.json({ messages });
  } catch (error) {
    console.log("Chat fetch error:", error);
    res.status(500).json({ error: "Failed to load chat" });
  }
});

app.get("/api/chat/stream", requireAuth, (req, res) => {
  registerChatStream(req, res, { userId: req.user._id, isAdmin: false });
});

app.get("/api/chat/stream/admin", requireAdmin, (req, res) => {
  registerChatStream(req, res, { userId: null, isAdmin: true });
});

app.get("/api/chat/users", requireAdmin, async (req, res) => {
  try {
    const messages = await ChatMessage.find()
      .sort({ createdAt: -1 })
      .populate("user", "fullName email")
      .lean();

    const summaries = [];
    const seen = new Set();

    for (const message of messages) {
      const user = message.user;
      if (!user || seen.has(String(user._id))) continue;
      seen.add(String(user._id));
      summaries.push({
        userId: String(user._id),
        fullName: user.fullName || user.email,
        email: user.email,
        lastMessage: message.text,
        lastSender: message.sender,
        lastAt: message.createdAt
      });
    }

    res.json({ users: summaries });
  } catch (error) {
    console.log("Chat users error:", error);
    res.status(500).json({ error: "Failed to load chat users" });
  }
});

app.get("/api/chat/user/:userId/messages", requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const messages = await ChatMessage.find({ user: userId })
      .sort({ createdAt: 1 })
      .lean();

    res.json({ messages });
  } catch (error) {
    console.log("Chat user fetch error:", error);
    res.status(500).json({ error: "Failed to load chat for user" });
  }
});

app.post("/api/chat/reply", requireAdmin, async (req, res) => {
  try {
    const { userId, text } = req.body;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    const reply = String(text || "").trim();
    if (!reply) {
      return res.status(400).json({ error: "Reply text required" });
    }

    const message = await ChatMessage.create({
      user: userId,
      sender: "admin",
      text: reply
    });

    streamChatMessage(message);

    res.json({ message });
  } catch (error) {
    console.log("Chat reply error:", error);
    res.status(500).json({ error: "Failed to save reply" });
  }
});

/* ================= SAVE USER ================= */

app.post("/save-user", async (req, res) => {

  try {

    const newUser = new User({
      fullName: req.body.fullName,
      email: normalizeEmail(req.body.email),
      address: req.body.address
    });

    await newUser.save();

    console.log("User saved:", newUser);

    res.json({ message: "User saved" });

  } catch (error) {

    console.log("User save error:", error);
    res.status(500).json({ error: "Failed to save user" });

  }

});

/* ================= LOGOUT ================= */

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
