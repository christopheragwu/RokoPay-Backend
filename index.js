const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const authRouter = require("./routers/authRouter");

const app = express();

// ✅ Allowed frontend domains
const allowedOrigins = [
  "http://localhost:5173",     // Local dev
  "https://rokopay.xyz"        // Your live frontend on cPanel
];

// ✅ CORS config
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};

// 🧠 IMPORTANT: CORS must be first
app.use(cors(corsOptions));

// ✅ FIX: Preflight (OPTIONS) handler — new format
app.options("/*", cors(corsOptions));

// 🔐 Helmet for security headers
app.use(helmet());

// 🍪 Cookie parser
app.use(cookieParser());

// 📦 Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🔌 Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ Connected to MongoDB");
  })
  .catch((err) => {
    console.error("❌ MongoDB error:", err);
  });

// 🛣️ Routes
app.use("/api/auth", authRouter);

// 🏠 Default route
app.get("/", (req, res) => {
  res.json({ message: "Hello from the server" });
});

// 🚀 Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Listening on port ${PORT}...`);
});
