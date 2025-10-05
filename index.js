const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const authRouter = require("./routers/authRouter");

const app = express();

// ✅ Allowed frontend domains
const allowedOrigins = [
  "http://localhost:5173",     // local dev
  "https://rokopay.xyz"        // your frontend on cPanel
];

// ✅ Setup CORS - must be first middleware
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

app.use(cors(corsOptions));

// ✅ Handle preflight requests (OPTIONS)
app.options("*", cors(corsOptions));

// 🔐 Secure HTTP headers
app.use(helmet());

// 🍪 Cookie support
app.use(cookieParser());

// 📦 Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🛢️ Connect to MongoDB
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

app.get("/", (req, res) => {
  res.json({ message: "Hello from the server" });
});

// 🚀 Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Listening on port ${PORT}...`);
});
