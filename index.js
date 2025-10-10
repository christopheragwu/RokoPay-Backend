const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const authRouter = require("./routers/authRouter");

const app = express();

// ✅ Allowed frontend domains
const allowedOrigins = [
  "http://localhost:5173",
  "https://rokopay.xyz",
  "https://www.rokopay.xyz"  // ✅ in case Cloudflare adds www
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

app.use(cors(corsOptions));

// 🔐 Helmet for headers
app.use(helmet());

// 🍪 Cookies
app.use(cookieParser());

// 🧠 Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🔌 MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ Connected to MongoDB");
  })
  .catch((err) => {
    console.error("❌ MongoDB error:", err);
  });

// 📦 Routes
app.use("/api/auth", authRouter);

app.get("/", (req, res) => {
  res.json({ message: "Hello from the server" });
});

// 🚀 Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Listening on port ${PORT}...`);
});
