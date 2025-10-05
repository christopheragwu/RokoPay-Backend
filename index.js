const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const authRouter = require("./routers/authRouter");

const app = express();

// ✅ Configure allowed origins
const allowedOrigins = [
  "http://localhost:5173",              // frontend in dev
  "https://your-production-domain.com"  // replace with prod frontend
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow requests with no origin (like Postman)
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // ✅ allow cookies (JWT)
  })
);

app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Database
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Database connected...");
  })
  .catch((err) => {
    console.log(err);
  });

// ✅ Routes
app.use("/api/auth", authRouter);
app.get("/", (req, res) => {
  res.json({ message: "Hello from the server" });
});

app.listen(process.env.PORT, () => {
  console.log(`Listening on port ${process.env.PORT}...`);
});
