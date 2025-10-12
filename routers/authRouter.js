const express = require("express");
const authController = require("../controllers/authController");
const { identifier } = require("../middlewares/identification");
const { verifyFirebaseToken } = require("../middlewares/firebaseVerify"); // 🔒 middleware (to be added next)
const router = express.Router();

// ✅ Sync Firebase-authenticated users to MongoDB
router.post("/sync", verifyFirebaseToken, authController.syncFirebaseUser);

// 🔑 Classic Auth (Optional Legacy Flow)
router.post("/signup", authController.signup);
router.post("/signin", authController.signin);
router.post("/signout", identifier, authController.signout);

// ✉️ Email Verification
router.patch("/send-verification-code", authController.sendVerificationCode);
router.patch("/verify-verification-code", authController.verifyVerificationCode);

// 🔐 Password Management
router.patch("/change-password", identifier, authController.changePassword);
router.patch("/send-forgot-password-code", authController.sendForgotPasswordCode);
router.patch("/verify-forgot-password-code", authController.verifyForgotPasswordCode);

module.exports = router;
