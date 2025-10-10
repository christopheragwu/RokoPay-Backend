const express = require("express")
const authController = require("../controllers/authController")
const { identifier } = require("../middlewares/identification")
const router = express.Router();

// Auth flows
router.post("/signup", authController.signup);
router.post("/signin", authController.signin);
router.get("/me", authController.getMe);
router.post("/signout", identifier, authController.signout);

// Email verification
router.patch("/send-verification-code", authController.sendVerificationCode);
router.patch("/verify-verification-code", authController.verifyVerificationCode);

// Password management
router.patch("/change-password", identifier, authController.changePassword);
router.patch("/send-forgot-password-code", authController.sendForgotPasswordCode);
router.patch("/verify-forgot-password-code", authController.verifyForgotPasswordCode);



module.exports = router;