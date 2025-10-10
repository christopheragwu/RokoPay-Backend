const jwt = require("jsonwebtoken");
const {
  signupSchema,
  signinSchema,
  acceptCodeSchema,
  changePasswordSchema,
  acceptFPCodeSchema,
} = require("../middlewares/validator");
const User = require("../models/usersModel");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashing");
const transport = require("../middlewares/sendMail");

exports.signup = async (req, res) => {
  const {
    firstName,
    lastName,
    gender,
    dateOfBirth,
    phoneNumber,
    email,
    password,
  } = req.body;

  try {
    // ✅ validate input
    const { error } = signupSchema.validate({
      firstName,
      lastName,
      gender,
      dateOfBirth,
      phoneNumber,
      email,
      password,
    });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    // ✅ check duplicates
    if (await User.findOne({ email })) {
      return res
        .status(401)
        .json({ success: false, message: "User already exists!" });
    }
    if (await User.findOne({ phoneNumber })) {
      return res
        .status(401)
        .json({ success: false, message: "Phone number already in use!" });
    }

    // ✅ hash password
    const hashedPassword = await doHash(password, 12);

    const newUser = new User({
      firstName,
      lastName,
      gender,
      dateOfBirth,
      phoneNumber,
      email,
      password: hashedPassword,
    });

    const result = await newUser.save();

    // ✅ generate a guaranteed 6-digit OTP
    const codeValue = Math.floor(100000 + Math.random() * 900000).toString();

    try {
      // ✅ send verification email
      const info = await transport.sendMail({
        from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
        to: result.email,
        subject: "RokoPay Account Verification Code",
        html: `<h1>${codeValue}</h1>`,
      });

      if (info.accepted.includes(result.email)) {
        const hashedCodeValue = hmacProcess(
          codeValue,
          process.env.HMAC_VERIFICATION_CODE_SECRET
        );
        result.verificationCode = hashedCodeValue;
        result.verificationCodeValidation = Date.now();
        await result.save();
      }
    } catch (mailErr) {
      console.error("Email sending failed:", mailErr.message);
    }

    // ✅ always respond cleanly
    return res.status(201).json({
      success: true,
      message: "Account created successfully. Please verify your email.",
      email: result.email,
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

exports.signin = async (req, res) => {
  const { email, password } = req.body;

  try {
    // ✅ Validate input
    const { error } = signinSchema.validate({ email, password });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    // ✅ Find user
    const existingUser = await User.findOne({ email }).select("+password");
    if (!existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User does not exist!" });
    }

    // ✅ Validate password
    const isValidPassword = await doHashValidation(
      password,
      existingUser.password
    );
    if (!isValidPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    // ✅ Check email verification
    if (!existingUser.verified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in.",
      });
    }

    // ✅ Create JWT (longer lifespan for persistent login)
    const token = jwt.sign(
      {
        userId: existingUser._id,
        email: existingUser.email,
        verified: existingUser.verified,
      },
      process.env.TOKEN_SECRET,
      { expiresIn: "7d" } // 🔁 7 days token validity
    );

    // ✅ Remove sensitive info
    const user = {
      id: existingUser._id,
      firstName: existingUser.firstName,
      lastName: existingUser.lastName,
      email: existingUser.email,
      phoneNumber: existingUser.phoneNumber,
      gender: existingUser.gender,
      dateOfBirth: existingUser.dateOfBirth,
      verified: existingUser.verified,
    };

    // ✅ Set secure cookie (without "Bearer")
    res
      .cookie("Authorization", token, {
        httpOnly: true,
        secure: true, // ✅ Always true in production (HTTPS is required)
        sameSite: "none", // ✅ Needed for frontend & backend on different domains
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      })

      .json({
        success: true,
        token,
        user,
        message: "Logged in successfully",
      });
  } catch (error) {
    console.error("Signin error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

exports.getMe = async (req, res) => {
  try {
    // ✅ FIX: Don't split — cookie already contains just the token
    const token = req.cookies.Authorization;

    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Not authorized" });
    }

    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);

    const user = await User.findById(decoded.userId).select(
      "firstName lastName email phoneNumber gender dateOfBirth verified"
    );

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, user });
  } catch (error) {
    console.error("GetMe error:", error);
    res
      .status(401)
      .json({ success: false, message: "Invalid or expired token" });
  }
};

exports.signout = async (req, res) => {
  try {
    // Check if the cookie exists first (optional but safe)
    const token = req.cookies.Authorization;

    if (!token) {
      return res.status(200).json({
        success: true,
        message: "No active session found. Already logged out.",
      });
    }

    // ✅ Clear the cookie
    res.clearCookie("Authorization", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // only HTTPS in production
      sameSite: "strict", // or 'lax' if needed for cross-site
    });

    return res.status(200).json({
      success: true,
      message: "Logged out successfully.",
    });
  } catch (error) {
    console.error("Signout error:", error);
    return res.status(500).json({
      success: false,
      message: "Logout failed. Please try again.",
    });
  }
};

exports.sendVerificationCode = async (req, res) => {
  const { email } = req.body;

  try {
    // 1. Check if user exists
    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User does not exist!",
      });
    }

    // 2. Check if already verified
    if (existingUser.verified) {
      return res.status(400).json({
        success: false,
        message: "You are already verified.",
      });
    }

    // 3. Generate verification code
    const codeValue = Math.floor(100000 + Math.random() * 900000).toString(); // Always 6-digit

    // 4. Send email using SendGrid
    const info = await transport.sendMail({
      from: '"RokoPay" <no-reply@rokopay.xyz>', // ✅ Use your authenticated domain
      to: existingUser.email,
      subject: "RokoPay Verification Code",
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.5;">
          <h2>Welcome to RokoPay 👋</h2>
          <p>Your account verification code is:</p>
          <h1 style="background: #f0f0f0; display: inline-block; padding: 10px 20px; border-radius: 8px;">
            ${codeValue}
          </h1>
          <p>This code will expire shortly. Do not share it with anyone.</p>
        </div>
      `,
    });

    // 5. Confirm delivery
    if (info.accepted.includes(existingUser.email)) {
      const hashedCode = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );

      existingUser.verificationCode = hashedCode;
      existingUser.verificationCodeValidation = Date.now();
      await existingUser.save();

      return res.status(200).json({
        success: true,
        message: "Verification code sent!",
      });
    }

    // 6. Email not accepted
    return res.status(400).json({
      success: false,
      message: "Failed to send verification code. Please try again.",
    });
  } catch (error) {
    console.error("❌ Error sending verification email:", error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong while sending verification code.",
    });
  }
};

exports.verifyVerificationCode = async (req, res) => {
  const { email, providedCode } = req.body;

  try {
    // 1. Find the user by email
    const user = await User.findOne({ email }).select(
      "+verificationCode +verificationCodeValidation"
    );

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // 2. Ensure a code exists
    if (!user.verificationCode || !user.verificationCodeValidation) {
      return res.status(400).json({
        success: false,
        message: "No verification code found. Please request a new one.",
      });
    }

    // 3. Check expiry (e.g., 10 minutes)
    const TEN_MINUTES = 10 * 60 * 1000;
    if (Date.now() - user.verificationCodeValidation > TEN_MINUTES) {
      return res.status(400).json({
        success: false,
        message: "Verification code expired. Please request a new one.",
      });
    }

    // 4. Hash provided code
    const hashedProvided = hmacProcess(
      providedCode,
      process.env.HMAC_VERIFICATION_CODE_SECRET
    );

    // 5. Compare codes
    if (hashedProvided !== user.verificationCode) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid verification code." });
    }

    // 6. Mark user as verified
    user.verified = true;
    user.verificationCode = undefined; // clear code
    user.verificationCodeValidation = undefined; // clear timestamp
    await user.save();

    return res.json({
      success: true,
      message: "Email verified successfully!",
      email: user.email,
    });
  } catch (err) {
    console.error("verifyVerificationCode error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

exports.changePassword = async (req, res) => {
  const { userId, verified } = req.user;
  const { oldPassword, newPassword } = req.body;

  try {
    const { error, value } = changePasswordSchema.validate({
      oldPassword,
      newPassword,
    });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    if (!verified) {
      return res
        .status(401)
        .json({ success: false, message: "You are not a verified user" });
    }

    const existingUser = await User.findOne({ _id: userId }).select(
      "+password"
    );
    if (!existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User does not exist!" });
    }

    const result = await doHashValidation(oldPassword, existingUser.password);
    if (!result) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid Credentials" });
    }

    const hashedPassword = await doHash(newPassword, 12);
    existingUser.password = hashedPassword; // ✅ fixed assignment
    await existingUser.save();

    return res
      .status(200)
      .json({ success: true, message: "Password Updated." });
  } catch (error) {
    console.log(error);
  }
};

exports.sendForgotPasswordCode = async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      return res
        .status(404)
        .json({ success: false, message: "User does not exists!" });
    }

    const codeValue = Math.floor(Math.random() * 1000000)
      .toString()
      .padStart(6, "0");

    let info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: existingUser.email,
      subject: "RokoPay Forgot Password Code",
      html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 8px;">
              <h2 style="color: #e63946;">RokoPay Password Reset</h2>
              <p>Hello,</p>
              <p>You requested to reset your password. Use the code below to proceed:</p>
          
              <div style="font-size: 24px; font-weight: bold; color: #333; background: #ffffff; padding: 10px 20px; border-radius: 6px; display: inline-block; margin: 20px 0;">
                ${codeValue}
              </div>

            <p>This code is valid for 5 minutes.</p>
            <p>If you didn't request a password reset, please ignore this email.</p>

            <hr style="margin: 30px 0;" />

            <p style="font-size: 12px; color: #777;">
            Need help? Contact our support team at <a href="mailto:support@rokopay.xyz">support@rokopay.xyz</a>.
            </p>
          </div>
        `,
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );
      existingUser.forgotPasswordCode = hashedCodeValue;
      existingUser.forgotPasswordCodeValidation = Date.now();
      await existingUser.save();
      return res.status(200).json({ success: true, message: "Code sent!" });
    }
    res.status(400).json({ success: false, message: "code sent failed" });
  } catch (error) {
    console.log(error);
  }
};

exports.verifyForgotPasswordCode = async (req, res) => {
  const { email, providedCode, newPassword } = req.body;

  try {
    const { error, value } = acceptFPCodeSchema.validate({
      email,
      providedCode,
      newPassword,
    });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    const codeValue = providedCode.toString();
    const existingUser = await User.findOne({ email }).select(
      "+forgotPasswordCode + forgotPasswordCodeValidation"
    );

    if (!existingUser) {
      return res
        .status(404)
        .json({ success: false, message: "User does not exists!" });
    }

    if (
      !existingUser.forgotPasswordCode ||
      !existingUser.forgotPasswordCodeValidation
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Something is wrong with the code!" });
    }

    if (
      Date.now() - existingUser.forgotPasswordCodeValidation >
      5 * 60 * 1000
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Code has been expired!" });
    }

    const hashedCodeValue = hmacProcess(
      codeValue,
      process.env.HMAC_VERIFICATION_CODE_SECRET
    );

    if (hashedCodeValue === existingUser.forgotPasswordCode) {
      existingUser.forgotPasswordCode = undefined;
      existingUser.forgotPasswordCodeValidation = undefined;
      await existingUser.save();

      const hashedNewPassword = await doHash(newPassword, 12);
      existingUser.password = hashedNewPassword;
      existingUser.forgotPasswordCode = undefined;
      existingUser.forgotPasswordCodeValidation = undefined;
      await existingUser.save();

      return res
        .status(200)
        .json({ success: true, message: "Password Updated!" });
    }

    return res
      .status(400)
      .json({ success: false, message: "Unexpected error" });
  } catch (error) {
    console.log(error);
  }
};
