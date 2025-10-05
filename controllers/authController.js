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
    // ✅ Validate request body
    const { error } = signinSchema.validate({ email, password });
    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    // ✅ Look up user
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

    // ✅ Check if user verified
    if (!existingUser.verified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in.",
      });
    }

    // ✅ Create JWT
    const token = jwt.sign(
      {
        userId: existingUser._id,
        email: existingUser.email,
        verified: existingUser.verified,
      },
      process.env.TOKEN_SECRET,
      { expiresIn: "8h" }
    );

    // ✅ Build safe user object (no password)
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

    // ✅ Send cookie + response
    res
      .cookie("Authorization", "Bearer " + token, {
        expires: new Date(Date.now() + 8 * 3600000), // 8h
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
      })
      .json({
        success: true,
        token,
        user, // 👈 full user details for frontend Zustand
        message: "Logged in successfully",
      });
  } catch (error) {
    console.error("Signin error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

exports.getMe = async (req, res) => {
  try {
    const token = req.cookies.Authorization?.split(" ")[1];
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

    res.json({ success: true, user });
  } catch (error) {
    console.error("GetMe error:", error);
    res
      .status(401)
      .json({ success: false, message: "Invalid or expired token" });
  }
};

exports.signout = async (req, res) => {
  res
    .clearCookie("Authorization", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    })
    .status(200)
    .json({ success: true, message: "Logged out successfully." });
};

exports.sendVerificationCode = async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      return res
        .status(404)
        .json({ success: false, message: "User does not exists!" });
    }
    if (existingUser.verified) {
      return res
        .status(400)
        .json({ success: false, message: "You are already verified" });
    }

    const codeValue = Math.floor(Math.random() * 1000000).toString();
    let info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: existingUser.email,
      subject: "RokoPay Account Verification Code",
      html: "<h1>" + codeValue + "</h1>",
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );
      existingUser.verificationCode = hashedCodeValue;
      existingUser.verificationCodeValidation = Date.now();
      await existingUser.save();
      return res.status(200).json({ success: true, message: "Code sent!" });
    }
    res.status(400).json({ success: false, message: "code sent failed" });
  } catch (error) {
    console.log(error);
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

    const codeValue = Math.floor(Math.random() * 1000000).toString();
    let info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: existingUser.email,
      subject: "RokoPay Forgot Password Code",
      html: "<h1>" + codeValue + "</h1>",
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
