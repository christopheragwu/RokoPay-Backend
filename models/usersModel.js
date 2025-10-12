const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    // ✅ Firebase UID (unique identifier)
    uid: {
      type: String,
      required: [true, "Firebase UID is required"],
      unique: true,
    },

    firstName: {
      type: String,
      required: [true, "First name is required"],
      trim: true,
      minlength: [2, "First name must be at least 2 characters long"],
    },

    lastName: {
      type: String,
      required: [true, "Last name is required"],
      trim: true,
      minlength: [2, "Last name must be at least 2 characters long"],
    },

    gender: {
      type: String,
      enum: ["Male", "Female", "Other"],
      required: [true, "Gender is required"],
    },

    dateOfBirth: {
      type: Date,
      required: [true, "Date of birth is required"],
    },

    phoneNumber: {
      type: String,
      required: [true, "Phone number is required"],
      unique: true,
      trim: true,
      match: [/^\+?[0-9]{7,15}$/, "Phone number must be valid"],
    },

    email: {
      type: String,
      required: [true, "Email is required"],
      trim: true,
      unique: true,
      minlength: [5, "Email must have at least 5 characters"],
      lowercase: true,
    },

    // ✅ Firebase handles password, so we no longer store it here
    password: {
      type: String,
      select: false,
    },

    // ✅ Sync status
    verified: {
      type: Boolean,
      default: false,
    },

    // Optional future fields
    createdAtFirebase: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
