const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
    firstName: {
        type: String,
        required: [true, "First name is required"],
        trim: true,
        minLength: [2, "First name must be at least 2 characters long"],
    },
    lastName: {
        type: String,
        required: [true, "Last name is required"],
        trim: true,
        minLength: [2, "Last name must be at least 2 characters long"],
    },
    gender: {
        type: String,
        enum: ["Male", "Female", "Other"], // limits allowed values
        required: [true, "Gender is required"],
    },
    dateOfBirth: {
        type: Date,
        required: [true, "Date of birth is required"],
    },
    phoneNumber: {
        type: String,
        required: [true, "Phone number is required"],
        unique: [true, "Phone number must be unique"],
        trim: true,
        match: [/^\+?[0-9]{7,15}$/, "Phone number must be valid"], 
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        trim: true,
        unique: [true, "Email must be unique"],
        minLength: [5, "Email must have 5 characters!"],
        lowercase: true,
    },
    password: {
        type: String,
        required: [true, "Password must be provided!"],
        trim: true,
        select: false,
    },
    verified: {
        type: Boolean,
        default: false,
    },
    verificationCode: {
        type: String,
        select: false,
    },
    verificationCodeValidation: {
        type: Number,
        select: false,
    },
    forgotPasswordCode: {
        type: String,
        select: false,
    },
    forgotPasswordCodeValidation: {
        type: Number,
        select: false,
    },
}, {
    timestamps: true
});

module.exports = mongoose.model("User", userSchema);
