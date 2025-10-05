const Joi = require("joi");

// Require at least 1 uppercase, minimum 6 chars, any characters allowed
const passwordPattern = /^(?=.*[A-Z]).{6,64}$/;

exports.signupSchema = Joi.object({
    firstName: Joi.string().min(2).max(50).required(),
    lastName: Joi.string().min(2).max(50).required(),
    gender: Joi.string().valid("Male", "Female", "Other").required(),
    dateOfBirth: Joi.date().iso().required(),
    phoneNumber: Joi.string()
        .pattern(/^\+?[0-9]{7,15}$/)
        .required()
        .messages({ "string.pattern.base": "Phone number must be valid" }),
    email: Joi.string().min(6).max(60).required().email({ tlds: { allow: false } }),
    password: Joi.string()
        .required()
        .pattern(passwordPattern)
        .messages({
            "string.pattern.base": "Password must be at least 6 characters and include at least 1 UPPERCASE letter"
        }),
});

exports.signinSchema = Joi.object({
    email: Joi.string().min(6).max(60).required().email({ tlds: { allow: false } }),
    password: Joi.string().required(),
});

exports.changePasswordSchema = Joi.object({
    oldPassword: Joi.string().required(),
    newPassword: Joi.string()
        .required()
        .pattern(passwordPattern)
        .messages({
            "string.pattern.base": "Password must be at least 6 characters and include at least 1 UPPERCASE letter"
        }),
});

exports.acceptFPCodeSchema = Joi.object({
    email: Joi.string().min(6).max(60).required().email({ tlds: { allow: false } }),
    providedCode: Joi.string().pattern(/^\d{6}$/).required(),
    newPassword: Joi.string()
        .required()
        .pattern(passwordPattern)
        .messages({
            "string.pattern.base": "Password must be at least 6 characters and include at least 1 UPPERCASE letter"
        }),
});
