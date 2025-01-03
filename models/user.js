import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { EMAIL_REGEX } from '../constants/index.js';

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please provide your first name'],
  },

  lastName: {
    type: String,
    required: [true, 'Please provide your last name'],
  },

  avatar: {
    type: String,
  },

  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    validate: {
      validator: function (email) {
        return String(email).toLowerCase().match(EMAIL_REGEX);
      },
      message: (props) => `${props.value} is not a valid email address`,
    },
  },

  password: {
    type: String,
  },

  passwordChangedAt: {
    type: Date,
  },

  passwordResetToken: {
    type: String,
  },

  passwordResetExpires: {
    type: Date,
  },

  createdAt: {
    type: Date,
    default: Date.now(),
  },

  updatedAt: {
    type: Date,
  },

  verified: {
    type: Boolean,
    default: false,
  },

  otp: {
    type: String,
    maxLength: 6,
  },

  otpExpiryTime: {
    type: Date,
  },
});

userSchema.pre('save', async function (next) {
  // Only run when the OTP is modified
  if (!this.isModified('otp') || !this.otp) return next();

  this.otp = await bcrypt.hash(this.otp, 12);
  next();
});

userSchema.pre('save', async function (next) {
  // Only run when the password is modified
  if (!this.isModified('password') || !this.password) return next();

  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.correctOTP = async function (
  candiateOTP, // OTP that user provides -> 123456
  userOTP // OTP that is stored in the database -> $2a$12$3
) {
  return await bcrypt.compare(candiateOTP, userOTP);
};

userSchema.methods.correctPassword = async function (
  candidatePassword, // password that user provides -> 123456
  userPassword // password that is stored in the database -> $2a$12$3
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  return resetToken;
};

userSchema.changedPasswordAfter = function (JWTTimestamp) {
  return JWTTimestamp < this.passwordChangedAt;
};

const User = new mongoose.model('User', userSchema);

export default User;
