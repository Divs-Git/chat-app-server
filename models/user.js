import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { EMAIL_REGEX } from '../constants/index.js';

const userSchema = new mongoose.Schema({
  first_name: {
    type: String,
    required: [true, 'Please provide your first name'],
  },

  last_name: {
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
    required: [true, 'Please provide a password'],
    minlength: 8,
  },

  confirmPassword: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function (confirmPassword) {
        return confirmPassword === this.password;
      },
      message: 'Passwords do not match',
    },
  },

  password_changed_at: {
    type: Date,
  },

  password_reset_token: {
    type: String,
  },

  password_reset_expires: {
    type: Date,
  },

  created_at: {
    type: Date,
    default: Date.now(),
  },

  updated_at: {
    type: Date,
  },

  verified: {
    type: Boolean,
    default: false,
  },

  otp: {
    type: Number,
    maxLength: 6,
  },

  otp_expiry_time: {
    type: Date,
  },
});

userSchema.pre('save', async function (next) {
  // Only run when the OTP is modified
  if (!this.isModified('otp')) return next();

  this.otp = await bcrypt.hash(this.otp, 12);

  next();
});

userSchema.pre('save', async function (next) {
  // Only run when the Password is modified
  if (!this.isModified('password')) return next();

  this.otp = await bcrypt.hash(this.otp, 12);

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
  const resetPasswordToken = crypto.randomBytes(32).toString('hex');

  this.password_reset_token = crypto
    .createHash('sha256')
    .update(resetPasswordToken)
    .digest('hex');

  this.password_reset_expires = Date.now() + 10 * 60 * 1000; // 10 minutes

  return resetPasswordToken;
};

userSchema.changedPasswordAfter = function (JWTTimestamp) {
  return JWTTimestamp < this.password_changed_at;
};

const User = new mongoose.model('User', userSchema);

export default User;
