import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import filterObj from '../utils/filterObject.js';
import crypto from 'crypto';
import otpGenerator from 'otp-generator';
import { promisify } from 'util';
import mailService from '../services/mailer.js';
import dotenv from 'dotenv';

dotenv.config({ path: '../config.env' });

function signToken(user_id) {
  jwt.sign(
    {
      user_id,
    },
    process.env.JWT_SECRET
  );
}

export const register = async (req, res, next) => {
  const { firstName, lastName, email, password, verified } = req.body;

  // Check if the verified user already exists with the provided email
  const existing_user = await User.findOne({ email });

  const filteredBody = filterObj(
    req.body,
    'firstName',
    'lastName',
    'email',
    'password'
  );

  // If the user exists and is verified, return an error
  if (existing_user && existing_user.verified) {
    return res.status(400).json({
      status: 'error',
      message: 'Email already in use, please login',
    });
  }

  // If the user exists but is not verified, update the user's information
  else if (existing_user) {
    await User.findOneAndUpdate({ email }, filteredBody, {
      new: true,
      validateModifiedOnly: true,
    });

    // generate OTP and send it to the user
    req.user_id = existing_user._id;
    next();
  }

  // If the user does not exist, create a new user
  else {
    const new_user = User.create(filteredBody);

    // generate OTP and send it to the user
    req.user_id = new_user._id;
    next();
  }
};

export const sendOTP = async (req, res, next) => {
  const { user_id } = req;
  const new_otp = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  const otp_expiry_time = Date.now() + 10 * 60 * 1000; // 10 minutes

  await User.findByIdAndUpdate(user_id, {
    otp: new_otp,
    otp_expiry_time,
  });

  // TODO: Send the OTP to the user via email
  mailService
    .sendEmail({
      from: 'divyansh.sri258@gmail.com',
      to: 'example@gmail.com',
      subject: 'OTP for Chatr',
      text: `Your OTP for Chatr is ${new_otp}. It will expire in 10 minutes`,
    })
    .then(() => {
      res.status(200).json({
        status: 'success',
        message: 'OTP sent successfully',
      });
    })
    .catch((error) => {
      return res.status(500).json({
        status: 'error',
        message: 'There was an error sending the OTP. Try again later',
      });
    });
};

export const verifyOTP = async (req, res, next) => {
  // Verify the OTP and update the user's verified status
  const { email, otp } = req.body;

  const user = User.findOne({ email, otp_expiry_time: { $gt: Date.now() } }); // Check if the OTP is still valid

  if (!user) {
    return res.status(400).json({
      status: 'error',
      message: 'Email is invalid or OTP has expired',
    });
  }

  if (!(await user.correctOTP(otp, user.otp))) {
    return res.status(400).json({
      status: 'error',
      message: 'Incorrect OTP',
    });
  }

  // OTP is correct, update the user's verified status
  user.verified = true;
  user.otp = undefined;

  await user.save({ new: true, validateModifiedOnly: true });

  const token = signToken(user._id);

  res.status(200).json({
    status: 'success',
    message: 'OTP verified successfully',
    token,
  });
};

export const login = async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: 'Please provide email and password' });
  }

  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return res.status(401).json({
      status: 'error',
      message: 'Incorrect email or password',
    });
  }

  const token = signToken(user._id);

  res.status(200).json({
    status: 'success',
    message: 'Logged in successfully',
    token,
  });
};

/**
 * Types of routes:
 * 1. Protected routes -> require the user to be logged in
 * 2. Unprotected routes
 */

export const protect = async (req, res, next) => {
  // 1. Get the JWT token and check if it exists
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    return res.status(401).json({
      status: 'error',
      message: 'You are not logged in. Please log in to get access',
    });
  }

  // 2. Verify the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3. Check if the user still exists
  const current_user = await User.findById(decoded.user_id);

  if (!current_user) {
    return res.status(401).json({
      status: 'error',
      message: 'The user no longer exist',
    });
  }

  // 4. Check if the user changed the password after the token was issued
  // iat -> issued at
  if (current_user.changedPasswordAfter(decoded.iat)) {
    return res.status(401).json({
      status: 'error',
      message: 'User recently changed password! Please log in again',
    });
  }

  // 5. Grant access to the protected route
  req.user = current_user;
  next();
};

export const forgotPassword = async (req, res, next) => {
  // Find the user with the provided email
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return res.status(404).json({
      status: 'error',
      message: 'User not found',
    });
  }

  // Generate a password reset token
  const resetToken = user.createPasswordResetToken();

  const resetURL = `https://chatr.com/resetPassword/?code=${resetToken}`;

  try {
    // TODO: Send the resetURL to the user via email

    res.status(200).json({
      status: 'success',
      message: 'Reset token sent to email',
    });
  } catch (error) {
    user.password_reset_token = undefined;
    user.password_reset_expires = undefined;

    await user.save({ validateBeforeSave: false });

    res.status(500).json({
      status: 'error',
      message: 'There was an error sending the email. Try again later!',
    });
  }
};

export const resetPassword = async (req, res, next) => {
  // Find the user with the provided reset token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    password_reset_token: hashedToken,
    password_reset_expires: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({
      status: 'error',
      message: 'Token is invalid or has expired',
    });

    return;
  }

  // Update the user's password
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.password_reset_token = undefined;
  user.password_reset_expires = undefined;

  await user.save();

  // Log the user in and send a JWT

  // TODO: Send the user a confirmation email that their password has been changed

  const token = signToken(user._id);

  res.status(200).json({
    status: 'success',
    message: 'Password reset successfully',
    token,
  });
};

export default {
  register,
  sendOTP,
  verifyOTP,
  login,
  protect,
  forgotPassword,
  resetPassword,
};
