import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import filterObj from '../utils/filterObject.js';
import crypto from 'crypto';
import otpGenerator from 'otp-generator';
import { promisify } from 'util';
import mailService from '../services/mailer.js';
import dotenv from 'dotenv';
import resetPasswordTemplate from '../templates/resetPasswordTemplate.js';

dotenv.config();

function signToken(userID) {
  return jwt.sign(
    {
      userID,
    },
    process.env.JWT_SECRET
  );
}

/**
 * Types of routes:
 * 1. Protected routes -> require the user to be logged in
 * 2. Unprotected routes
 */

const protect = async (req, res, next) => {
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
  const currentUser = await User.findById(decoded.userID);

  if (!currentUser) {
    return res.status(401).json({
      status: 'error',
      message: 'The user no longer exist',
    });
  }

  // 4. Check if the user changed the password after the token was issued
  // iat -> issued at
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return res.status(401).json({
      status: 'error',
      message: 'User recently changed password! Please log in again',
    });
  }

  // 5. Grant access to the protected route
  req.user = currentUser;
  next();
};

const register = async (req, res, next) => {
  const { firstName, lastName, email, password, verified } = req.body;

  // Check if the verified user already exists with the provided email
  const existingUser = await User.findOne({ email });

  const filteredBody = filterObj(
    req.body,
    'firstName',
    'lastName',
    'email',
    'password'
  );

  // If the user exists and is verified, return an error
  if (existingUser && existingUser.verified) {
    return res.status(400).json({
      status: 'error',
      message: 'Email already in use, please login',
    });
  }

  // If the user exists but is not verified, update the user's information
  else if (existingUser) {
    await User.findOneAndUpdate({ email }, filteredBody, {
      new: true,
      validateModifiedOnly: true,
    });

    // generate OTP and send it to the user
    req.UserID = existingUser._id;
    next();
  }

  // If the user does not exist, create a new user
  else {
    const newUser = await User.create(filteredBody);

    // generate OTP and send it to the user
    req.userID = newUser._id;
    next();
  }
};

const sendOTP = async (req, res, next) => {
  const { userID } = req;
  const newOTP = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  const otpExpiryTime = Date.now() + 10 * 60 * 1000; // 10 minutes

  const user = await User.findByIdAndUpdate(userID, {
    otpExpiryTime,
  });

  // TODO: Send the OTP to the user via email
  user.otp = newOTP.toString();

  console.log(user.otp);

  await user.save({ new: true, validateModifiedOnly: true });

  res.status(200).json({
    status: 'success',
    message: 'OTP sent successfully',
  });

  // mailService
  //   .sendMail({
  //     from: 'tdyphotography39@gmail.com',
  //     to: user.email,
  //     subject: 'Verification OTP for Chatr',
  //     html: otp(user),
  //   })
  //   .then(() => {
  //     res.status(200).json({
  //       status: 'success',
  //       message: 'OTP sent successfully',
  //     });
  //   })
  //   .catch((error) => {
  //     console.log(error);
  //     return res.status(500).json({
  //       status: 'error',
  //       message: 'There was an error sending the OTP. Try again later',
  //     });
  //   });
};

const verifyOTP = async (req, res, next) => {
  // Verify the OTP and update the user's verified status
  const { email, otp } = req.body;

  const user = await User.findOne({
    email,
    otpExpiryTime: { $gt: Date.now() },
  }); // Check if the OTP is still valid

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

const login = async (req, res, next) => {
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

const forgotPassword = async (req, res, next) => {
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
  await user.save({ validateBeforeSave: false });

  try {
    // TODO: Send the resetURL to the user via email
    const resetURL = `https://localhost:8080/auth/reset-password/?code=${resetToken}`;

    mailService.sendMail({
      to: user.email,
      subject: 'Reset Password',
      html: resetPasswordTemplate(user.firstName, resetURL),
      attachments: [],
    });

    res.status(200).json({
      status: 'success',
      message: 'Reset token sent to email',
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save({ validateBeforeSave: false });

    res.status(500).json({
      status: 'error',
      message: 'There was an error sending the email. Try again later!',
    });
  }
};

const resetPassword = async (req, res, next) => {
  // Find the user with the provided reset token

  const hashedToken = crypto
    .createHash('sha256')
    .update(req.body.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({
      status: 'error',
      message: 'Token is invalid or has expired',
    });
  }

  // Update the user's password
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

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
