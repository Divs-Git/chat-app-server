import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import filterObj from '../utils/filterObject.js';
import otpGenerator from 'otp-generator';

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

  res.status(200).json({
    status: 'success',
    message: 'OTP sent successfully',
  });
};

export const verifyOTP = async (req, res, next) => {
  // Verify the OTP and update the user's verified status
  const { email, otp } = req.body;

  const user = User.findOne({ email, otp_expiry_time: { $gt: Date.now() } }); // Check if the OTP is still valid

  if (!user) {
    res.status(400).json({
      status: 'error',
      message: 'Email is invalid or OTP has expired',
    });
  }

  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
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
    res.status(401).json({
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

export const forgotPassword = async (req, res, next) => {};

export const resetPassword = async (req, res, next) => {};
