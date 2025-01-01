import jwt from 'jsonwebtoken';
import User from '../models/user.js';

function signToken(user_id) {
  jwt.sign(
    {
      user_id,
    },
    process.env.JWT_SECRET
  );
}

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
