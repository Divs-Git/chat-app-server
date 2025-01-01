import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { EMAIL_REGEX } from '../constants';

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
    required: [true, 'Please provide a password'],
    minlength: 8,
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
});

userSchema.methods.correctPassword = async function (
  candidatePassword, // password that user provides -> 123456
  userPassword // password that is stored in the database -> $2a$12$3
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = new mongoose.model('User', userSchema);

export default User;
