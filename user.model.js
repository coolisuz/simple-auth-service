const mongoose = require('mongoose');
const Validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  fullname: {
    type: String,
    required: [true, 'Full name is required'],
  },

  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [Validator.isEmail, 'Please enter valid email'],
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [5, 'Minimum 6 characters'],
  },
});

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  }
});

const User = mongoose.model('User', userSchema);
module.exports = User;
