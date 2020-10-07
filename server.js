// Bismillah
const express = require('express');
const mongoose = require('mongoose');
const { json } = require('express');
const cookieSession = require('cookie-session');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const User = require('./user.model');
const globalErrorHandler = require('./utils/globalErrorHandler');
const AppError = require('./utils/appError');
const catchAsync = require('./utils/catchAsync');

const app = express();
dotenv.config({ path: './config.env' });

/////////////////////////// MONGO START /////////////////////////////
const DB = process.env.DB.replace('<password>', process.env.DB_PASSWORD);
const startMongo = async () => {
  try {
    await mongoose.connect(DB, {
      useCreateIndex: true,
      useUnifiedTopology: true,
      useNewUrlParser: true,
      useFindAndModify: false,
    });
    console.log('DB connection successful');
  } catch (error) {
    throw new Error('Could not connect to database');
  }
};
startMongo();
//*********************** MONGO END ********************************

app.set('trust proxy', true);
app.use(json());
app.use(
  cookieSession({
    signed: false,
  })
);

/////////////////////////// SIGN UP START /////////////////////////////
const signup = catchAsync(async (req, res, next) => {
  // Create User
  const newUser = await User.create(req.body);

  // Generate JWT
  const userJWT = jwt.sign(
    {
      id: newUser.id,
      email: newUser.email,
    },
    process.env.JWT_SECRET_KEY
  );

  // Store jwt on session object
  req.session = {
    jwt: userJWT,
  };

  // Send response back to the client
  res.status(201).json({
    status: 'success',
    message: 'User created',
    data: { user: newUser },
  });
});
app.post('/signup', signup);

//*********************** SIGN UP END ********************************

/////////////////////////// SIGN IN START ///////////////////////////////////
const signin = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  const existingUser = await User.findOne({ email });

  if (!existingUser) {
    return next(new AppError('Invalid email or password', 400));
  }

  // Compare password
  const isCorrectPassword = await bcrypt.compare(
    password,
    existingUser.password
  );

  if (!isCorrectPassword) {
    return next(new AppError('Invalid email or password', 400));
  }
  const userJwt = jwt.sign(
    {
      id: existingUser.id,
      email: existingUser.email,
    },
    process.env.JWT_SECRET_KEY
  );

  // Store it on session object
  req.session = {
    jwt: userJwt,
  };

  // Send response back to the client
  res.status(200).json({
    status: 'success',
    data: { user: existingUser },
  });
});

app.post('/signin', signin);
//*********************** SIGN IN END ********************************

/////////////////////////// SIGN OUT START ///////////////////////////////////
app.post('/signout', (req, res, next) => {
  req.session = null;
  res.status(200).json({
    status: 'success',
    message: 'You have been logged out',
  });
});

//*********************** SIGN IN END ********************************

/////////////////////////// ERRO HANDLING START /////////////////////////////
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server`));
});
app.use(globalErrorHandler);
//*********************** ERROR HANDLIING END ********************************

app.listen(process.env.PORT, () => {
  console.log('listening on port 8000');
});
