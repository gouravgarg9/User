const User = require("./../models/userSchema");
const { promisify } = require("util");
const catchAsync = require("../utils/catchAsync");
const jwt = require("jsonwebtoken");
const AppError = require("./../utils/appError");
const Mail = require("./../utils/email");
const crypto = require("crypto");
const { findById, findByIdAndUpdate } = require("./../models/userSchema");
const OTP = require("./../utils/otpGenerator");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_EXPIREDURATION,
  });
};

const createAndSendToken = (user, statusCode, res) => {
  if (!user) return;

  const token = signToken(user._id);
  user.password = undefined;
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.COOKIE_JWT_EXPIRES * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };
  // if(process.env.NODE_ENV === 'production')
  // cookieOptions.secure = true;

  res.cookie("jwt", token, cookieOptions);
  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    email: req.body.email,
    username: req.body.username,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  if (!newUser) next(new AppError(`Account can't be created`), 404);

  res.status(200).json({
    status: "success",
    message: "Verify yourself to get started",
  });
});

exports.sendSignUpOTP = catchAsync(async (req, res, next) => {
  const newUser = await User.findOne({ email: req.body?.email });

  if (!newUser)
    return next(new AppError("No Sign up request from this account", 404));

  if (newUser.verified)
    return next(new AppError(`Already Verified.Log in`, 404));

  const url = "xyz";
  try {
    await OTP.generateSendSaveOTP(newUser);
  } catch (err) {
    return next(new AppError(`Problem Generating OTP. Try Again.`, 500));
  }

  res.status(200).json({
    status: "success",
    message: "OTP sent",
  });
});

exports.verifySignUpOTP = catchAsync(async (req, res, next) => {
  let newUser = await User.findOne({ email: req.body?.email });

  if (!newUser)
    return next(new AppError("No Sign up request from this account", 404));

  if (newUser.verified)
    return next(new AppError(`Already Verified.Log in`, 404));

  const hashedCandidateOTP = crypto
    .createHash("sha256")
    .update(req.body.otp)
    .digest("hex");

  if (Date.now() > Date.parse(newUser.OTPExpires))
    return next(new AppError("OTP Expired,Try Again", 404));

  if (hashedCandidateOTP !== newUser.hashedOTP)
    return next(new AppError("Wrong OTP,Try Again", 404));

  newUser = await newUser.updateOne({
    verified: true,
    OTPExpires: undefined,
    hashedOTP: undefined,
  });

  new Mail(newUser).sendVerified();
  createAndSendToken(newUser, 202, res);
});

//400 - bad request
//401 - Unauthorized

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password)
    return next(new AppError("PLease provide email and password", 400));

  //select to to explicitly select password as its select is fals ein schema as we need to verify login
  const user = await User.findOne({ email: email }).select("+password");

  if (!(user && (await user.verifyPassword(password, user.password)))) {
    return next(new AppError("Invalid mail or password", 401));
  }

  //For secuirty, dont tell password or mail whats wrong
  // if(!user)
  // return next(new AppError('No user registered with this mail',401));

  // if(!user.verifyPassword(password,user.password))
  //     return next(new AppError('Wrong Password',401));

  createAndSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  //get token and check if exists
  let token;

  if (req.cookies?.jwt) token = req.cookies.jwt;
  else if (req.headers?.authorization?.split(" ")[0] === "Bearer")
    token = req.headers.authorization.split(" ")[1];

  if (!token) return next(new AppError("Not logged in", 401));

  //validate and decode token
  //sign verify are synchronous but we will make verify promise by using promisify from native util module
  const decoded = await promisify(jwt.verify)(
    token,
    process.env.JWT_SECRET_KEY
  );

  //check if user still exists
  const freshUser = await User.findById(decoded.id);
  if (!freshUser) return next(new AppError("User don't exist anymore"));

  //if user changed password after token issued
  if (freshUser.passwordChangedAfter(decoded.iat))
    return next(new AppError("Password changed recently"));

  //finally authorize access
  req.user = freshUser;
  res.locals.user = freshUser;
  next();
});

//used in view routes so that pug can be modified accordingly.
exports.checkLoggedIn = async (req, res, next) => {
  if (!req.cookies?.jwt) return next();

  //validate and decode token
  //sign verify are synchronous but we will make verify promise by using promisify from native util module
  try {
    const decoded = await promisify(jwt.verify)(
      req.cookies.jwt,
      process.env.JWT_SECRET_KEY
    );

    //check if user still exists
    const freshUser = await User.findById(decoded.id);
    if (!freshUser) return next();

    //if user changed password after token issued
    if (freshUser.passwordChangedAfter(decoded.iat)) return next();

    //finally authorize access
    req.user = freshUser;
    res.locals.user = freshUser;
    return next();
  } catch (err) {
      return next();
  }
};

//403 - forbidden
exports.authorizeAccess = (...roles) => {
  return (req, res, next) => {
    if (roles.includes(req.user.role))
      return next(new AppError("Restricted Access only", 403));
  };
};

// recieves mail in body and send resetkey
exports.forgotPassword = catchAsync(async (req, res, next) => {
  //get user
  const user = await User.findOne({ email: req.body.email });

  if (!user) return next(new AppError("No user found", 404));

  //generate key and update user
  const resetKey = user.createPassResetKey();
  await user.save({ validateBeforeSave: false });

  //generate url and send mail

  const resetRoute = "api/users/resetPassword";
  const resetUrl = `${req.protocol}://${req.hostname}/${resetRoute}/${resetKey}`;
  // const message = `Go to this url to reset Password : ${resetUrl}`;

  try {
    // await sendmail({
    //     email : user.email,
    //     subject : 'Password Reset Request (Valid for 10 minutes only)',
    //     message
    // });

    await new Mail(user).sendResetPasswordURL({ resetUrl });
    res.status(200).json({
      status: "success",
      message: "Reset Link sent to mail id",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(new AppError("Unable to send mail. Try later", 500));
  }
});

// recieves key verify it and set new passsword
exports.resetPassword = catchAsync(async (req, res, next) => {
  //hash token and ger user
  const hashtoken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");
  const user = await User.findOne({ passwordResetToken: hashtoken }).select(
    "+password"
  );

  if (!user) return next(new AppError("Token is invalid", 404));

  let message = null;

  if (Date.parse(user.passwordResetExpires) < Date.now())
    messgae = "Token Expired";
  else if (await user.verifyPassword(req.body.password, user.password))
    message = "Same as old password.Try new one.";
  else {
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
  }

  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  if (message) {
    await user.save({ validateBeforeSave: false });
    return next(new AppError(message, 404));
  }

  await user.save();
  //log the user in
  createAndSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  //1.get user
  const user = await User.findById(req.user.id).select("+password");

  //2.checkforPassword
  const passwordCorrect = await user.verifyPassword(
    req.body.currentPassword,
    user.password
  );

  user.password = undefined;
  if (!user || !passwordCorrect)
    return next(new AppError("Wrong Password", 404));
  else if (req.body.currentPassword === req.body.newPassword)
    return next(new AppError("Same as old password.Try new one.", 404));

  //3.updateNewPassword
  user.password = req.body.newPassword;
  user.passwordConfirm = req.body.confirmNewPassword;
  await user.save();

  user.password = undefined;
  //4.log user in again
  createAndSendToken(user, 200, res);
});

exports.deleteUser = catchAsync(async (req, res, next) => {
  //find user
  const user = await User.findById(req.user.id).select("+password");
  const correct = user.verifyPassword(req.body.password, user.password);
  user.password = undefined;
  if (!user || !correct) return next(new AppError("Invalid credentials", 404));

  user.update({ active: false });

  res.status(204).json({
    status: "success",
    data: null,
  });
});

exports.logOut = (req, res, next) => {
  res.cookie("jwt", "logged out", {
    expires: Date.now() + 1000,
    httpOnly: true,
  }),
    res.status(200).json({
      status: "success",
    });
};
