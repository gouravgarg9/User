const otpGenerator = require("otp-generator");
const catchAsync = require("./catchAsync");
const crypto = require("crypto");
const User = require("./../models/userSchema");
const Mail = require('./../utils/email')


const generateOTP = () => {
  const OTP = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  return OTP;
};

module.exports.generateSendSaveOTP = async (user) => {
    
    const otp = generateOTP();
    const hashedOTP = crypto.createHash("sha256").update(otp).digest("hex");
    const OTPExpires = Date.now() + 10 * 60 * 1000;
    
    await new Mail(user).sendSignUpOTP({otp});

    await User.findOneAndUpdate({ _id: user._id }, { hashedOTP,OTPExpires});
}