const express = require("express");

const userControllers = require("./../controllers/userControllers");
const authControllers = require("./../controllers/authControllers");

const router = express.Router();

router.get("/:email", userControllers.getuser);

router.post("/signup", authControllers.signup);
router.post("/sendSignUpOTP", authControllers.sendSignUpOTP);
router.post("/verifySignUpOTP", authControllers.verifySignUpOTP);
router.post("/forgotPassword", authControllers.forgotPassword);
router.patch("/resetPassword/:token", authControllers.resetPassword);

router.post("/login", authControllers.login);

router.patch(
  "/updatePassword",
  authControllers.protect,
  userControllers.checkVerified,
  authControllers.updatePassword
);
router.delete(
  "/deleteUser",
  authControllers.protect,
  userControllers.checkVerified,
  authControllers.deleteUser
);
router.patch(
  "/updateMe",
  authControllers.protect,
  userControllers.checkVerified,
  userControllers.userPhotoUpload,
  userControllers.userPhotoResize,
  userControllers.updateMe
);

//router.get('/logout', authController.logout);

module.exports = router;
