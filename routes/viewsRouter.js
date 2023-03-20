const express = require('express');
const viewsControllers = require('./../controllers/viewsControllers')
const userControllers = require('./../controllers/userControllers');
const authControllers = require('./../controllers/authControllers');

const router = express.Router();

router.get('/',viewsControllers.sendHome);
router.get('/loginSignup',viewsControllers.sendLogSign);
// router.get('',);
// router.get('',);
// router.get('',);
// router.get('',);


module.exports = router;