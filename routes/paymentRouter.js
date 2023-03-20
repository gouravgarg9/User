const express = require('express');
const paymentControllers = require('./../controllers/paymentconrollers')
const userControllers = require('./../controllers/userControllers');
const authControllers = require('./../controllers/authControllers');

const router = express.Router();
router.get('/:prod_id',authControllers.protect,paymentControllers.createCheckoutSession);



module.exports = router;