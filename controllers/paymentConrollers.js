const AppError = require("../utils/appError")
const catchAsync = require("../utils/catchAsync")
const stripe = require('stripe')(process.env.STRIPE_PRIVATE_KEY);

module.exports.createCheckoutSession = catchAsync(async (req,res,next)=>{
        const line_items = req.body.cart.map((element,index,arr)=>{
            return {
                price : element.product_id,
                quantity : 1
            }
        });
        
        const session = await stripe.checkout.sessions.create({
            mode: 'payment',
            success_url : `${req.protocol}://${req.get('host')}/`,
            cancel_url : `${req.protocol}://${req.get('host')}/`,
            customer_email : req.user.email,
            line_items
        })

        res.redirect(303,session.url);
})