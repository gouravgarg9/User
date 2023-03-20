const catchAsync = require("../utils/catchAsync")

exports.sendHome = catchAsync(async(req,res,next)=>{
    res.render('home',{title : 'Adavanced Purchase'})
})

exports.sendLogSign = catchAsync(async(req,res,next)=>{
    res.render('home',{title : 'Log In'})
})