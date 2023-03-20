const AppError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync")
const User = require('./../models/userSchema')
const multer = require('multer');
const FilterObject = require('./../utils/FilterObject')
const sharp = require('sharp');

    // const multerStorage = multer.diskStorage({
    //     destination: (req,file,cb)=>{
    //         cb(null,'public/images/users');
    //     },
    //     filename: (req,file,cb)=>{
    //         const extension = file.mimetype.split('/')[1];
    //         cb(null,`user_${req.user._id}_at_${Date.now()}.${extension}`)
    //     }
    // })

const multerStorage = multer.memoryStorage();

const multerFilter = (req,file,cb)=>{
    if(file.mimetype.startsWith('image'))
        cb(null,true);
    else
        cb(new AppError('Please upload image only',404),false);
}

const upload = multer({
    storage:multerStorage,
    fileFilter:multerFilter
})

exports.userPhotoUpload = upload.single('userImage');

exports.userPhotoResize = (req,res,next)=>{
    if(!req.file)
       return next();

    req.file.filename = `user_${req.user._id}_at_${Date.now()}.jpeg`;

    sharp(req.file.buffer).resize(500,500,{fit : 'fill'})
    .toFormat('jpeg')
    .jpeg({quality : 90})
    .toFile(`public/images/users/${req.file.filename}`);

    next();
}

exports.getuser = catchAsync(async(req,res,next)=>{
    const user = await User.find({email : req.params.email});
    if(!user)
        next(new AppError('No user bt this email'),200);
    res.status(200).json({
        status : 'success',
        data : {
            user
        }
    })
})

exports.updateMe = catchAsync(async(req,res,next)=>{
    //filter fields applicable
    const applicableFieldsObj = FilterObject(req.body,false,"username");

    if(req.file)
        applicableFieldsObj.photo = req.file.filename;

    //change fields and update
    await User.findByIdAndUpdate(req.user._id,applicableFieldsObj);
    
    //send response
    res.status(200)
    .json({
      status : "success",
      data : {
        message : "Field Changed",
      }
    })
  })

  exports.checkVerified = catchAsync(async(req,res,next)=>{
    const email = req.user?.email || req.body.user?.email || req.body.email;
    const user = await User.findOne({email});
    if(!user)
        return next(new AppError('Wrong Email',404));
    
    if(!user.verified)
        return next(new AppError('First Verify yourself',404));
        
    next();
  })