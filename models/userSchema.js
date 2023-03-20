const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const UserSchema = new mongoose.Schema({
    username : {
        type : String,
        require : [true,"plz provide a username"],
        unique : [true,"Username already exists in database"],
    },
    email : {
        type : String,
        require : [true,"plz provide an email id"],
        unique : [true,"email already exists in database"],
        lowercase : true,
        validate : [validator.isEmail,'Please provide a valid email']
    },
    photo: {
        type : String,
        default : 'xyz.jpg'
    },
    role : {
        type : String,
        enum : ['buyer','seller','admin'],
        default : 'buyer'
    },
    password : {
        type : String,
        require  : [true, 'enter a password'],
        minlength : [8,'try longer password'],
        select : false
    },
    passwordConfirm : {
        type : String,
        require  : [true, 'confirm your password'],
        //executes only on create and save only
        validate:{
            validator: function(el){
                return el === this.password;
            },
            message : "password don't match"
        }
    },
    passwordChangedAt : Date,
    passwordResetToken : String,
    passwordResetExpires : Date,
    active:{
        type:Boolean,
        default: true,
        select: false
    },

    verified:{
        type:Boolean,
        default:false
    },
    hashedOTP : String,
    OTPExpires : Date
});


UserSchema.pre(/^find/,function(next){
    this.find({active : {$ne : false}});
    next();
});


UserSchema.pre('save',async function(next){
    if(this.isNew || this.isModified('password'))
    {
        this.password = await bcrypt.hash(this.password,12);
        //passwordconfirm was required to schema not database
        this.passwordConfirm = undefined;
        this.passwordChangedAt = Date.now() - 1000; 
        this.passwordResetToken = undefined;
        this.passwordResetExpires = undefined;
    }
    next();
});

UserSchema.methods.verifyPassword = async function(candidatePassword,userPassword)
{
    //we need to pass userpassword as well as this.password is not available as password select is set to false
    return await bcrypt.compare(candidatePassword,userPassword);
}

UserSchema.methods.passwordChangedAfter = function(JWTtimestamp){
    if(this.passwordChangedAt){
        passwordTimeStamp = Date.parse(this.passwordChangedAt);
        return passwordTimeStamp > JWTtimestamp*1000; 
    }    
    return false;
}

UserSchema.methods.createPassResetKey = function(){
    const resetKey = crypto.randomBytes(32).toString('hex');
    const passwordResetToken = crypto.createHash('sha256').update(resetKey).digest('hex');
    const passwordResetExpires = Date.now() + 10 * 60 * 1000;
    this.passwordResetToken = passwordResetToken;
    this.passwordResetExpires = passwordResetExpires;
    return resetKey;
}

const User = mongoose.model('user',UserSchema);

module.exports = User;
