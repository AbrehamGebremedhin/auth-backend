const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: [true, 'Please enter a user name.'] 
    },
    password: { 
        type: String, 
        required: [true, 'Please enter a password.'], 
        minlength: 6, 
        select: false 
    },
    phonenumber: {
        type: String,
        required: [true, 'Please add a phone number'],
        unique: true,
        match: [
            /^\+251\d{9}$/,
            'Please add a valid phone number',
        ]
    },
    email: {
        type: String,
        required: [true, 'Please add an email'],
        unique: true,
        match: [
            /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
            'Please add a valid email',
        ]
    },
    createdOn:  { 
        type: Date,
         default: Date.now()
    }
});

//Password encryption
UserSchema.pre('save', async function (next) {
    if(!this.isModified('password')){
        next();
    }

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
})

//Returns a signed JSON Web Token
UserSchema.methods.getSignedJwtToken = function () {
    return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE
    });
}

UserSchema.methods.matchPassword = async function(password) {
    return await bcrypt.compare(password, this.password);
}

// Generates a signed Refresh Token
UserSchema.methods.getSignedRefreshToken = function() {
    return jwt.sign({ id: this._id }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: '7d' // Refresh token is valid for 7 days
    });
}

module.exports = mongoose.model('User', UserSchema);