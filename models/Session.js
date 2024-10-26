const mongoose = require('mongoose');

const SessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    refreshToken: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 60 * 60 * 24 * 7
    },
    ipAddress: {
        type: String
    },
    userAgent: {
        type: String
    },
    deviceType: {
        type: String
    }
});

module.exports = mongoose.model('Session', SessionSchema);
