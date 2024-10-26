const jwt = require('jsonwebtoken');
const ErrorResponse = require('../utils/errorResponse');
const asyncHandler = require('../middleware/async');
const User = require('../models/User');

exports.protect = asyncHandler(async (req, res, next) => {
    let token;

    // Extract the access token from cookies
    if (req.cookies.accessToken) {
        token = req.cookies.accessToken;
    }

    // Ensure token exists
    if (!token) {
        return next(new ErrorResponse('Not authorized to access this route', 401));
    }

    try {
        // Verify the access token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id);

        if (!req.user) {
            return next(new ErrorResponse('User not found', 404));
        }

        next();
    } catch (err) {
        // Handle invalid or expired access token
        if (err.name === 'TokenExpiredError') {
            return next(new ErrorResponse('Access token expired', 401)); // Or redirect to refresh token endpoint
        }

        return next(new ErrorResponse('Not authorized to access this route', 401));
    }
});
