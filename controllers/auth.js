const ErrorResponse = require('../utils/errorResponse');
const asyncHandler = require('../middleware/async');
const User = require('../models/User');
const Session = require('../models/Session');

//Register User
exports.addUser = asyncHandler( async(req, res, next) => {
    const { username, email, phonenumber, password, role } = req.body;
    
    const user = await User.create({
        username,
        email,
        phonenumber,
        password
    })

    sendJWT(user, 200, req, res);
});

//Login User
exports.loginUser = asyncHandler( async(req, res, next) => {
    const { email, password } = req.body;
    
    //Validation
    if(!email || !password) {
        return next(new ErrorResponse('Please enter an Email or password', 400))
    }

    const user = await User.findOne({ email }).select('+password');

    if(!user) {
        return next(new ErrorResponse('Invalid Email', 401));
    }

    const isCorrect = await user.matchPassword(password);

    if(!isCorrect) {
        return next(new ErrorResponse('Invalid Password', 401));
    }

    sendJWT(user, 200, req, res);
});

//Logout User
exports.logoutUser = asyncHandler( async(req, res, next) => {
    res.cookie('token', 'none', {
        maxAge: new Date(Date.now() + 10 * 1000),
        httpOnly: true
    })

    res.status(200).json({
        success: true,
        data: {}        
    })
});

//Gets logged in user information
exports.getCurrentUser = asyncHandler( async(req, res, next) => {
    const user = await User.findById(req.user.id);

    res.status(200).json({
        success: true,
        data: user        
    })
}); 

//Send JWT Token
const sendJWT = async (user, status, req, res) => {
    const accessToken = user.getSignedJwtToken();
    const refreshToken = user.getSignedRefreshToken();

    // Extract device information
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.ip || req.connection.remoteAddress;
    const deviceType = getDeviceType(userAgent); // Helper function to detect device

    // Store session in the database
    await Session.create({
        userId: user._id,
        refreshToken,
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // Set refresh token expiration to 7 days
        ipAddress,
        userAgent,
        deviceType
    });

    // Set cookies
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict'
    };

    res.cookie('accessToken', accessToken, {
        ...cookieOptions,
        maxAge: 10 * 60 * 1000 // 10 minutes
    });

    res.cookie('refreshToken', refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(status).json({
        success: true
    });
};

//Refresh Token
exports.refreshToken = asyncHandler(async (req, res, next) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        return next(new ErrorResponse('No refresh token provided', 403));
    }

    // Find session with matching refresh token
    const session = await Session.findOne({ refreshToken });

    if (!session) {
        return next(new ErrorResponse('Invalid refresh token', 403));
    }

    // Verify device information
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.ip || req.connection.remoteAddress;
    
    if (session.userAgent !== userAgent || session.ipAddress !== ipAddress) {
        return next(new ErrorResponse('Device information mismatch', 403));
    }

    // Verify the refresh token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
        if (err || decoded.id !== session.userId.toString()) {
            return next(new ErrorResponse('Invalid or expired refresh token', 403));
        }

        const user = await User.findById(session.userId);

        if (!user) {
            return next(new ErrorResponse('User not found', 404));
        }

        // Generate a new access token
        const newAccessToken = user.getSignedJwtToken();

        // Set new access token cookie
        res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 10 * 60 * 1000 // 10 minutes
        });

        res.status(200).json({
            success: true
        });
    });
});

//Get Device Type
const getDeviceType = (userAgent) => {
    if (/mobile/i.test(userAgent)) {
        return 'Mobile';
    }

    if (/like Mac OS X/.test(userAgent)) {
        return 'iOS';
    }

    if (/Android/.test(userAgent)) {
        return 'Android';
    }

    return 'Web';
};

