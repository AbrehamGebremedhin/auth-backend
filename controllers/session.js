const asyncHandler = require('../middleware/async');
const ErrorResponse = require('../utils/errorResponse');
const Session = require('../models/Session'); 

// @desc    Get all sessions for the logged-in user
// @route   GET /api/auth/sessions
// @access  Private
exports.getUserSessions = asyncHandler(async (req, res, next) => {
    const sessions = await Session.find({ userId: req.user.id });

    res.status(200).json({
        success: true,
        data: sessions
    });
});

// @desc    Delete a specific session (log out from a specific device)
// @route   DELETE /api/auth/sessions/:sessionId
// @access  Private
exports.deleteSession = asyncHandler(async (req, res, next) => {
    const session = await Session.findById(req.params.sessionId);

    if (!session || session.userId.toString() !== req.user.id) {
        return next(new ErrorResponse('Session not found or unauthorized', 404));
    }

    // Delete the specified session
    await session.remove();

    res.status(200).json({
        success: true,
        data: {}
    });
});

// @desc    Delete all sessions for the logged-in user (log out from all devices)
// @route   DELETE /api/auth/sessions
// @access  Private
exports.deleteAllSessions = asyncHandler(async (req, res, next) => {
    // Delete all sessions for the logged-in user
    await Session.deleteMany({ userId: req.user.id });

    res.status(200).json({
        success: true,
        data: {}
    });
});
