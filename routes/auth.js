const express = require('express');
const { addUser, loginUser, logoutUser, getCurrentUser, refreshToken } = require('../controllers/auth');
const {
    getUserSessions,
    deleteSession,
    deleteAllSessions
} = require('../controllers/session');

const { protect } = require('../middleware/auth');

const router = express.Router()

// Route to register a new user
router.post('/register', addUser);

// Route to login a user
router.post('/login', loginUser);

// Route to logout a user
router.post('/logout', logoutUser);

// Route to get the current logged-in user
router.get('/profile', protect,  getCurrentUser);

// Route to refresh the JWT token
router.post('/refresh', refreshToken);

// Route to get all sessions for the logged-in user
router.get('/sessions', protect, getUserSessions);

// Route to delete a specific session (log out from a specific device)
router.delete('/sessions/:sessionId', protect, deleteSession);

// Route to delete all sessions (log out from all devices)
router.delete('/sessions', protect, deleteAllSessions);



module.exports = router;