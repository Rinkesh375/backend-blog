const express = require('express');
const router = express.Router();
const verifyToken = require('../middleware/authMiddleware'); // Import the JWT verification middleware
const blogController = require('../controllers/blogController');

// Fetch blogs (protected route)
router.get('/blogs', verifyToken, blogController.getAllBlogs);

module.exports = router;
