const express = require('express');
const router = express.Router();
const blogController = require('../controllers/blogController');
const verifyToken = require('../middleware/authMiddleware');

router.get('/blogs', verifyToken, blogController.getAllBlogs);
router.get('/blogs/search', verifyToken, blogController.searchBlogsByTitle);
router.get('/blogs/filter', verifyToken, blogController.filterBlogsByCategory);
router.get('/blogs/sort', verifyToken, blogController.sortBlogsByDate);
router.post('/blogs', verifyToken, blogController.createBlog);
router.put('/blogs/:id', verifyToken, blogController.updateBlog);
router.delete('/blogs/:id', verifyToken, blogController.deleteBlog);
router.put('/blogs/:id/like', verifyToken, blogController.likeBlog);
router.put('/blogs/:id/comment', verifyToken, blogController.commentOnBlog);

module.exports = router;
