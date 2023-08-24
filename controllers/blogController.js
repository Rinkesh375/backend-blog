const Blog = require('../models/Blog');

exports.getAllBlogs = async (req, res) => {
  try {
    const blogs = await Blog.find().populate('author', 'username');
    res.status(200).json({ blogs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.searchBlogsByTitle = async (req, res) => {
  try {
    const { title } = req.query;
    const blogs = await Blog.find({ title: { $regex: title, $options: 'i' } }).populate('author', 'username');
    res.status(200).json({ blogs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.filterBlogsByCategory = async (req, res) => {
  try {
    const { category } = req.query;
    const blogs = await Blog.find({ category }).populate('author', 'username');
    res.status(200).json({ blogs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.sortBlogsByDate = async (req, res) => {
  try {
    const { order } = req.query;
    const sortOrder = order === 'asc' ? 1 : -1;
    const blogs = await Blog.find().sort({ createdAt: sortOrder }).populate('author', 'username');
    res.status(200).json({ blogs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.createBlog = async (req, res) => {
  try {
    const { title, content, category } = req.body;
    const author = req.userId; 
    const blog = new Blog({
      title,
      content,
      category,
      author,
    });

    await blog.save();

    res.status(201).json({ message: 'Blog created successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.updateBlog = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, category } = req.body;
    const author = req.userId;

    const blog = await Blog.findById(id);

    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    if (blog.author.toString() !== author.toString()) {
      return res.status(403).json({ message: 'Unauthorized to update this blog' });
    }

    blog.title = title;
    blog.content = content;
    blog.category = category;

    await blog.save();

    res.status(200).json({ message: 'Blog updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.deleteBlog = async (req, res) => {
  try {
    const { id } = req.params;
    const author = req.userId; 

    const blog = await Blog.findById(id);

    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    if (blog.author.toString() !== author.toString()) {
      return res.status(403).json({ message: 'Unauthorized to delete this blog' });
    }

    await blog.remove();

    res.status(200).json({ message: 'Blog deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.likeBlog = async (req, res) => {
  try {
    const { id } = req.params;
    const user = req.userId; 

    const blog = await Blog.findById(id);

    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    if (blog.likes.includes(user)) {
      return res.status(400).json({ message: 'You already liked this blog' });
    }

    blog.likes.push(user);
    await blog.save();

    res.status(200).json({ message: 'Blog liked successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};

exports.commentOnBlog = async (req, res) => {
  try {
    const { id } = req.params;
    const { text } = req.body;
    const user = req.userId; 

    const blog = await Blog.findById(id);

    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    const comment = {
      user,
      text,
    };

    blog.comments.push(comment);
    await blog.save();

    res.status(200).json({ message: 'Comment added successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};
