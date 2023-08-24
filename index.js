require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const app = express();
const port = process.env.PORT || 3001;
const cors = require('cors');
app.use(cors());
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const authController = require('./controllers/authController');
const authRoutes = require('./routes/authRoutes');
const middlewareRoutes = require('./routes/middlewareRoutes');
const blogRoutes = require('./routes/blogRoutes');

app.use(express.json());

app.post('/api/register', authController.register);
app.post('/api/login', authController.login);

app.use('/api', authRoutes);
app.use('/api', middlewareRoutes);
app.use('/api', blogRoutes);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
