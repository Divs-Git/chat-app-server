import app from './app.js';
import http from 'http';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

dotenv.config({ path: './config.env' });

const server = http.createServer(app);

const DB = process.env.DB_URI.replace('<PASSWORD>', process.env.DB_PASSWORD);

// Connect to MongoDB
mongoose
  .connect(DB, {
    // options to deal with deprecation warnings
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('DB connection successful');
  })
  .catch((err) => {
    console.log('DB connection failed');
    console.log(err);
  });

const PORT = process.env.PORT || 8080;

server.listen(PORT, () => {
  console.log('Server is running on port 8080');
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

// Handle unhandled rejections
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
