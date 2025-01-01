import express from 'express'; // Fast, unopinionated, minimalist web framework for Node.js
import morgan from 'morgan'; // HTTP request logger middleware for node.js
import rateLimit from 'express-rate-limit'; // Basic rate-limiting middleware for Express
import helmet from 'helmet'; // Helps secure Express apps by setting various HTTP headers
import mongoSanitize from 'express-mongo-sanitize'; // Express middleware to sanitize user-supplied data to prevent MongoDB Operator Injection
import bodyParser from 'body-parser'; // Node.js body parsing middleware
import xss from 'xss'; // Library to prevent cross-site scripting attacks
import cors from 'cors'; // Enable CORS with various options
import routes from './routes/index.js'; // Import routes

const app = express();

// Middleware
app.use(express.json({ limit: '10kb' })); // Body limit is 10kb

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({ extended: true }));

app.use(helmet());

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

const limiter = rateLimit({
  max: 3000,
  windowMs: 60 * 60 * 1000, // 1 hour
  message: 'Too many requests from this IP, please try again in an hour',
});
app.use('/chatr', limiter);

app.use(mongoSanitize());

// app.use(xss());

app.use(
  cors({
    origin: '*',
    methods: 'GET,POST,PUT,DELETE,PATCH',
    credentials: true, // enable set cookie with CORS in browser
  })
);

app.use(routes);

export default app;
