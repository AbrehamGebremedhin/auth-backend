const path = require('path');
const express = require('express');
const dotenv = require('dotenv');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser')
const cors = require('cors');
const bodyparser = require('body-parser')
const errorHandler = require('./middleware/error');

const connectDB = require('./config/connectDB')

dotenv.config({path: './config/config.env'});
connectDB();

const authentication = require('./routes/auth')

const app = express();

app.use(express.json());

app.use(bodyparser.urlencoded({extended:false}))
app.use(bodyparser.json())

// Sanitize data
app.use(mongoSanitize());

// Set security headers
app.use(helmet());

// Prevent XSS attacks
app.use(xss());

// Prevent http param pollution
app.use(hpp());

// Specify your frontend origin
const allowedOrigins = ['https://auth-frontend-ns448v832-abrehamgebremedhins-projects.vercel.app', 'https://radiant-shortbread-9fe958.netlify.app'];

app.use(cors({
    origin: allowedOrigins,
    credentials: true, // Allow cookies to be sent
}));

app.use(cookieParser({
    debug: true
}));

app.use('/api/v1/auth', authentication);

app.use(errorHandler);

const PORT= process.env.PORT || 5000;

const server = app.listen(
    PORT, console.log(`Server running on ${process.env.NODE_ENV} mode on ${PORT}`)
);

process.on('unhandledRejection', (err, promise) => {
    console.log(`Error: ${err.message}`)

    server.close(() => process.exit(1))
});
