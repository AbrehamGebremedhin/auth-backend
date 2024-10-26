const path = require('path');
const express = require('express');
const dotenv = require('dotenv');
const morgan = require('morgan');
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

// Enable CORS
app.use(cors());

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
