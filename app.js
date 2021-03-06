﻿require('rootpath')();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('_middleware/error-handler');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// allow cors requests from any origin and with credentials
app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));

// api routes
app.use('/accounts/user', require('./api/accounts.controller'));
app.use('/accounts/business', require('./api/business-account.controller'));
app.use('/accounts', require('./api/login.controller'));
app.use('/accounts', require('./api/verifyemail.controller'));
app.use('/accounts', require('./api/forgotpassword.controller'));
app.use('/accounts', require('./api/resetpassword.controller'));



// global error handler
app.use(errorHandler);

// start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;
app.listen(port, () => {
    console.log('Server listening on port ' + port);
});
