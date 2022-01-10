require('rootpath')();
const express = require('express');
const app = express();
const morgan = require('morgan')
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('_middleware/error-handler');
const dotenv = require('dotenv');
dotenv.config();


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// allow cors requests from any origin and with credentials
app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));

// Morgan Logs
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
    console.log("Morgan");
  }

// api routes

app.use('/check', require('./Model/controller'));
app.use('/hospital', require('./hospital/hospital.controller'));
app.use('/doctor', require('./doctor/doctor.controller'));
app.use('/patient', require('./patient/patient.controller'));

// global error handler
app.use(errorHandler);


// start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;
app.listen(port, () => {
    console.log('Server listening on port ' + port);
});
