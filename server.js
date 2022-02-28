const { morganEnv, port, nodeEnv } = require("./config");
const express = require("express");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const errorHandler = require("./_middleware/error-handler");

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// allow cors requests from any origin and with credentials
app.use(
  cors({
    origin: (origin, callback) => callback(null, true),
    credentials: true,
  })
);

// Morgan Logs
if (morganEnv === "development") {
  app.use(morgan("dev"));
  console.log("Morgan");
}

// api routes

app.use("/check", require("./Model/controller"));
app.use("/hospital", require("./hospital/hospital.controller"));
app.use("/doctor", require("./doctor/doctor.controller"));
app.use("/patient", require("./patient/patient.controller"));

// global error handler
app.use(errorHandler);

// start server
app.listen(port, () => {
  console.log(`${nodeEnv} SERVER LISTENING ON PORT ${port}`);
});
