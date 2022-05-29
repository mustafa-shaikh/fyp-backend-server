const { morganEnv, port, nodeEnv } = require("./config");
const express = require("express");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const errorHandler = require("./_middleware/error-handler");
const chainProcedure = require("./Model/service");

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
  console.log("Development");
} else if (morganEnv === "testing") {
  app.use(morgan("dev"));
  console.log("Testing");
}

chainProcedure
  ._publishSymptoms()
  .then((data) => {
    // res.send(data);
    // console.log("chain", data);
    console.log("chain connected");
  })
  .catch((error) => {
    process.env["CHAIN_STATUS"] = "connected";
    // res.send(data);
    // console.log("chain error", error);
    console.log("couldn't connect to chain");
  });

chainProcedure
  ._getInfo()
  .then((data) => {
    // res.send(data);
    // console.log("chain", data);
    console.log("sent to chain");
  })
  .catch((error) => {
    // res.send(data);
    // console.log("chain error", error);
    console.log("couldn't send to chain");
  });

// api routes

app.use("/check", require("./Model/controller"));
app.use("/hospital", require("./hospital/hospital.controller"));
app.use("/pharmacy", require("./pharmacy/pharmacy.controller"));
app.use("/doctor", require("./doctor/doctor.controller"));
app.use("/patient", require("./patient/patient.controller"));

// global error handler
app.use(errorHandler);

// start server
app.listen(port, () => {
  console.log(`${nodeEnv} SERVER LISTENING ON PORT ${port}`);
});
