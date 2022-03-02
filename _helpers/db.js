const { connectionString } = require("../config");
const mongoose = require("mongoose");
const connectionOptions = {
  useCreateIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
};
mongoose.connect(connectionString, connectionOptions);
mongoose.Promise = global.Promise;

module.exports = {
    Patient: require('../patient/patient.model'),
    Doctor: require('../doctor/doctor.model'),
    Hospital: require('../hospital/hospital.model'),
    Pharmacy: require('../pharmacy/pharmacy.model'),
    PatientRefreshToken: require('../patient/patient-refresh-token.model'),
    DoctorRefreshToken: require('../doctor/doctor-refresh-token.model'),
    HospitalRefreshToken: require('../hospital/hospital-refresh-token.model'),
    PharmacyRefreshToken: require('../pharmacy/pharmacy-refresh-token.model'),
    isValidId
};

function isValidId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}