const config = require('config.json');
const mongoose = require('mongoose');
const connectionOptions = { useCreateIndex: true, useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false };
mongoose.connect(process.env.MONGODB_URI || config.connectionString, connectionOptions);
mongoose.Promise = global.Promise;

module.exports = {
    Patient: require('patient/patient.model'),
    Doctor: require('doctor/doctor.model'),
    Hospotal: require('hospital/hospital.model'),
    PatientRefreshToken: require('patient/patient-refresh-token.model'),
    DoctorRefreshToken: require('doctor/doctor-refresh-token.model'),
    HospitalRefreshToken: require('hospital/hospital-refresh-token.model'),
    isValidId
};

function isValidId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}