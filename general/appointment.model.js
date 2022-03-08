const { string } = require('joi');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    time: { type: String, unique: true, required: true },
    patientId: { type: String, required: true },
    doctorId: { type: String, required: true },
    appointmentStatus: {type: Boolean, required:true, default: "unchecked"},
    appointmentView: {type: Boolean, required:true, default: "false"},
    updated: Date
});

schema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    }
);

module.exports = mongoose.model('Appointment', schema);