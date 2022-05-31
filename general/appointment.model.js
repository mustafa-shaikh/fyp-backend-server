const { string } = require('joi');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    time: { type: String, unique: true, required: true },
    patientId: { type: Schema.Types.ObjectId, ref : "Patient" },
    doctorId: { type: Schema.Types.ObjectId, ref : "Doctor" },
    appointmentStatus: { type: Boolean, default: "false" },
    appointmentView: { type: Boolean, default: "false" },
    updated: Date
});

schema.set('toJSON', {
    virtuals: true,
    versionKey: false,
}
);

module.exports = mongoose.model('Appointment', schema);