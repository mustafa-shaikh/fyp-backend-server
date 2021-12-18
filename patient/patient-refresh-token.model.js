const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    patient: { type: Schema.Types.ObjectId, ref: 'Patient' },
    token: String,
    expires: Date,
    created: { type: Date, default: Date.now },
    createdByIp: String,
    revoked: Date,
    revokedByIp: String,
    replacedByToken: String
});

schema.virtual('isExpired').get(function () {
    return Date.now() >= this.expires;
});

schema.virtual('isActive').get(function () {
    return !this.revoked && !this.isExpired;
});

module.exports = mongoose.model('PatientRefreshToken', schema);