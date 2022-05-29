
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    email: { type: String, unique: true, required: true },
    passwordHash: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    address: { type: String, default:"NaN"},
    phone: { type: String, default:"1234-5678910" },
    imageUrl: { type: String, required: true , default:'https://www.pinclipart.com/picdir/middle/209-2098523_individuals-person-icon-circle-png-clipart.png' },
    city: {type: String, default: "NaN"},
    patientStatus: {type:String, required:true, default: "unauthorized"},
    // acceptTerms: Boolean,
    role: { type: String, required: true,  default: "Patient" },
    verificationToken: String,
    verified: Date,
    resetToken: {
        token: String,
        expires: Date
    },
    passwordReset: Date,
    created: { type: Date, default: Date.now },
    updated: Date
});

schema.virtual('isVerified').get(function () {
    return !!(this.verified || this.passwordReset);
});

schema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    transform: function (doc, ret) {
        // remove these props when object is serialized
        delete ret._id;
        delete ret.passwordHash;
    }
});

module.exports = mongoose.model('Patient', schema);