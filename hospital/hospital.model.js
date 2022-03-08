const { string } = require('joi');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    email: { type: String, unique: true, required: true },
    passwordHash: { type: String, required: true },
    //type: { type: String, required: true },
    name: { type: String, required: true },
    city: {type: String, required:true, default: "Nan"},
    linked_status: {type: String, required:true, default: "unlinked"},
    linked_with: {type: String, required:true, default: "Nan"},
    hospitalStatus: {type:String, required:true, default: "authorized"},
    hospitalAddress: {type:String, required:true, default: "NaN"},
    requests:[
        {
            doctorProfile: { type: Schema.Types.ObjectId, ref: "Doctor" },
            doctorName: { type: String, required: true, default:""},
            linkStatus: { type: String,required:true, default : "active"}
        }],
    //acceptTerms: Boolean,
    role: { type: String, required: true },
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

module.exports = mongoose.model('Hospital', schema);