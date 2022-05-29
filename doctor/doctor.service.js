const schedule =
{
    monday: {
        "slot1": "9:00 am - 9:30 am",
        "slot2": "9:30 am - 10:00 am",
        "slot3": "10:00 am - 10:30 am",
        "slot4": "10:30 am - 11:00 am",
        "slot5": "11:00 am - 11:30 am",
        "slot6": "11:30 am - 12:00 pm",
        "slot7": "12:00 pm - 12:30 pm",
        "slot8": "12:30 pm - 01:00 pm",
        "slot9": "01:30 pm - 02:00 pm",
        "slot10": "02:00 pm - 02:30 pm",
        "slot11": "02:30 pm - 03:00 pm",
    },

    tuesday: {
        "slot1": "9:00 am - 9:30 am",
        "slot2": "9:30 am - 10:00 am",
        "slot3": "10:00 am - 10:30 am",
        "slot4": "10:30 am - 11:00 am",
        "slot5": "11:00 am - 11:30 am",
        "slot6": "11:30 am - 12:00 pm",
        "slot7": "12:00 pm - 12:30 pm",
        "slot8": "12:30 pm - 01:00 pm",
        "slot9": "01:30 pm - 02:00 pm",
        "slot10": "02:00 pm - 02:30 pm",
        "slot11": "02:30 pm - 03:00 pm",
    },

    wednesday: {
        "slot1": "9:00 am - 9:30 am",
        "slot2": "9:30 am - 10:00 am",
        "slot3": "10:00 am - 10:30 am",
        "slot4": "10:30 am - 11:00 am",
        "slot5": "11:00 am - 11:30 am",
        "slot6": "11:30 am - 12:00 pm",
        "slot7": "12:00 pm - 12:30 pm",
        "slot8": "12:30 pm - 01:00 pm",
        "slot9": "01:30 pm - 02:00 pm",
        "slot10": "02:00 pm - 02:30 pm",
        "slot11": "02:30 pm - 03:00 pm",
    },

    thursday: {
        "slot1": "9:00 am - 9:30 am",
        "slot2": "9:30 am - 10:00 am",
        "slot3": "10:00 am - 10:30 am",
        "slot4": "10:30 am - 11:00 am",
        "slot5": "11:00 am - 11:30 am",
        "slot6": "11:30 am - 12:00 pm",
        "slot7": "12:00 pm - 12:30 pm",
        "slot8": "12:30 pm - 01:00 pm",
        "slot9": "01:30 pm - 02:00 pm",
        "slot10": "02:00 pm - 02:30 pm",
        "slot11": "02:30 pm - 03:00 pm",
    },

    friday: {
        "slot1": "9:00 am - 9:30 am",
        "slot2": "9:30 am - 10:00 am",
        "slot3": "10:00 am - 10:30 am",
        "slot4": "10:30 am - 11:00 am",
        "slot5": "11:00 am - 11:30 am",
        "slot6": "11:30 am - 12:00 pm",
        "slot7": "12:00 pm - 12:30 pm",
        "slot8": "12:30 pm - 01:00 pm",
        "slot9": "01:30 pm - 02:00 pm",
        "slot10": "02:00 pm - 02:30 pm",
        "slot11": "02:30 pm - 03:00 pm",
    }
}
const { secret } = require('../config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sendEmail = require('../_helpers/send-email');
const db = require('../_helpers/db');
const Role = require('../_helpers/role');


module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    linkToHospital,
    getAllHospital,
    getAllDoctor, //273
    getById,
    create,
    update,
    delete: _delete,
    linkDetails,
};

async function linkToHospital(userId, params) {
    //console.log("Taha at doc service");
    const hospital = await db.Hospital.findById(params.hospitalId);
    // console.log("taha", params.doctorName)

    // validate (if email was changed)
    // if (params.email && doctor.email !== params.email && await db.Doctor.findOne({ email: params.email })) {
    //     throw 'Email "' + params.email + '" is already taken';
    // }

    // hash password if it was entered
    // if (params.password) {
    //     params.passwordHash = hash(params.password);
    // }

    // copy params to doctor and save
    //Object.assign(hospital, params);
    const temp = {
        doctorProfile: userId,
        linkStatus: params.linkStatus,
        doctorName: params.doctorName
    }

    hospital.requests.push(temp)
    //doctor.updated = Date.now();
    await hospital.save();

    // return linkDetails(doctor);
}

function linkDetails(doctor) {
    const { id, title, firstName, lastName, email, doctorStatus, city, role, linked_status, linked_with, created, updated, isVerified } = doctor;
    return { id, title, firstName, lastName, email, doctorStatus, city, role, linked_status, linked_with, created, updated, isVerified };
}


async function authenticate({ email, password, ipAddress }) {
    const doctor = await db.Doctor.findOne({ email });

    if (!doctor || !bcrypt.compareSync(password, doctor.passwordHash)) {
        throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(doctor);
    const refreshToken = generateRefreshToken(doctor, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(doctor),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    const { doctor } = refreshToken;


    // replace old refresh token with a new one and save
    const newRefreshToken = generateRefreshToken(doctor, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = generateJwtToken(doctor);

    // return basic details and tokens
    return {
        ...basicDetails(doctor),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

async function revokeToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);

    // revoke token and save
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}

async function register(params, origin) {
    // validate
    if (await db.Doctor.findOne({ email: params.email })) {
        // send already registered error in email to prevent doctor enumeration
        //return await sendAlreadyRegisteredEmail(params.email, origin);
    }

    // create doctor object
    const doctor = new db.Doctor(params);

    // first registered doctor is an doctor
    // const isFirstDoctor = (await db.Doctor.countDocuments({})) === 0;
    doctor.role = Role.Doctor;
    doctor.verificationToken = randomTokenString();

    // hash password
    doctor.passwordHash = hash(params.password);
    doctor.schedule = schedule;
    // save doctor
    await doctor.save();
    console.log(doctor);

    // send email
    // await sendVerificationEmail(doctor, origin);
}

async function verifyEmail({ token }) {
    const doctor = await db.Doctor.findOne({ verificationToken: token });

    if (!doctor) throw 'Verification failed';

    doctor.verified = Date.now();
    doctor.verificationToken = undefined;
    await doctor.save();
}

async function forgotPassword({ email }, origin) {
    const doctor = await db.Doctor.findOne({ email });

    // always return ok response to prevent email enumeration
    if (!doctor) return;

    // create reset token that expires after 24 hours
    doctor.resetToken = {
        token: randomTokenString(),
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000)
    };
    await doctor.save();

    // send email
    await sendPasswordResetEmail(doctor, origin);
}

async function validateResetToken({ token }) {
    const doctor = await db.Doctor.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!doctor) throw 'Invalid token';
}

async function resetPassword({ token, password }) {
    const doctor = await db.Doctor.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!doctor) throw 'Invalid token';

    // update password and remove reset token
    doctor.passwordHash = hash(password);
    doctor.passwordReset = Date.now();
    doctor.resetToken = undefined;
    await doctor.save();
}

async function getAllHospital() {
    const hospitalList = await db.Hospital.find();
    return hospitalList.map(x => hospitalDetails(x));
}

async function getAllDoctor() {
    const doctorList = await db.Doctor.find();
    return doctorList;
}

async function getById(id) {
    const doctor = await getDoctor(id);
    return basicDetails(doctor);
}

async function create(params) {
    // validate
    if (await db.Doctor.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const doctor = new db.Doctor(params);
    doctor.verified = Date.now();

    // hash password
    doctor.passwordHash = hash(params.password);

    // save doctor
    await doctor.save();

    return basicDetails(doctor);
}

async function update(id, params) {
    const doctor = await getDoctor(id);

    // validate (if email was changed)
    if (params.email && doctor.email !== params.email && await db.Doctor.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = hash(params.password);
    }

    // copy params to doctor and save
    Object.assign(doctor, params);
    doctor.updated = Date.now();
    await doctor.save();

    return basicDetails(doctor);
}

async function _delete(id) {
    const doctor = await getDoctor(id);
    await doctor.remove();
}

// helper functions

async function getDoctor(id) {
    if (!db.isValidId(id)) throw 'Doctor not found';
    const doctor = await db.Doctor.findById(id);
    if (!doctor) throw 'Doctor not found';
    return doctor;
}

async function getRefreshToken(token) {
    const refreshToken = await db.DoctorRefreshToken.findOne({ token }).populate('doctor');
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

function generateJwtToken(doctor) {
    // create a jwt token containing the doctor id that expires in 15 minutes
    return jwt.sign({ sub: doctor.id, id: doctor.id }, secret, { expiresIn: '15m' });
}

function generateRefreshToken(doctor, ipAddress) {
    // create a refresh token that expires in 7 days
    return new db.DoctorRefreshToken({
        doctor: doctor.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(doctor) {
    const { id, title, firstName, lastName, email, doctorStatus, city, role, linked_status, linked_with, created, updated, isVerified, schedule } = doctor;
    return { id, title, firstName, lastName, email, doctorStatus, city, role, linked_status, linked_with, created, updated, isVerified, schedule };
}

function hospitalDetails(hospital) {
    const { id, name, hospitalStatus, hospitalAddress, city } = hospital;
    return { id, name, hospitalStatus, hospitalAddress, city };
}

async function sendVerificationEmail(doctor, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${doctor.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${doctor.verificationToken}</code></p>`;
    }

    await sendEmail({
        to: doctor.email,
        subject: 'Sign-up Verification API - Verify Email',
        html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`
    });
}

async function sendAlreadyRegisteredEmail(email, origin) {
    let message;
    if (origin) {
        message = `<p>If you don't know your password please visit the <a href="${origin}/account/forgot-password">forgot password</a> page.</p>`;
    } else {
        message = `<p>If you don't know your password you can reset it via the <code>/account/forgot-password</code> api route.</p>`;
    }

    await sendEmail({
        to: email,
        subject: 'Sign-up Verification API - Email Already Registered',
        html: `<h4>Email Already Registered</h4>
               <p>Your email <strong>${email}</strong> is already registered.</p>
               ${message}`
    });
}

async function sendPasswordResetEmail(doctor, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${doctor.resetToken.token}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${doctor.resetToken.token}</code></p>`;
    }

    await sendEmail({
        to: doctor.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}