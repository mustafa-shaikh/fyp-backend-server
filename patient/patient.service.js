const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');

module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({ email, password, ipAddress }) {
    const patient = await db.Patient.findOne({ email });

    if (!patient || !patient.isVerified || !bcrypt.compareSync(password, patient.passwordHash)) {
        throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(patient);
    const refreshToken = generateRefreshToken(patient, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(patient),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    const { patient } = refreshToken;

    // replace old refresh token with a new one and save
    const newRefreshToken = generateRefreshToken(patient, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = generateJwtToken(patient);

    // return basic details and tokens
    return {
        ...basicDetails(patient),
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
    if (await db.Patient.findOne({ email: params.email })) {
        // send already registered error in email to prevent patient enumeration
        return await sendAlreadyRegisteredEmail(params.email, origin);
    }

    // create patient object
    const patient = new db.Patient(params);

    // first registered patient is an patient
    // const isFirstPatient = (await db.Patient.countDocuments({})) === 0;
    patient.role = Role.Patient;
    patient.verificationToken = randomTokenString();

    // hash password
    patient.passwordHash = hash(params.password);

    // save patient
    await patient.save();

    // send email
    await sendVerificationEmail(patient, origin);
}

async function verifyEmail({ token }) {
    const patient = await db.Patient.findOne({ verificationToken: token });

    if (!patient) throw 'Verification failed';

    patient.verified = Date.now();
    patient.verificationToken = undefined;
    await patient.save();
}

async function forgotPassword({ email }, origin) {
    const patient = await db.Patient.findOne({ email });

    // always return ok response to prevent email enumeration
    if (!patient) return;

    // create reset token that expires after 24 hours
    patient.resetToken = {
        token: randomTokenString(),
        expires: new Date(Date.now() + 24*60*60*1000)
    };
    await patient.save();

    // send email
    await sendPasswordResetEmail(patient, origin);
}

async function validateResetToken({ token }) {
    const patient = await db.Patient.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!patient) throw 'Invalid token';
}

async function resetPassword({ token, password }) {
    const patient = await db.Patient.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!patient) throw 'Invalid token';

    // update password and remove reset token
    patient.passwordHash = hash(password);
    patient.passwordReset = Date.now();
    patient.resetToken = undefined;
    await patient.save();
}

async function getAll() {
    const patients = await db.Patient.find();
    return patients.map(x => basicDetails(x));
}

async function getById(id) {
    const patient = await getPatient(id);
    return basicDetails(patient);
}

async function create(params) {
    // validate
    if (await db.Patient.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const patient = new db.Patient(params);
    patient.verified = Date.now();

    // hash password
    patient.passwordHash = hash(params.password);

    // save patient
    await patient.save();

    return basicDetails(patient);
}

async function update(id, params) {
    const patient = await getPatient(id);

    // validate (if email was changed)
    if (params.email && patient.email !== params.email && await db.Patient.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = hash(params.password);
    }

    // copy params to patient and save
    Object.assign(patient, params);
    patient.updated = Date.now();
    await patient.save();

    return basicDetails(patient);
}

async function _delete(id) {
    const patient = await getPatient(id);
    await patient.remove();
}

// helper functions

async function getPatient(id) {
    if (!db.isValidId(id)) throw 'Patient not found';
    const patient = await db.Patient.findById(id);
    if (!patient) throw 'Patient not found';
    return patient;
}

async function getRefreshToken(token) {
    const refreshToken = await db.PatientRefreshToken.findOne({ token }).populate('patient');
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

function generateJwtToken(patient) {
    // create a jwt token containing the patient id that expires in 15 minutes
    return jwt.sign({ sub: patient.id, id: patient.id }, config.secret, { expiresIn: '15m' });
}

function generateRefreshToken(patient, ipAddress) {
    // create a refresh token that expires in 7 days
    return new db.PatientRefreshToken({
        patient: patient.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7*24*60*60*1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(patient) {
    const { id, firstName, lastName, patientStatus, email, role, created, updated, isVerified } = patient;
    return { id, firstName, lastName, patientStatus ,email, role, created, updated, isVerified };
}

async function sendVerificationEmail(patient, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${patient.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${patient.verificationToken}</code></p>`;
    }

    await sendEmail({
        to: patient.email,
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

async function sendPasswordResetEmail(patient, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${patient.resetToken.token}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${patient.resetToken.token}</code></p>`;
    }

    await sendEmail({
        to: patient.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}