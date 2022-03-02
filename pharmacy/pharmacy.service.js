const {secret} = require('../config.js');
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
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({ email, password, ipAddress }) {
    const pharmacy = await db.Pharmacy.findOne({ email });
    // if (!pharmacy || !pharmacy.isVerified || !bcrypt.compareSync(password, hospital.
        if (!pharmacy || !bcrypt.compareSync(password, pharmacy.passwordHash)) {
            throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(pharmacy);
    const refreshToken = generateRefreshToken(pharmacy, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(pharmacy),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {    
    const refreshToken = await getRefreshToken(token);
    const { hospital } = refreshToken;
    
    

    // replace old refresh token with a new one and save
    const newRefreshToken = generateRefreshToken(hospital, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = generateJwtToken(hospital);

    // return basic details and tokens
    return {
        ...basicDetails(hospital),
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
    if (await db.Pharmacy.findOne({ email: params.email })) {
        // send already registered error in email to prevent pharmacy enumeration
        // return await sendAlreadyRegisteredEmail(params.email, origin);
    }
    
    // create hospital object
    const pharmacy = new db.Pharmacy(params);

    // first registered hospital is an admin
    // const isFirstHospital = (await db.Hospital.countDocuments({})) === 0;
    pharmacy.role = Role.Pharmacy;
    pharmacy.verificationToken = randomTokenString();
    
    // hash password
    pharmacy.passwordHash = hash(params.password);
    
    // save hospital
    await pharmacy.save();
    
    // send email
    // await sendVerificationEmail(pharmacy, origin);
}

async function verifyEmail({ token }) {

    const hospital = await db.Hospital.findOne({ verificationToken: token });

    if (!hospital) throw 'Verification failed';

    hospital.verified = Date.now();
    hospital.verificationToken = undefined;
    await hospital.save();
}

async function forgotPassword({ email }, origin) {
    const hospital = await db.Hospital.findOne({ email });

    // always return ok response to prevent email enumeration
    if (!hospital) return;

    // create reset token that expires after 24 hours
    hospital.resetToken = {
        token: randomTokenString(),
        expires: new Date(Date.now() + 24*60*60*1000)
    };
    await hospital.save();

    // send email
    await sendPasswordResetEmail(hospital, origin);
}

async function validateResetToken({ token }) {
    const hospital = await db.Hospital.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!hospital) throw 'Invalid token';
}

async function resetPassword({ token, password }) {
    const hospital = await db.Hospital.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!hospital) throw 'Invalid token';

    // update password and remove reset token
    hospital.passwordHash = hash(password);
    hospital.passwordReset = Date.now();
    hospital.resetToken = undefined;
    await hospital.save();
}

async function getAll() {
    const hospitals = await db.Hospital.find();
    return hospitals.map(x => basicDetails(x));
}

async function getById(id) {
    const hospital = await getHospital(id);
    return basicDetails(hospital);
}

async function create(params) {
    // validate
    if (await db.Hospital.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const hospital = new db.Hospital(params);
    hospital.verified = Date.now();

    // hash password
    hospital.passwordHash = hash(params.password);

    // save hospital
    await hospital.save();

    return basicDetails(hospital);
}

async function update(id, params) {
    const hospital = await getHospital(id);

    // validate (if email was changed)
    if (params.email && hospital.email !== params.email && await db.Hospital.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = hash(params.password);
    }

    // copy params to hospital and save
    Object.assign(hospital, params);
    hospital.updated = Date.now();
    await hospital.save();

    return basicDetails(hospital);
}

async function _delete(id) {
    const hospital = await getHospital(id);
    await hospital.remove();
}

// helper functions

async function getHospital(id) {
    if (!db.isValidId(id)) throw 'Hospital not found';
    const hospital = await db.Hospital.findById(id);
    if (!hospital) throw 'Hospital not found';

    return hospital;
}

async function getRefreshToken(token) {
    const refreshToken = await db.HospitalRefreshToken.findOne({ token }).populate('hospital');
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

function generateJwtToken(hospital) {
    // create a jwt token containing the hospital id that expires in 15 minutes
    return jwt.sign({ sub: hospital.id, id: hospital.id }, secret, { expiresIn: '15m' });
}

function generateRefreshToken(hospital, ipAddress) {

    // create a refresh token that expires in 7 days
    return new db.HospitalRefreshToken({
        hospital: hospital.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7*24*60*60*1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(pharmacy) {
    const { id,  name, pharmacyStatus, email, role, created, updated, isVerified } = pharmacy;
    return { id, name, pharmacyStatus ,email, role, created, updated, isVerified };
}

async function sendVerificationEmail(pharmacy, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${hospital.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${hospital.verificationToken}</code></p>`;
    }

    await sendEmail({
        to: hospital.email,
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

async function sendPasswordResetEmail(hospital, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${hospital.resetToken.token}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${hospital.resetToken.token}</code></p>`;
    }

    await sendEmail({
        to: hospital.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}