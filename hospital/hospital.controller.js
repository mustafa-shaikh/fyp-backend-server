const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('../_middleware/validate-request');
const authorize = require('../_middleware/authorize')
const Role = require('../_helpers/role');
const hospitalService = require('./hospital.service');
const doctorService = require('../doctor/doctor.service');
const { doctorDetails } = require('./hospital.service');

// routes
router.post('/signIn', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize(Role.Hospital), revokeTokenSchema, revokeToken);
router.post('/signUp', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.get('/', authorize(Role.Hospital), getAll);
//router.get('/doctorList', authorize(Role.Doctor), getAllDoctor); //line 56 new function
router.post('/linkedDoctors', getById);
router.post('/', authorize(Role.Hospital), createSchema, create);
router.put('/:id', authorize(Role.Hospital), updateSchema, update);
router.delete('/:id', authorize(), _delete);
router.post('/getDoctorById', authorize(Role.Hospital), createSchema, create);
router.get('/doctorList', authorize(Role.Hospital), getAllDoctors, linkDetails); //line 42 old func
router.post('/doctorDetails', authenticateSchema, authenticateDoctor, doctorDetails);

module.exports = router;

function linkDetails(req, res, next) {
    //console.log("taha details1")
    const ipAddress = req.ip;
    hospitalService.authenticate({ipAddress })
    .then(({ refreshToken, ...hospital }) => {
            setTokenCookie(res, refreshToken);
            res.json(hospital);
        })
        .catch(next);
}

function getAllDoctor(req, res, next) {
    hospitalService.getAll()
        .then(hospitals => res.json(hospitals))
        .catch(next);
}
 
function authenticateSchema(req, res, next) {
    const schema= Joi.object({
        email: Joi.string().required(),
        password: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function getAllDoctor(req, res, next) {
    doctorService.getAllDoctor()
        .then(doctorList => res.json(doctorList))
        .catch(next);
}

function authenticate(req, res, next) {
    const { email, password } = req.body;
    const ipAddress = req.ip;
    // console.log("Reached here")
    hospitalService.authenticate({ email, password, ipAddress })
    .then(({ refreshToken, ...hospital }) => {
            setTokenCookie(res, refreshToken);
            res.json(hospital);
        })
        .catch(next);
}

function authenticateDoctor(req, res, next) {
    const { email, password } = req.body;
    const ipAddress = req.ip;
    // console.log("authenticating")
    doctorService.authenticate({ email, password, ipAddress })
    .then(({ refreshToken, ...doctor }) => {
            setTokenCookie(res, refreshToken);
            res.json(doctor);
        })
        .catch(next);
}

function refreshToken(req, res, next) {
    const token = req.cookies.hRefreshToken;
    const ipAddress = req.ip;
    
    hospitalService.refreshToken({ token, ipAddress })
    .then(({ refreshToken, ...hospital }) => {
        setTokenCookie(res, refreshToken);
        res.json(hospital);
        })
        .catch(next);
}

function revokeTokenSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().empty('')
    });
    validateRequest(req, next, schema);
}

function revokeToken(req, res, next) {
    // accept token from request body or cookie
    const token = req.body.token || req.cookies.hRefreshToken;
    const ipAddress = req.ip;

    if (!token) return res.status(400).json({ message: 'Token is required' });

    // users can revoke their own tokens and hospitals can revoke any tokens
    if (!req.user.ownsToken(token) && req.user.role !== Role.Hospital) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    hospitalService.revokeToken({ token, ipAddress })
        .then(() => res.json({ message: 'Token revoked' }))
        .catch(next);
}

function registerSchema(req, res, next) {
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        //acceptTerms: Joi.boolean().valid(true).required()
    });
    validateRequest(req, next, schema);
}

function register(req, res, next) {
    hospitalService.register(req.body, req.get('origin'))
        .then(() => res.json({ message: 'Registration successful, please check your email for verification instructions' }))
        .catch(next);
}

function verifyEmailSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required()
    });
    validateRequest(req, next, schema);

}

function verifyEmail(req, res, next) {
    hospitalService.verifyEmail(req.body)
        .then(() => res.json({ message: 'Verification successful, you can now login' }))
        .catch(next);
}

function forgotPasswordSchema(req, res, next) {
    const schema = Joi.object({
        email: Joi.string().email().required()
    });
    validateRequest(req, next, schema);
}

function forgotPassword(req, res, next) {
    hospitalService.forgotPassword(req.body, req.get('origin'))
        .then(() => res.json({ message: 'Please check your email for password reset instructions' }))
        .catch(next);
}

function validateResetTokenSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function validateResetToken(req, res, next) {
    hospitalService.validateResetToken(req.body)
        .then(() => res.json({ message: 'Token is valid' }))
        .catch(next);
}

function resetPasswordSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required()
    });
    validateRequest(req, next, schema);
}

function resetPassword(req, res, next) {
    hospitalService.resetPassword(req.body)
        .then(() => res.json({ message: 'Password reset successful, you can now login' }))
        .catch(next);
}

function getAll(req, res, next) {
    hospitalService.getAll()
        .then(hospitals => res.json(hospitals))
        .catch(next);
}

function getById(req, res, next) {
    // users can get their own hospital and hospitals can get any hospital
    // if (req.params.id !== req.user.id && req.user.role !== Role.Hospital) {
    //     return res.status(401).json({ message: 'Unauthorized' });
    // }
    console.log(req.body);
    hospitalService.getById(req.body.id)
        .then(hospital => hospital ? res.json(hospital) : res.sendStatus(404))
        .catch(next);
}

function getAllDoctors(req, res, next) {
    // users can get their own hospital and hospitals can get any hospital
    // if (req.params.id !== req.user.id && req.user.role !== Role.Hospital) {
    //     return res.status(401).json({ message: 'Unauthorized' });
    // }
    console.log(req.body);
    hospitalService.getAllDoctors()
        .then(doctors => doctors ? res.json(doctors) : res.sendStatus(404))
        .catch(next);
}

function createSchema(req, res, next) {
    const schema = Joi.object({
        type: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        role: Joi.string().valid(Role.Hospital, Role.User).required()
    });
    validateRequest(req, next, schema);
}

function create(req, res, next) {
    hospitalService.create(req.body)
        .then(hospital => res.json(hospital))
        .catch(next);
}

function updateSchema(req, res, next) {
    const schemaRules = {
        // type: Joi.string().empty(''),
        firstName: Joi.string().empty(''),
        lastName: Joi.string().empty(''),
        email: Joi.string().email().empty(''),
        password: Joi.string().min(6).empty(''),
        confirmPassword: Joi.string().valid(Joi.ref('password')).empty('')
    };

    // only hospitals can update role
    if (req.user.role === Role.Hospital) {
        schemaRules.role = Joi.string().valid(Role.Hospital, Role.Hospital).empty('');
    }

    const schema = Joi.object(schemaRules).with('password', 'confirmPassword');
    validateRequest(req, next, schema);
}

function update(req, res, next) {
    // users can update their own hospital and hospitals can update any hospital
    if (req.params.id !== req.user.id && req.user.role !== Role.Hospital) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    

    hospitalService.update(req.params.id, req.body)
        .then(hospital => res.json(hospital))
        .catch(next);
}

function _delete(req, res, next) {
    // users can delete their own hospital and hospitals can delete any hospital
    if (req.params.id !== req.user.id && req.user.role !== Role.Hospital) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    hospitalService.delete(req.params.id)
        .then(() => res.json({ message: 'Hospital deleted successfully' }))
        .catch(next);
}

// helper functions

function setTokenCookie(res, token) {
    // create cookie with refresh token that expires in 7 days
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + 7*24*60*60*1000)
    };
    res.cookie('hRefreshToken', token, cookieOptions);
}