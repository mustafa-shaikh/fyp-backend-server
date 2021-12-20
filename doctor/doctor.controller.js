﻿const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const authorize = require('_middleware/authorize')
const Role = require('_helpers/role');
const doctorService = require('./doctor.service');

// routes
router.post('/authenticate', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize(Role.Doctor), revokeTokenSchema, revokeToken);
router.post('/register', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.put('/:id', authorize(Role.Doctor), updateSchema, update);


router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken);
router.get('/', authorize(Role.Doctor), getAll);
router.get('/:id', authorize(), getById);
router.post('/', authorize(Role.Doctor), createSchema, create);
router.delete('/:id', authorize(Role.Doctor), _delete);

module.exports = router;

function authenticateSchema(req, res, next) {
    const schema = Joi.object({
        email: Joi.string().required(),
        password: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function authenticate(req, res, next) {
    const { email, password } = req.body;
    const ipAddress = req.ip;
    doctorService.authenticate({ email, password, ipAddress })
        .then(({ refreshToken, ...doctor }) => {
            setTokenCookie(res, refreshToken);
            res.json(doctor);
        })
        .catch(next);
}

function refreshToken(req, res, next) {
    const token = req.cookies.dRefreshToken;
    const ipAddress = req.ip;
    doctorService.refreshToken({ token, ipAddress })
        .then(({ refreshToken, ...doctor }) => {
            setTokenCookie(res, refreshToken);
            res.json(doctor);
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
    const token = req.body.token || req.cookies.dRefreshToken;
    const ipAddress = req.ip;

    if (!token) return res.status(400).json({ message: 'Token is required' });

    // users can revoke their own tokens and doctors can revoke any tokens
    if (!req.user.ownsToken(token) && req.user.role !== Role.Doctor) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    doctorService.revokeToken({ token, ipAddress })
        .then(() => res.json({ message: 'Token revoked' }))
        .catch(next);
}

function registerSchema(req, res, next) {
    const schema = Joi.object({
        // title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        acceptTerms: Joi.boolean().valid(true).required()
    });
    validateRequest(req, next, schema);
}

function register(req, res, next) {
    doctorService.register(req.body, req.get('origin'))
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
    doctorService.verifyEmail(req.body)
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
    doctorService.forgotPassword(req.body, req.get('origin'))
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
    doctorService.validateResetToken(req.body)
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
    doctorService.resetPassword(req.body)
        .then(() => res.json({ message: 'Password reset successful, you can now login' }))
        .catch(next);
}

function getAll(req, res, next) {
    doctorService.getAll()
        .then(doctors => res.json(doctors))
        .catch(next);
}

function getById(req, res, next) {
    // users can get their own doctor and doctors can get any doctor
    if (req.params.id !== req.user.id && req.user.role !== Role.Doctor) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    doctorService.getById(req.params.id)
        .then(doctor => doctor ? res.json(doctor) : res.sendStatus(404))
        .catch(next);
}

function createSchema(req, res, next) {
    const schema = Joi.object({
        title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        role: Joi.string().valid(Role.Doctor, Role.User).required()
    });
    validateRequest(req, next, schema);
}

function create(req, res, next) {
    doctorService.create(req.body)
        .then(doctor => res.json(doctor))
        .catch(next);
}

function updateSchema(req, res, next) {
    const schemaRules = {
        title: Joi.string().empty(''),
        firstName: Joi.string().empty(''),
        lastName: Joi.string().empty(''),
        email: Joi.string().email().empty(''),
        city: Joi.string().empty(''),
        password: Joi.string().min(6).empty(''),
        confirmPassword: Joi.string().valid(Joi.ref('password')).empty('')
    };

    const schema = Joi.object(schemaRules).with('password', 'confirmPassword');
    validateRequest(req, next, schema);
}

function update(req, res, next) {
    // users can update their own doctor and doctors can update any doctor
    if (req.params.id !== req.user.id && req.user.role !== Role.Doctor) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    doctorService.update(req.params.id, req.body)
        .then(doctor => res.json(doctor))
        .catch(next);
}

function _delete(req, res, next) {
    // users can delete their own doctor and doctors can delete any doctor
    if (req.params.id !== req.user.id && req.user.role !== Role.Doctor) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    doctorService.delete(req.params.id)
        .then(() => res.json({ message: 'Doctor deleted successfully' }))
        .catch(next);
}

// helper functions

function setTokenCookie(res, token) {
    // create cookie with refresh token that expires in 7 days
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + 7*24*60*60*1000)
    };
    res.cookie('dRefreshToken', token, cookieOptions);
}