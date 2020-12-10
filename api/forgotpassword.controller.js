const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const authorize = require('_middleware/authorize')
const Role = require('_helpers/role');
const forgotpasswordService = require('../services/forgotpassword.service');

router.post('/forgot-password', forgotPasswordSchema, forgotPassword);

module.exports = router


function forgotPasswordSchema(req, res, next) {
    const schema = Joi.object({
        email: Joi.string().email().required()
    });
    validateRequest(req, next, schema);
}

function forgotPassword(req, res, next) {
    forgotpasswordService.forgotPassword(req.body, req.get('origin'))
        .then(() => res.json({ message: 'Please check your email for password reset instructions' }))
        .catch(next);
}