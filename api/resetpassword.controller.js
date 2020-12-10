const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const busauthorize = require('_middleware/busauthorize');
const Role = require('_helpers/role');
const resetpasswordService = require('../services/resetpassword.service');

router.post('/reset-password', resetPasswordSchema, resetPassword);

module.exports = router

function resetPasswordSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required()
    });
    validateRequest(req, next, schema);
}

function resetPassword(req, res, next) {
    resetpasswordService.resetPassword(req.body)
        .then(() => res.json({ message: 'Password reset successful, you can now login' }))
        .catch(next);
}

