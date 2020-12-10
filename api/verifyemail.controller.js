const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const authorize = require('_middleware/authorize')
const busauthorize = require('_middleware/busauthorize');
const Role = require('_helpers/role');
const verifyemailService = require('C:/Users/LENOVO/node-mongo-signup-verification-api/services/verifyemail.service')


router.post('/verify-email', verifyEmailSchema, verifyEmail);

module.exports = router;

function verifyEmailSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function verifyEmail(req, res, next) {
    verifyemailService.verifyEmail(req.body)
        .then(() => res.json({ message: 'Verification successful, you can now login' }))
        .catch(next);
        
}


