const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');
var otpGenerator = require('otp-generator')

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
    const busaccount = await db.BusinessAccount.findOne({ email });

    if (!busaccount || !busaccount.isVerified || !bcrypt.compareSync(password, busaccount.passwordHash)) {
        throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(busaccount);
    const refreshToken = generateRefreshToken(busaccount, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(busaccount),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    const { busaccount } = refreshToken;

    // replace old refresh token with a new one and save
    const newRefreshToken = generateRefreshToken(busaccount, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = generateJwtToken(busaccount);

    // return basic details and tokens
    return {
        ...basicDetails(busaccount),
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
    if (await db.BusinessAccount.findOne({ email: params.email })) {
        // send already registered error in email to prevent business account enumeration
        return await sendAlreadyRegisteredEmail(params.email, origin);
    }

    // create account object
    const busaccount = new db.BusinessAccount(params);

    // first registered account is an admin
    const isFirstAccount = (await db.BusinessAccount.countDocuments({})) === 0;
    busaccount.role = isFirstAccount ? Role.Admin : Role.Business;
    busaccount.verificationToken = randomTokenString();

    // hash password
    busaccount.passwordHash = hash(params.password);

    // save account
    await busaccount.save();

    // send email
    await sendVerificationEmail(busaccount, origin);
}

async function verifyEmail({ token }) {
    const busaccount = await db.BusinessAccount.findOne({ verificationToken: token });

    if (!busaccount) throw 'Verification failed in business service';

    busaccount.verified = Date.now();
    busaccount.verificationToken = undefined;
    await busaccount.save();
}

async function forgotPassword({ email }, origin) {
    const busaccount = await db.BusinessAccount.findOne({ email });

    // always return ok response to prevent email enumeration
    if (!busaccount) return;

    // create reset token that expires after 24 hours
    busaccount.resetToken = {
        token: randomTokenString(),
        expires: new Date(Date.now() + 24*60*60*1000)
    };
    await busaccount.save();

    // send email
    await sendPasswordResetEmail(busaccount, origin);
}

async function validateResetToken({ token }) {
    const busaccount = await db.BusinessAccount.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!busaccount) throw 'Invalid token';
}

async function resetPassword({ token, password }) {
    const busaccount = await db.BusinessAccount.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!busaccount) throw 'Invalid token';

    // update password and remove reset token
    busaccount.passwordHash = hash(password);
    busaccount.passwordReset = Date.now();
    busaccount.resetToken = undefined;
    await busaccount.save();
}

async function getAll() {
    const busaccounts = await db.BusinessAccount.find();
    return busaccounts.map(x => basicDetails(x));
}

async function getById(id) {
    const busaccount = await getAccount(id);
    return basicDetails(busaccount);
}

async function create(params) {
    // validate
    if (await db.BusinessAccount.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const busaccount = new db.BusinessAccount(params);
    busaccount.verified = Date.now();

    // hash password
    busaccount.passwordHash = hash(params.password);

    // save account
    await busaccount.save();

    return basicDetails(busaccount);
}

async function update(id, params) {
    const busaccount = await getAccount(id);

    // validate (if email was changed)
    if (params.email && busaccount.email !== params.email && await db.BusinessAccount.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = hash(params.password);
    }

    // copy params to account and save
    Object.assign(busaccount, params);
    busaccount.updated = Date.now();
    await busaccount.save();

    return basicDetails(busaccount);
}

async function _delete(id) {
    const busaccount = await getAccount(id);
    await busaccount.remove();
}

// helper functions

async function getAccount(id) {
    if (!db.isValidId(id)) throw 'Business Account not found';
    const busaccount = await db.BusinessAccount.findById(id);
    if (!busaccount) throw 'Business Account not found';
    return busaccount;
}

async function getRefreshToken(token) {
    const refreshToken = await db.RefreshToken.findOne({ token }).populate('busaccount');
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

function generateJwtToken(busaccount) {
    // create a jwt token containing the account id that expires in 15 minutes
    return jwt.sign({ sub: busaccount.id, id: busaccount.id }, config.secret, { expiresIn: '15m' });
}

function generateRefreshToken(busaccount, ipAddress) {
    // create a refresh token that expires in 7 days
    return new db.RefreshToken({
        busaccount: busaccount.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7*24*60*60*1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return  otpGenerator.generate(6, { upperCase: false, specialChars: false,digits:true,alphabets:false });
    //return crypto.randomBytes(40).toString('hex');
}

function basicDetails(busaccount) {
    const { id, nameOfBusiness, typeOfBusiness,contacts, bio, email, role, created, updated, isVerified } = busaccount;
    return { id, nameOfBusiness, typeOfBusiness, contacts,bio, email, role, created, updated, isVerified };
}

async function sendVerificationEmail(busaccount, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/busaccount/verify-email?token=${busaccount.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${busaccount.verificationToken}</code></p>`;
    }

    await sendEmail({
        to: busaccount.email,
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

async function sendPasswordResetEmail(busaccount, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/busaccount/reset-password?token=${busaccount.resetToken.token}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${busaccount.resetToken.token}</code></p>`;
    }

    await sendEmail({
        to: busaccount.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}