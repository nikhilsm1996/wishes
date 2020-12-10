const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');

module.exports = {
    
    resetPassword
}

async function resetPassword({ token, password }) {
    const busaccount = await db.BusinessAccount.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    const account = await db.Account.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });



    if (!busaccount && !account)
     {throw 'Invalid token';}

else if (busaccount){
    // update password and remove reset token
    busaccount.passwordHash = hash(password);
    busaccount.passwordReset = Date.now();
    busaccount.resetToken = undefined;
    await busaccount.save();
}
else if(account){
 // update password and remove reset token
 account.passwordHash = hash(password);
 account.passwordReset = Date.now();
 account.resetToken = undefined;
 await account.save();


}
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

async function sendPasswordResetEmail(account, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/busaccount/reset-password?token=${account.resetToken.token}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${account.resetToken.token}</code></p>`;
    }

    await sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}
