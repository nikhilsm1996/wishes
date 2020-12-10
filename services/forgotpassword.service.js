const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');

module.exports = {
    
     forgotPassword
}

async function forgotPassword({ email }, origin) {
    const account = await db.Account.findOne({ email });
    const busaccount = await db.BusinessAccount.findOne({ email });

    // always return ok response to prevent email enumeration
    if (!account && !busaccount) {
        return;
    
    }
    else if (account){
    // create reset token that expires after 24 hours
    account.resetToken = {
        token: randomTokenString(),
        expires: new Date(Date.now() + 24*60*60*1000)
    };
    await account.save();

    // send email
    await sendPasswordResetEmail(account, origin);
    }

    else if(busaccount){
// create reset token that expires after 24 hours
busaccount.resetToken = {
    token: randomTokenString(),
    expires: new Date(Date.now() + 24*60*60*1000)
};
await busaccount.save();

// send email
await sendPasswordResetEmail(busaccount, origin);
}


    }





async function sendPasswordResetEmail(account, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken.token}`;
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

async function sendPasswordResetEmail(busaccount, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${busaccount.resetToken.token}`;
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


function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}
