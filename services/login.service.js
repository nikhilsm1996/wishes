const config = require('config.json');
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
    
    
}

async function authenticate({ email, password, ipAddress }) {
    const account = await db.Account.findOne({ email });
    const busaccount = await db.BusinessAccount.findOne({ email });
    console.log("Entering Authenticate Function")
    console.log(account)
    console.log(busaccount)

        

    if (busaccount && account !== null) {
        throw 'Email or password is incorrect ';
        
    }  
    else if (account != null && account.role == 'User' ){
        console.log("entering else if")
    

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}
else if ( busaccount != null && busaccount.role=='Business'){
    console.log("entering second else if")
 
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
     
 
 }
}


}

    //refresh token of  normal account
    async function refreshToken({ token, ipAddress }) {
        const refreshToken = await getRefreshToken(token);
        const { account } = refreshToken;
    
        // replace old refresh token with a new one and save
        const newRefreshToken = generateRefreshToken(account, ipAddress);
        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        refreshToken.replacedByToken = newRefreshToken.token;
        await refreshToken.save();
        await newRefreshToken.save();
    
        // generate new jwt
        const jwtToken = generateJwtToken(account);
    
        // return basic details and tokens
        return {
            ...basicDetails(account),
            jwtToken,
            refreshToken: newRefreshToken.token
        };
    }
    //revoke token for normal user
    
    async function revokeToken({ token, ipAddress }) {
        const refreshToken = await getRefreshToken(token);
    
        // revoke token and save
        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        await refreshToken.save();
    }
    
    //generate JWT Token for normal user

    function generateJwtToken(account) {
        // create a jwt token containing the account id that expires in 15 minutes
        return jwt.sign({ sub: account.id, id: account.id }, config.secret, { expiresIn: '15m' });
    }
    //generate Refresh Token for normal user
    function generateRefreshToken(account, ipAddress) {
        // create a refresh token that expires in 7 days
        return new db.RefreshToken({
            account: account.id,
            token: randomTokenString(),
            expires: new Date(Date.now() + 7*24*60*60*1000),
            createdByIp: ipAddress
        });
    }


    // refresh toke for business user
    async function refreshTokenB({ token, ipAddress }) {
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
    
    //revoke token for business user
    async function revokeTokenB({ token, ipAddress }) {
        const refreshToken = await getRefreshToken(token);
    
        // revoke token and save
        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        await refreshToken.save();
    }
    
    //generate JWT Token for business user

    function generateJwtTokenB(busaccount) {
        // create a jwt token containing the account id that expires in 15 minutes
        return jwt.sign({ sub: busaccount.id, id: busaccount.id }, config.secret, { expiresIn: '15m' });
    }
    //generate Refresh Token for Business user
    function generateRefreshTokenB(account, ipAddress) {
        // create a refresh token that expires in 7 days
        return new db.RefreshToken({
            account: account.id,
            token: randomTokenString(),
            expires: new Date(Date.now() + 7*24*60*60*1000),
            createdByIp: ipAddress
        });
    }



function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

function basicDetails(busaccount) {
    const { id, nameOfBusiness, email, role, created, updated } = busaccount;
    return { id, nameOfBusiness,  email, role, created, updated };
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

