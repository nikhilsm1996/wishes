const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    email: { type: String, unique: true, required: true },
    passwordHash: { type: String, required: true },
    title: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    
    personalDetails: {
        address:{type: String},
        city:{type:String},
        nationality:{type: String},
        birthday:{type:Date},
        starSign:{type:String},
        profession:{type:String},
        education:{type:String},
        maritalStatus:{type:String}
    },
    favourites: {
        colour: {type:String},
        sport:{type:String},
        book:{type:String},
        author:{type:String},
        meal:{type:String},
        hobby:{type:String},
        number:{type:String},
        music:{type:String},
        season:{type:String}
    },
    


    topThree: {
        dreamDestination: [{type:String}],
        inventionsOfAllTime:[{type:String}],
        childhoodGames:[{type:String}],
        tvSeries:[{type:String}],
        songs:[{type:String}],
        movies:[{type:String}],
        artists:[{type:String}],
        celebrities:[{type:String}],
        issues:[{type:String}],



    },
    acceptTerms: Boolean,
    role: { type: String, required: true },
    verificationToken: String,
    verified: Date,
    resetToken: {
        token: String,
        expires: Date
    },
    passwordReset: Date,
    created: { type: Date, default: Date.now },
    updated: Date
});

schema.virtual('isVerified').get(function () {
    return !!(this.verified || this.passwordReset);
});

schema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    transform: function (doc, ret) {
        // remove these props when object is serialized
        delete ret._id;
        delete ret.passwordHash;
    }
});

module.exports = mongoose.model('Account', schema);