const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    passwordHistory: { type: [String], required: true }, // Array of previous passwords
    isAdmin: { type: Boolean, default: false },
    failedLoginAttempts: { type: Number, default: 0 },
    lastFailedLogin: { type: Date, default: null },
    passwordLastChanged: { type: Date, default: Date.now }, // Track last password change date
});

// module.exports = mongoose.model('Users', userSchema);
const Users = mongoose.model("User", userSchema);
module.exports = Users;
