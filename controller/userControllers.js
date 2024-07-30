const Users = require("../model/usermodel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");



const loginUser = async (req, res) => {
    console.log(req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({
            success: false,
            message: "Please enter all fields",
        });
    }

    try {
        const user = await Users.findOne({ email: email });
        if (!user) {
            return res.json({
                success: false,
                message: "User does not exist.",
            });
        }

        const maxFailedAttempts = 3;
        const lockoutDuration = 15 * 60 * 1000; // 15 minutes in milliseconds

        if (user.failedLoginAttempts >= maxFailedAttempts) {
            const now = new Date();
            const timeSinceLastAttempt = now - new Date(user.lastFailedLogin);
            const timeLeft = lockoutDuration - timeSinceLastAttempt;

            if (timeSinceLastAttempt < lockoutDuration) {
                const minutesLeft = Math.ceil(timeLeft / (60 * 1000));

                return res.json({
                    success: false,
                    message: `Too many failed attempts. Your account is locked. Please try again in ${minutesLeft} minute(s).`,
                    attemptsLeft: 0,
                    timeLeft: minutesLeft,
                });
            }

            user.failedLoginAttempts = 0;
            user.lastFailedLogin = null;
            await user.save();
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            user.failedLoginAttempts += 1;
            user.lastFailedLogin = new Date();
            await user.save();

            const attemptsLeft = maxFailedAttempts - user.failedLoginAttempts;

            return res.json({
                success: false,
                message: `Password doesn't match. You have ${attemptsLeft} attempt(s) left.`,
                attemptsLeft: attemptsLeft,
                timeLeft: null,
            });
        }

        // Check if the password is about to expire (90 days)
        const passwordAge = Date.now() - new Date(user.passwordLastChanged).getTime();
        const days90 = 20 * 24 * 60 * 60 * 1000; // 90 days in milliseconds
        const daysLeft = Math.ceil((days90 - passwordAge) / (24 * 60 * 60 * 1000)); // Days left until expiration

        if (daysLeft <= 0) {
            return res.status(403).json({
                success: false,
                message: "Your password has expired. Please change your password.",
                passwordExpired: true,
            });
        } else if (daysLeft <= 10) {
            // Warn user if the password will expire in the next 10 days
            return res.status(200).json({
                success: true,
                message: `User logged in successfully. Your password will expire in ${daysLeft} day(s). Please consider changing it soon.`,
                token: token,
                userData: user,
                passwordExpiryWarning: true,
                daysLeft: daysLeft,
            });
        }

        user.failedLoginAttempts = 0;
        user.lastFailedLogin = null;
        await user.save();
//  session created and session delete
        const token = jwt.sign(
            { id: user._id, isAdmin: user.isAdmin },
            process.env.JWT_TOKEN_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({
            success: true,
            message: "User logged in successfully.",
            token: token,
            userData: user,
        });

    } catch (error) {
        console.log(error);
        res.json({
            success: false,
            message: "Server Error",
        });
    }
};



//*! Register logic
const createUser = async (req, res) => {
    console.log(req.body);

    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
        return res.json({
            success: false,
            message: "Please enter all fields",
        });
    }

    try {
        const existingUser = await Users.findOne({ email: email });
        if (existingUser) {
            return res.json({
                success: false,
                message: "User already exists.",
            });
        }

        const randomSalt = await bcrypt.genSalt(10);
        const encryptedPassword = await bcrypt.hash(password, randomSalt);

        const newUser = new Users({
            firstName: firstName,
            lastName: lastName,
            email: email,
            password: encryptedPassword,
            passwordHistory: [encryptedPassword], // Store the password in the password history array
        });

        await newUser.save();
        res.json({
            success: true,
            message: "User created successfully.",
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: "Server Error",
        });
    }
};

const changePassword = async (req, res) => {
    try {
        console.log(req.body);
        const { oldPassword, newPassword, userId } = req.body;

        const user = await Users.findById(userId);

        if (!user) {
            return res.json({
                success: false,
                message: "User not found",
            });
        }

        const isMatched = await bcrypt.compare(oldPassword, user.password);

        if (!isMatched) {
            return res.json({
                success: false,
                message: "Old password is incorrect",
            });
        }

        if (newPassword.length < 8) {
            return res.json({
                success: false,
                message: "New password must be at least 8 characters long",
            });
        }

        for (let oldHashedPassword of user.passwordHistory) {
            const isPasswordUsedBefore = await bcrypt.compare(newPassword, oldHashedPassword);
            if (isPasswordUsedBefore) {
                return res.json({
                    success: false,
                    message: "New password cannot be the same as any of the previous passwords.",
                });
            }
        }

        const newHashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = newHashedPassword;
        user.passwordHistory.push(newHashedPassword);
        user.passwordLastChanged = new Date(); // Update the password last changed date
        await user.save();

        res.json({
            success: true,
            message: "Password changed successfully",
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: "Server Error",
            error: error.message,
        });
    }
};

module.exports = {
    createUser,
    loginUser,
    changePassword,
};



