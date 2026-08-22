import userModel from "../models/user.model.js";
import sessionModel from "../models/session.model.js";
import otpModel from "../models/otp.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import mongoose from "mongoose";
import nodemailer from "nodemailer";

/**
 * @function register
 * @description Registers a new user, hashes the password using SHA-256, generates unique session identifiers,
 *              creates a database session entry, and signs JWT tokens (Access and Refresh) stored in secure cookies.
 * @param {Object} req - Express request object containing username, email, and password in the body.
 * @param {Object} res - Express response object.
 * @why SHA-256 hashing is used for cryptographic protection of user passwords. Hybrid session-token mechanism is
 *      employed where a unique sessionId is signed inside stateless JWTs and tracked in Mongoose to enable features 
 *      like immediate revocation, active session monitoring, and logging out of all devices.
 */
export async function register(req, res) {
    const { username, email, password } = req.body;

    // Check if the username or email is already taken to enforce uniqueness
    const isAlreadyRegistered = await userModel.findOne({
        $or: [
            { username },
            { email }
        ]
    });

    if (isAlreadyRegistered) {
        return res.status(409).json({
            message: "Username or email already exists"
        });
    }

    // Hash the password with SHA-256 for secure storage in the database
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    });

    // Generate a unique session ID to map this specific login instance in the database
    const sessionId = new mongoose.Types.ObjectId();

    // Sign the short-lived access token containing the user and session identifiers
    const accessToken = jwt.sign({
        id: user._id,
        sessionId
    }, config.JWT_SECRET, {
        expiresIn: "15m"
    });

    // Sign the long-lived refresh token used to request new access tokens
    const refreshToken = jwt.sign({
        id: user._id,
        sessionId
    }, config.JWT_SECRET, {
        expiresIn: "7d"
    });

    // Record the session details in the database to track active logins
    await sessionModel.create({
        _id: sessionId,
        userId: user._id,
        token: refreshToken,
        userAgent: req.headers["user-agent"] || "Unknown Device",
        ipAddress: req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown IP"
    });

    // Set the short-lived Access Token in an httpOnly cookie for automatic auth transmission
    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 15 * 60 * 1000 // 15 minutes
    });

    // Set the Refresh Token in an httpOnly cookie to prevent client-side JS access (XSS defense)
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
        message: "User registered successfully",
        user: {
            username: user.username,
            email: user.email,
        },
        token: accessToken
    });
}

/**
 * @function getMe
 * @description Retrieves details of the currently authenticated user by decoding the access token and
 *              verifying that the associated session is active and not revoked.
 * @param {Object} req - Express request object containing the access token in cookies or headers.
 * @param {Object} res - Express response object.
 * @why Ensures that revoked/deleted sessions (due to logout or manual termination) cannot be used even if
 *      the JWT has not yet reached its expiration time.
 */
export async function getMe(req, res) {
    try {
        const token = req.cookies.accessToken || req.cookies.token || req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "token not found"
            });
        }

        const decoded = jwt.verify(token, config.JWT_SECRET);
        
        // Query database to ensure session was not revoked or deleted
        const sessionExists = await sessionModel.exists({ _id: decoded.sessionId });
        if (!sessionExists) {
            return res.status(401).json({
                message: "Session expired or revoked"
            });
        }

        const user = await userModel.findById(decoded.id).select("-password");
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.status(200).json({
            user
        });
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

/**
 * @function login
 * @description Authenticates a user with email and password, verifies credentials, creates a new
 *              session entry, and issues rotated Access and Refresh tokens.
 * @param {Object} req - Express request object containing email and password in the body.
 * @param {Object} res - Express response object.
 * @why Enforces secure login validation, registers the new session (mapping user agent and IP), 
 *      and sets secure cookies to begin a new authenticated state.
 */
export async function login(req, res) {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required"
        });
    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Cryptographically compare input password against stored hashedPassword
        const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
        if (user.password !== hashedPassword) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        const sessionId = new mongoose.Types.ObjectId();

        const accessToken = jwt.sign({
            id: user._id,
            sessionId
        }, config.JWT_SECRET, {
            expiresIn: "15m"
        });

        const refreshToken = jwt.sign({
            id: user._id,
            sessionId
        }, config.JWT_SECRET, {
            expiresIn: "7d"
        });

        // Store the session context in Mongoose
        await sessionModel.create({
            _id: sessionId,
            userId: user._id,
            token: refreshToken,
            userAgent: req.headers["user-agent"] || "Unknown Device",
            ipAddress: req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown IP"
        });

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.status(200).json({
            message: "Logged in successfully",
            user: {
                username: user.username,
                email: user.email,
            },
            token: accessToken
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message
        });
    }
}

/**
 * @function refresh
 * @description Performs Refresh Token Rotation (RTR). Validates the client's current refresh token,
 *              re-verifies the session, and issues a new access token and a brand-new rotated refresh token.
 * @param {Object} req - Express request object containing the refresh token cookie.
 * @param {Object} res - Express response object.
 * @why Refresh Token Rotation prevents replay attacks. If an attacker intercepts a refresh token, reuse detection
 *      means the old token is invalidated. If a token is presented that doesn't match the current rotated value,
 *      it signals potential theft and the entire session is cleared/blocked.
 */
export async function refresh(req, res) {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({
            message: "Refresh token not found"
        });
    }

    try {
        const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
        
        // Find the active session using the session ID and the current refresh token
        const session = await sessionModel.findOne({ _id: decoded.sessionId, token: refreshToken });
        if (!session) {
            // Revocation / Theft detection: token has already been reused or is invalid. Clear credentials.
            res.clearCookie("accessToken");
            res.clearCookie("refreshToken");
            return res.status(401).json({
                message: "Invalid or revoked session"
            });
        }

        const user = await userModel.findById(decoded.id);
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Generate rotated token values
        const newAccessToken = jwt.sign({
            id: user._id,
            sessionId: session._id
        }, config.JWT_SECRET, {
            expiresIn: "15m"
        });

        const newRefreshToken = jwt.sign({
            id: decoded.id,
            sessionId: decoded.sessionId || session._id
        }, config.JWT_SECRET, {
            expiresIn: "7d"
        });

        // Rotate the token on the session model in the database
        session.token = newRefreshToken;
        session.userAgent = req.headers["user-agent"] || session.userAgent;
        session.ipAddress = req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress || session.ipAddress;
        await session.save();

        res.cookie("accessToken", newAccessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.status(200).json({
            message: "Access token refreshed successfully",
            accessToken: newAccessToken
        });
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired refresh token"
        });
    }
}

/**
 * @function logout
 * @description Logs out the user from the current session. Deletes the active session from the database
 *              and clears authentication cookies.
 * @param {Object} req - Express request object containing the refresh token cookie.
 * @param {Object} res - Express response object.
 * @why Revokes database record for the specific device session, ensuring the access and refresh tokens
 *      cannot be utilized anymore.
 */
export async function logout(req, res) {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
        try {
            const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
            await sessionModel.deleteOne({ _id: decoded.sessionId });
        } catch (e) {
            // Ignore error on invalid/expired token during logout
        }
    }
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(200).json({
        message: "Logged out successfully"
    });
}

/**
 * @function logoutAll
 * @description Revokes all active database sessions associated with the user, effectively logging them
 *              out from all devices and browser clients.
 * @param {Object} req - Express request object with credentials in cookies or header.
 * @param {Object} res - Express response object.
 * @why Enables user security controls (e.g. "Log out of all devices" if a device is lost or compromised).
 */
export async function logoutAll(req, res) {
    const token = req.cookies.accessToken || req.cookies.refreshToken || req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({
            message: "Not authenticated"
        });
    }

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET);
        // Wipe all sessions associated with the authenticated user ID
        await sessionModel.deleteMany({ userId: decoded.id });
        
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        
        res.status(200).json({
            message: "Logged out from all devices successfully"
        });
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

/**
 * @function getSessions
 * @description Retrieves a list of active login sessions for the authenticated user, indicating IP,
 *              User Agent, creation date, and highlighting the current active session.
 * @param {Object} req - Express request containing access credentials.
 * @param {Object} res - Express response object.
 * @why Promotes security transparency, allowing users to verify active devices accessing their account.
 */
export async function getSessions(req, res) {
    const token = req.cookies.accessToken || req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({
            message: "Not authenticated"
        });
    }

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET);
        
        const currentSessionExists = await sessionModel.exists({ _id: decoded.sessionId });
        if (!currentSessionExists) {
            return res.status(401).json({
                message: "Session expired or revoked"
            });
        }

        const sessions = await sessionModel.find({ userId: decoded.id }).select("-token");
        
        const mappedSessions = sessions.map(session => ({
            _id: session._id,
            userAgent: session.userAgent,
            ipAddress: session.ipAddress,
            createdAt: session.createdAt,
            isCurrent: session._id.toString() === decoded.sessionId
        }));

        res.status(200).json({
            sessions: mappedSessions
        });
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

/**
 * @function deleteSession
 * @description Terminates a specific active session by ID. If the terminated session matches the client's
 *              current active session, they are instantly logged out.
 * @param {Object} req - Express request containing the sessionId parameter.
 * @param {Object} res - Express response object.
 * @why Provides granular security controls, letting users revoke access from specific external devices.
 */
export async function deleteSession(req, res) {
    const token = req.cookies.accessToken || req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({
            message: "Not authenticated"
        });
    }

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET);
        const { sessionId } = req.params;

        if (!sessionId) {
            return res.status(400).json({
                message: "Session ID is required"
            });
        }

        const session = await sessionModel.findOne({ _id: sessionId, userId: decoded.id });
        if (!session) {
            return res.status(404).json({
                message: "Session not found"
            });
        }

        await sessionModel.deleteOne({ _id: sessionId });

        const isCurrentSession = sessionId === decoded.sessionId;
        if (isCurrentSession) {
            res.clearCookie("accessToken");
            res.clearCookie("refreshToken");
        }

        res.status(200).json({
            message: "Session terminated successfully",
            isCurrentSession
        });
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

/**
 * @function sendOTP
 * @description Generates a secure, temporary 6-digit One-Time Password (OTP) for passwordless auth, 
 *              saves/upserts it to the database, and attempts to send it via Nodemailer.
 * @param {Object} req - Express request containing the target email in the body.
 * @param {Object} res - Express response object.
 * @why Passwordless authentication via OTP minimizes phishing risk and credential reuse. Falls back
 *      to logging the code to the dev console and returning it in the API if SMTP config is absent,
 *      allowing seamless API development.
 */
export async function sendOTP(req, res) {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            message: "Email is required"
        });
    }

    try {
        // Generate a random 6-digit numerical string
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Upsert OTP record for this email
        await otpModel.findOneAndUpdate(
            { email },
            { otp, createdAt: new Date() },
            { upsert: true, new: true }
        );

        let sent = false;
        const useOAuth2 = process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN;
        const useSMTP = config.EMAIL_USER && config.EMAIL_PASS;

        if (useOAuth2 || useSMTP) {
            try {
                let transporter;
                if (useOAuth2) {
                    transporter = nodemailer.createTransport({
                        service: "gmail",
                        auth: {
                            type: "OAuth2",
                            user: process.env.GOOGLE_USER || config.EMAIL_USER,
                            clientId: process.env.GOOGLE_CLIENT_ID,
                            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                            refreshToken: process.env.GOOGLE_REFRESH_TOKEN
                        }
                    });
                } else {
                    transporter = nodemailer.createTransport({
                        host: config.EMAIL_HOST,
                        port: config.EMAIL_PORT,
                        secure: config.EMAIL_PORT === 465,
                        auth: {
                            user: config.EMAIL_USER,
                            pass: config.EMAIL_PASS
                        }
                    });
                }

                await transporter.sendMail({
                    from: `"Authentication System" <${process.env.GOOGLE_USER || config.EMAIL_USER}>`,
                    to: email,
                    subject: "Your Authentication OTP",
                    text: `Your OTP is: ${otp}. It is valid for 5 minutes.`,
                    html: `<h3>Your OTP is: <b>${otp}</b></h3><p>It is valid for 5 minutes.</p>`
                });
                sent = true;
            } catch (err) {
                console.error("Nodemailer error: ", err);
            }
        }

        const responseData = {
            message: sent ? "OTP sent to email successfully" : "OTP generated successfully (Fallback to local)"
        };

        if (!sent) {
            responseData.otp = otp; // Returned in response for testing/development when email configuration is missing
            console.log(`[DEV ONLY] OTP for ${email} is ${otp}`);
        }

        res.status(200).json(responseData);
    } catch (error) {
        return res.status(500).json({
            message: error.message
        });
    }
}

/**
 * @function loginOTP
 * @description Verifies the provided OTP. If valid, deletes the OTP record to prevent reuse, and looks
 *              up the user. If the user doesn't exist, it automatically creates a new user profile
 *              (passwordless registration), creates a session, and issues Access and Refresh tokens.
 * @param {Object} req - Express request containing email and OTP.
 * @param {Object} res - Express response object.
 * @why Enables frictionless, single-click signup/login via email verification, while ensuring the
 *      OTP is one-time use (deleting it instantly upon successful validation).
 */
export async function loginOTP(req, res) {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({
            message: "Email and OTP are required"
        });
    }

    try {
        const record = await otpModel.findOne({ email, otp });
        if (!record) {
            return res.status(400).json({
                message: "Invalid or expired OTP"
            });
        }

        // Instantly delete the verified OTP record to block replay/reuse attacks
        await otpModel.deleteOne({ email });

        let user = await userModel.findOne({ email });
        let isNewUser = false;

        if (!user) {
            // Automatically register the user if they don't exist under this email
            const username = email.split("@")[0] + "_" + Math.floor(1000 + Math.random() * 9000);
            const randomPassword = crypto.randomBytes(16).toString("hex");
            const hashedPassword = crypto.createHash("sha256").update(randomPassword).digest("hex");

            user = await userModel.create({
                username,
                email,
                password: hashedPassword
            });
            isNewUser = true;
        }

        const sessionId = new mongoose.Types.ObjectId();

        const accessToken = jwt.sign({
            id: user._id,
            sessionId
        }, config.JWT_SECRET, {
            expiresIn: "15m"
        });

        const refreshToken = jwt.sign({
            id: user._id,
            sessionId
        }, config.JWT_SECRET, {
            expiresIn: "7d"
        });

        await sessionModel.create({
            _id: sessionId,
            userId: user._id,
            token: refreshToken,
            userAgent: req.headers["user-agent"] || "Unknown Device",
            ipAddress: req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown IP"
        });

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.status(200).json({
            message: isNewUser ? "User registered and logged in via OTP successfully" : "Logged in via OTP successfully",
            user: {
                username: user.username,
                email: user.email,
            },
            token: accessToken
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message
        });
    }
}