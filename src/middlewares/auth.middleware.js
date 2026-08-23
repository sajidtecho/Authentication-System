import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";
import userModel from "../models/user.model.js";

/**
 * @function requireAuth
 * @description Middleware that extracts the access token, verifies the signature and expiration,
 *              validates that the session has not been revoked/deleted in the database,
 *              and attaches the authenticated user (minus password) and session metadata to the request.
 */
export async function requireAuth(req, res, next) {
    try {
        const token = req.cookies.accessToken || req.cookies.token || req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "Authentication token not found"
            });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, config.JWT_SECRET);
        } catch (err) {
            return res.status(401).json({
                message: "Invalid or expired token"
            });
        }

        // Query database to ensure session is still active and not revoked
        const session = await sessionModel.findOne({ _id: decoded.sessionId });
        if (!session || session.revoked) {
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

        // Attach credentials and session contexts to req for downstream handlers
        req.user = user;
        req.session = session;

        next();
    } catch (error) {
        return res.status(500).json({
            message: error.message
        });
    }
}
