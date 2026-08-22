import { Router } from "express";
import * as authController from "../controllers/auth.controller.js";

const authRouter = Router();



/**
 *POST/api/auth/register
*/
authRouter.post("/register", authController.register);

/**
 * POST /api/auth/login
 */
authRouter.post("/login", authController.login);

/**
 * POST /api/auth/send-otp
 */
authRouter.post("/send-otp", authController.sendOTP);

/**
 * POST /api/auth/login-otp
 */
authRouter.post("/login-otp", authController.loginOTP);

/**
 * POST /api/auth/refresh
 */
authRouter.post("/refresh", authController.refresh);

/**
 * POST /api/auth/logout
 */
authRouter.post("/logout", authController.logout);

/**
 * POST /api/auth/logout-all
 */
authRouter.post("/logout-all", authController.logoutAll);

/**
 * GET /api/auth/sessions
 */
authRouter.get("/sessions", authController.getSessions);

/**
 * DELETE /api/auth/sessions/:sessionId
 */
authRouter.delete("/sessions/:sessionId", authController.deleteSession);

/***
 * GET /api/auth/get-me
 */
authRouter.get("/get-me", authController.getMe);

export default authRouter;