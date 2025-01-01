import express from 'express';
import authController from '../controllers/auth.js';

const router = express.Router();

router.post('/login', authController.login);

router.post('/register', authController.register);

router.post('/send-otp', authController.sendOTP);

router.post('/verify-otp', authController.verifyOTP);

router.post('/forgot-password', authController.forgotPassword);

router.post('/reset-password', authController.resetPassword);

export default router;
