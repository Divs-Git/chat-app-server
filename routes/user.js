import express from 'express';
import userController from '../controllers/user.js';
import authController from '../controllers/auth.js';

const router = express.Router();

router.patch('/update-me', authController.protect, userController.updateMe);

export default router;
