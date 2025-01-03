import express from 'express';
import authRoute from './auth.js';
import userRoute from './user.js';

const router = express.Router();

router.use('/auth', authRoute);

router.use('/user', userRoute);

export default router;
