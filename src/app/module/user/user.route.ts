import { Router } from 'express';
import { upload } from '../../lib/multer';
import { UserController } from './user.controller';

const router = Router()

router.patch("/profile-image", upload.single("profileImage"), UserController.uploadProfileImage);

export const UserRoutes = router
