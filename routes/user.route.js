import { Router } from "express";
import {  getAllUsers, login, register, update,deleteUser } from "../controllers/userController.js";
import { checkAdmin, checkAuth } from "../middleWeares/authorization.middleware.js";  

const router = Router();


router.get('/', checkAuth, checkAdmin, getAllUsers);
router.post('/', register);

router.post('/login', login);


router.put('/:id', update);

router.delete('/:id', deleteUser);


export default router;
