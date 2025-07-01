import { Router } from "express";
import {
    getUserRecipes, deleteRecipe, updateRecipe, addRecipe, getRecipeById,
    getRecipesByMaxPreperTime, getAllRecipes
} from "../controllers/recipeController.js";
import { checkAdmin, checkAuth } from "../middleWeares/authorization.middleWare.js";

const router = Router();


router.get('/', checkAuth, checkAdmin, getAllRecipes);
router.get('/getUserRecipes', checkAuth, checkAdmin, getUserRecipes);
router.get('/getRecipesByMaxPreperTime', checkAuth, checkAdmin, getRecipesByMaxPreperTime);
router.get('/:id', checkAuth, checkAdmin, getRecipeById);
router.post('/', addRecipe);
router.put('/:id', updateRecipe);
router.delete('/:id', deleteRecipe);


export default router;
