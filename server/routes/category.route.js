import { Router } from "express";
import {  getRecipesByCategory, getCategoriesWithRecipes, getCategoryByIdOrName, getAllCategories } from "../controllers/categotyController.js";
import { checkAdmin, checkAuth } from "../middleWeares/authorization.middleWare.js";
const router = Router();


router.get('/', checkAuth, checkAdmin, getAllCategories);
router.get('/getCategoriesWithRecipes', checkAuth, checkAdmin, getCategoriesWithRecipes);
router.get('/:idOrName', checkAuth, checkAdmin, getCategoryByIdOrName);
router.get('/getRecipesByCategory/:categoryId', checkAuth, checkAdmin, getRecipesByCategory);

export default router;
