import Category from '../models/category.model.js';
import Recipe from '../models/recipe.model.js';
import mongoose from 'mongoose';

// 1. קבלת כל הקטגוריות
export const getAllCategories = async (req, res, next) => {
  try {
    const categories = await Category.find();
     res.json(categories);
  } catch (err) {
    next(err);
  }
};
//get category by id or name
export const getCategoryByIdOrName = async (req, res, next) => {
  try {
    const { idOrName } = req.params;

    const query = mongoose.Types.ObjectId.isValid(idOrName)
      ? { _id: idOrName }
      : { name: idOrName };

    const category = await Category.findOne(query);
    if (!category) {
      return res.status(404).json({ error: 'קטגוריה לא נמצאה' });
    }

    res.json(category);
  } catch (err) {
    next(err);
  }
};
//get categorues with recipes
export const getCategoriesWithRecipes = async (req, res, next) => {
  try {
    const categories = await Category.find();
    const result = [];

    for (const category of categories) {
      const recipes = await Recipe.find({ categories: category._id });
      result.push({ category, recipes });
    }

    res.json(result);
  } catch (err) {
    next(err);
  }
};
//get recipes by category id
export const getRecipesByCategory = async (req, res, next) => {
  try {
    const { categoryId } = req.params;

    const recipes = await Recipe.find({ categories: categoryId });

    res.json(recipes);
  } catch (err) {
    next(err);
  }
};
