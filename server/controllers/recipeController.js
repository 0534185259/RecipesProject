import  Recipe  from '../models/recipe.model.js';
import jwt from 'jsonwebtoken';

//methode to get all recipes with optional search, limit, and pagination
export const getAllRecipes = async (req, res, next) => {

  const { search = '', limit = 10, page = 1 } = req.query;

  const filter = {
    name: { $regex: search, $options: 'i' }
  };

  const recipes = await Recipe.find(filter)
    .limit(Number(limit))
    .skip((Number(page) - 1) * Number(limit));

  res.json(recipes);
};
// methode to get recipes by max preparation time
export const getRecipesByMaxPreperTime = async (req, res, next) => {
  try {
    const { maxPrepTime } = req.query;

    if (!maxPrepTime) {
      return res.status(400).json({ error: 'חובה לציין זמן הכנה מקסימלי (maxPrepTime)' });
    }

    const recipes = await Recipe.find({
      timePreperation: { $lte: Number(maxPrepTime) }
    });

    res.json(recipes);
  } catch (err) {
    res.status(500).json({ error: 'שגיאה בשליפת מתכונים לפי זמן הכנה' });
  }
};



// methode to get a recipe by id
export const getRecipeById = async (req, res, next) => {
  try {
    const { id } = req.params;
    const recipe = await Recipe.findById(id).populate('categories').populate('owner');
    if (!recipe) {
      return next({ message: 'Recipe not found', status: 404 });
    }
    res.json(recipe);


  }
  catch (error) {
    next({ message: error.message });
  }
}
// methode to add a new recipe
export const addRecipe = async (req, res, next) => {
  try {
    const recipe = req.body;
    const newRecipe = new Recipe(recipe);
    const savedRecipe = await newRecipe.save();
    res.status(201).json({ message: 'Recipe added successfully', recipe: savedRecipe });
  } catch (error) {
    next({ message: error.message });
  }
};

// methode to update a recipe by id
export const updateRecipe = async (req, res, next) => {
  try {
    const { id } = req.params;
    const recipeData = req.body;
    const updatedRecipe = await Recipe.findByIdAndUpdate(id, recipeData, { new: true });
    if (!updatedRecipe) {
      return next({ message: 'Recipe not found', status: 404 });
    }
    res.json({ message: 'Recipe updated successfully', recipe: updatedRecipe });
  } catch (error) {
    next({ message: error.message });
  }
};
// methode to delete a recipe by id
export const deleteRecipe = async (req, res, next) => {
  try {
    const { id } = req.params;
    const deletedRecipe = await Recipe.findByIdAndDelete(id);
    if (!deletedRecipe) {
      return next({ message: 'Recipe not found', status: 404 });
    }
    res.json({ message: 'Recipe deleted successfully' });
  } catch (error) {
    next({ message: error.message });
  }
};


// methode to get all recipes of a user
export const getUserRecipes = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'טוקן לא נשלח' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded._id;
    const recipes = await Recipe.find({ owner: userId })
    res.json(recipes);
  } catch (err) {
    res.status(401).json({ error: 'גישה נדחתה – טוקן לא תקין או שגיאה' });
  }
};
