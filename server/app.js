import express from 'express';
import userRoutes from './routes/user.route.js';
import categoryRoutes from './routes/category.route.js';
import recipeRoutes from './routes/recipe.route.js';

import cors from 'cors';
import morgan from 'morgan';   
import { config } from 'dotenv'; 
import {connectDB} from './config/db.js';


config(); 
connectDB();
const app = express();
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));
app.use(cors())

app.use(morgan('dev'));


app.use('/api/user', userRoutes); 
app.use('/api/category', categoryRoutes);
app.use('/api/recipe', recipeRoutes);


app.get("/", (req, res) => {
    res.send("Welcome to Our Recipe Site");
});

app.listen(5000, () => {
    console.log('Server is running on port 5000');
});
