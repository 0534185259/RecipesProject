# RESTful API for Recipes & Users Management

This is a Node.js & Express-based RESTful API for managing recipes, users, and categories.  
It uses **MongoDB Atlas** as the cloud database, and **JWT** for authentication.  
All endpoints return JSON responses and follow proper HTTP methods and status codes.


##  Technologies Used

- Node.js
- Express.js
- MongoDB Atlas + Mongoose
- JWT – authentication
- dotenv – environment variables
- Middleware – for error handling and authentication


##  Project Structure

- `models/` – Mongoose schemas for Users, Recipes, and Categories
- `routes/` – Express route handlers
- `controllers/` – Logic for each API call
- `middlewares/` – Custom middleware (auth, error handler)
- `config/` – Database connection

---

##  User Roles

- **Admin** – Full access
- **User** – Limited access to own data
- **Guest** – Registered but inactive (no access)


##  Environment Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up `.env` file:
    ```env
    PORT=4200
    MONGODB_URI=mongodb+srv://zpnyry5089:Zpnyry2151%40@cluster0.vngwvmm.mongodb.net/RecipesDB?retryWrites=true&w=majority
    JWT_SECRET=12adfsdc@fsd
    ```
4. Run the project: `npm start`
5. Use **Postman** or **Thunder Client** to test endpoints

## API Endpoints

| Method | Route            | Description                |
| ------ | ---------------- | -------------------------- |
| POST   | `/auth/register` | Register a new user        |
| POST   | `/auth/login`    | Login and receive token    |
| GET    | `/auth/..`       | Get logged-in user details |


| Method | Route        | Description                |
| ------ | ------------ | -------------------------- |
| GET    | `/users`     | Get all users (admin only) |
| DELETE | `/users/:id` | Delete a user (admin only) |
| PATCH  | `/users/:id` | Update user info           |

| Method | Route               | Description                     |
| ------ | ------------------- | ------------------------------- |
| GET    | `/api/recipes`      | Get all recipes                 |
| GET    | `/api/recipes/{id}` | Get a recipe by its ID          |
| POST   | `/api/recipes`      | Create a new recipe             |
| PUT    | `/api/recipes/{id}` | Update an existing recipe by ID |
| DELETE | `/api/recipes/{id}` | Delete a recipe by its ID       |

| Method | Route            | Description                  |
| ------ | ---------------- | ---------------------------- |
| GET    | `/api/categories` | Get all categories                 |
| GET    | `/api/category/{id}` | Get a categoryg by its ID          |
| POST   | `/api/category`      | Create a new category             |
| PUT    | `/api/category/{id}` | Update an existing category by ID |
| DELETE | `/api/category/{id}` | Delete a category by its ID       |

