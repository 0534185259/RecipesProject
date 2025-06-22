
import {User} from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import { generateToken } from '../models/user.model.js';

export const getAllUsers = async (req, res, next) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        next({ message: error.message });
    }
};


export const register = async (req, res, next) => {
    console.log('Request reg:');
    try {
        const { username, email, password, role } = req.body;
        const newUser = new User({ username, email, password, role });
         const sevedUser = await newUser.save();
        const token = generateToken(sevedUser);
       res.status(201).json({ message: 'The user has been added successfully', username: sevedUser.username, token });
    } catch (error) {
        next({ message: error.message });
    }
};

export const login = async (req, res, next) => {


    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return next({ message: 'user not found', status: 401 }); 
        }
        const isAuthorization = await bcrypt.compare(password, user.password);
        if (!isAuthorization) {
            return next({ message: 'user not found', status: 401 }); 
        }

        const token = generateToken(user);
        res.json({ message: 'User logged in successfully' ,username: user.username, token });
    } catch (error) {
        next({ message: error.message });
    }
};


export const update= async (req, res, next) => {
    try {
        const { id } = req.params;
        const { username, email, password, role } = req.body;

        const user = { username, email, role };

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            user.password = hashedPassword;
        }

        const updatedUser = await User.findByIdAndUpdate(id, updatedData, { new: true });
        if (!updatedUser) {
            return next({ message: 'User not found', status: 404 });
        }

        res.json({ message: 'User updated successfully', user: updatedUser });
    } catch (error) {
        next({ message: error.message });
    }
};
export const deleteUser = async (req, res, next) => {
    try {
        const { id } = req.params;
        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) {
            return next({ message: 'User not found', status: 404 });
        }
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        next({ message: error.message });
    }
};
