import { model, Schema } from 'mongoose';

const recipeSchema = new Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    categories: [{ type: Schema.Types.ObjectId, ref: 'Category' }],
    timePreperation: { type: Number, required: true }, // in minutes
    difficulty: {
        type: Number,
        min: 1,
        max: 5,
        required: true,
        validate: {
            validator: Number.isInteger,
            message: '{VALUE} is not an integer value'
        }
    },
    publishedDate: { type: Date, default: Date.now },
    layers: [
        {
            name: { type: String, required: true },       // שם השכבה (למשל "בסיס עוגה")
            ingredients: [String],                        // רשימת מצרכים
        }
    ],
    instructions: {
        type: [String],
        required: [true, 'חובה לציין הוראות הכנה'],
        validate: {
            validator: function (arr) {
                return Array.isArray(arr) && arr.length > 0;
            },
            message: 'יש להזין לפחות שלב אחד בהכנה'
        }
    },
    image: String,
    isPrivate: { type: Boolean, default: false }, // האם המתכון פרטי,
    owner: { type: Schema.Types.ObjectId, ref: 'User', required: true }, // בעל המתכון
});

export default model('Recipe', recipeSchema);