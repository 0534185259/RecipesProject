import { model, Schema } from "mongoose"

const categorySchema = new Schema({
    code: { type: String, unique: true, required: true },
    description: { type: String },
    recipes: [{ type: Schema.Types.ObjectId, ref: 'Recipe' }],
    numOfRecipes: { 
        type: Number, 
        default : function() {
            return this.recipes ? this.recipes.length : 0;
        },
        immutable: true // Prevent changes to this field after creation
    }
});
export default model('Category', categorySchema);