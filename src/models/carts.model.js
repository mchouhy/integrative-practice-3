// Importación de Mongoose:
import mongoose from "mongoose";

// Definición de un "Schema": objeto que define la forma de los documentos:
const cartSchema = new mongoose.Schema({
  products: [
    {
      product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true,
      },
      quantity: {
        type: Number,
        required: true,
      },
    },
  ],
});

// Middleware pre que realiza la población automáticamente - "pre hook":
cartSchema.pre("findOne", function (next) {
  this.populate("products.product", "_id title price");
  next();
});

// Exportación del model para utilizarlo en cartManager.js. En model se pasa como primer argumento el nombre de la colección y como segundo el "Schema":
export const cartModel = mongoose.model("carts", cartSchema);
