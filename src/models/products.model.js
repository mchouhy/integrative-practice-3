// Importación de Mongoose:
import mongoose from "mongoose";

// Definición de un "Schema": objeto que define la forma de los documentos:
const productSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  price: {
    type: Number,
    required: true,
  },
  img: {
    type: String,
  },
  thumbnails: {
    // Un array de strings.
    type: [String],
  },
  stock: {
    type: Number,
    required: true,
  },
  code: {
    type: String,
    required: true,
    // Ponemos unique porque tendremos una validación que no permita agregar dos productos con el mismo código.
    unique: true,
  },
  status: {
    type: Boolean,
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  owner: {
    type: String,
    required: true,
    default: "admin",
  },
});

// Exportación del model para utilizarlo en productService.js. En model se pasa como primer argumento el nombre de la colección y como segundo el "Schema":
export const productModel = mongoose.model("Product", productSchema);
