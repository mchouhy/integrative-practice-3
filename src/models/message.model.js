// Importación de Mongoose:
import mongoose from "mongoose";

// Definición de un "Schema": objeto que define la forma de los documentos:
const messageSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    require: true,
  },
});

// Exportación del model. En model se pasa como primer argumento el nombre de la colección y como segundo el "Schema":
export const messageModel = mongoose.model("messages", messageSchema);
