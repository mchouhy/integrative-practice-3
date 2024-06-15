// Importación del Router de Express JS:
import { Router } from "express";
// Importación del manejador de productos:
import { ProductController } from "../../controllers/productController.js";
// Creación del Router de Products:
const productsApiRouter = Router();
// Llamado de la función constructora:
const productController = new ProductController();

// Rutas de productos:
// Get que retorna todos los productos o los productos limitados aplicando un query:
productsApiRouter.get("/", productController.getProducts);

// Get que retorna un producto por id ingresado:
productsApiRouter.get("/:prodId", productController.getProductById);

// Post que agrega un nuevo producto al archivo json de productos:
productsApiRouter.post("/", productController.addProduct);

// Put que actualiza el producto seleccionado por id:
productsApiRouter.put("/:prodId", productController.updateProduct);

// Delete que elimina el producto seleccionado por id:
productsApiRouter.delete("/:prodId", productController.deleteProductById);

// Exportación del router para utilizarlo desde app.js:
export { productsApiRouter };
