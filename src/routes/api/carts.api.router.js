// Importación del Router de Express JS:
import { Router } from "express";
// Importación del manejador de carts:
import { CartController } from "../../controllers/cartController.js";
// Creación del Router de Carts:
const cartsApiRouter = Router();
// Llamado de la función constructora:
const cartController = new CartController();
// Importación del middleware de auth:
import { authMiddleware } from "../../middlewares/auth.js";

cartsApiRouter.use(authMiddleware);

// Rutas de carts:
// Post que crea un nuevo cart:
cartsApiRouter.post("/", cartController.newCart);

// Get que lista los productos que pertenezcan al cart por id:
cartsApiRouter.get("/:cid", cartController.getCartById);

// Post que agrega como objeto el producto al array de products del cart seleccionado:
cartsApiRouter.post("/:cid/product/:pid", cartController.addProduct);

// Delete que elimina un producto del cart:
cartsApiRouter.delete("/:cid/product/:pid", cartController.deleteProductById);

// Put que actualiza productos en el cart:
cartsApiRouter.put("/:cid", cartController.updateCart);

// Put que actualiza la cantidad de productos en el cart:
cartsApiRouter.put("/:cid/product/:pid", cartController.updateProductQuantity);

// Delete que vacía el cart:
cartsApiRouter.delete("/:cid", cartController.emptyCart);

// Post que finaliza la compra:
cartsApiRouter.post("/:cid/checkout", cartController.checkOut);

// Exportación del router de carts para utilizarlo desde app.js:
export { cartsApiRouter };
