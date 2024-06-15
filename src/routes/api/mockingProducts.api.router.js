// Importación del Router de Express JS:
import { Router } from "express";
// Importación del manejador de productos:
import { getProductsMock } from "../../controllers/mockingProductsController.js";
// Creación del Router de Products:
const mockingProductsApiRouter = Router();

mockingProductsApiRouter.get("/", getProductsMock);

export { mockingProductsApiRouter };
