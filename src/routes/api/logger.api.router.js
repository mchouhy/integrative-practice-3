// Importación del Router de Express JS:
import { Router } from "express";
// Importación del manejador de logger:
import { loggerController } from "../../controllers/loggerController.js";
// Creación del Router de Logger:
const loggerApiRouter = Router();

loggerApiRouter.get("/", loggerController);

export { loggerApiRouter };
