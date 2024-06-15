// Importación de Express JS:
import { Router } from "express";
// Creación del Router de Express JS:
const viewsRouter = Router();
// Importación del manejador de views:
import { ViewController } from "../controllers/view.controller.js";
// Llamado de la función de viewController:
const viewController = new ViewController();
// Importación de passport:
import passport from "passport";
// Importación del roleChecker:
import { roleChecker } from "../middlewares/roleChecker.js";
import { authMiddleware } from "../middlewares/auth.js";

// Ruta GET para renderizar los productos:
viewsRouter.get(
  "/products",
  roleChecker(["usuario"]),
  passport.authenticate("jwt", { session: false }),
  authMiddleware,
  viewController.renderProducts
);

// Ruta GET para renderizar el cart:
viewsRouter.get("/carts/:cid", viewController.renderCart);

// Ruta GET para renderizar el login:
viewsRouter.get("/login", viewController.renderLogin);

// Ruta GET para renderizar el register:
viewsRouter.get("/register", viewController.renderRegister);

// Ruta GET para renderizar los productos en tiempo real para el admin:
viewsRouter.get(
  "/realtimeproducts",
  roleChecker(["admin"]),
  viewController.renderRealTimeProducts
);

// Ruta GET para renderizar el login:
viewsRouter.get("/chat", roleChecker(["usuario"]), viewController.renderChat);

// Ruta GET para renderizar el home:
viewsRouter.get("/", viewController.renderHomePage);

export default viewsRouter;
