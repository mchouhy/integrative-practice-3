// IMPORTACIONES:
// Importación de Express JS (https://expressjs.com/en/starter/hello-world.html):
import express from "express";
// Creación de la app que utilizará Express JS y Handlebars:
const app = express();
// Importación del motor de plantillas Handlebars (https://www.npmjs.com/package/express-handlebars):
import { engine } from "express-handlebars";
// Importación del módulo handlebarse para utilizar un helper personalizado:
import Handlebars from "handlebars";
// Importación de las rutas del api de productos:
import { productsApiRouter } from "./routes/api/products.api.router.js";
// Importación de las rutas del api de carts:
import { cartsApiRouter } from "./routes/api/carts.api.router.js";
// Importación de las rutas del api de usuarios:
import { usersApiRouter } from "./routes/api/users.api.router.js";
// Importación de las rutas del api de logger:
import { loggerApiRouter } from "./routes/api/logger.api.router.js";
// Importación de las rutas de views:
import viewsRouter from "./routes/views.router.js";
// Importación de las rutas de mocking products:
import { mockingProductsApiRouter } from "./routes/api/mockingProducts.api.router.js";
// Importación de la conexión a la base de datos de Mongo Atlas:
import "./database.js";
// Importación de Cors:
import cors from "cors";
// Importación de path:
import path from "path";
// Importación de Passport:
import passport from "passport";
// Importación de la función para inicializar Passport:
import initializePassport from "./config/passport.config.js";
// Importación del objeto de configuración:
import configObject from "./config/dotenv.config.js";
// Importación de file to path:
import { fileURLToPath } from "url";
// Importación del middleware de auth:
import { authMiddleware } from "./middlewares/auth.js";
// Importación de cookie parser:
import cookieParser from "cookie-parser";
// Importación del manejador de errores:
import errorHandler from "./middlewares/errors.js";
// Importación de Logger:
import { addLogger } from "./middlewares/logger.js";
// Variables env:
const { port } = configObject;
// Importación de swagger:
import swaggerUiExpress from "swagger-ui-express";
import { specs } from "./config/swagger.config.js";
// MIDDLEWARES:
// Middleware que permite analizar los cuerpos de las solicitudes con datos codificados en URL y hacerlos accesibles en req.body:
app.use(express.urlencoded({ extended: true }));
// Función que permite comunicarnos con el servidor en formato JSON:
app.use(express.json());
// Directorio raíz desde el cual Express servirá los archivos estáticos cuando se realicen solicitudes HTTP:
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, "public")));
// Función de cors:
app.use(cors());
// Passport:
initializePassport();
app.use(passport.initialize());
app.use(cookieParser());
// Middleware de auth de passport:
app.use(authMiddleware);
// Manejo de errores:
app.use(errorHandler);
// Logger:
app.use(addLogger);

// HANDLEBARS:
// Crea una instancia del motor de plantillas Handlebars:
const hbs = engine({
  handlebars: Handlebars,
});
// Aplicación del motor de plantillas Handlebars a todos los archivos con la extensión ".handlebars":
app.engine("handlebars", hbs);
// Registra el helper 'hasRole'
Handlebars.registerHelper("hasRole", function (roles, role, options) {
  return roles.includes(role) ? options.fn(this) : options.inverse(this);
});
// Renderización de las vistas de la aplicación a través de Handlebars:
app.set("view engine", "handlebars");
// Directorio raíz desde el cual deben leerse los archivos con la extensión ".handlebars":
app.set("views", "./src/views");

// RUTAS:
// Endpoint de la ruta de api products:
app.use("/api/products", productsApiRouter);
// Endpoint de la ruta de api carts:
app.use("/api/carts", cartsApiRouter);
// Endpoint de la ruta de api users:
app.use("/api/users", usersApiRouter);
// Endpoint de la ruta de api mocking products:
app.use("/mockingproducts", mockingProductsApiRouter);
// Endpoint de la ruta de api logger test:
app.use("/api/loggertest", loggerApiRouter);
// Endpoint de la ruta de views:
app.use("/", viewsRouter);
// Swagger:
app.use("/apidocs", swaggerUiExpress.serve, swaggerUiExpress.setup(specs));
// Cache false para poder ver los cambios de desarrollo en handlebars:
app.set("view cache", false);

// PUERTO:
// Función que escucha cualquier cambio en el servidor:
const httpServer = app.listen(port, () =>
  console.log(
    `Escuchando cualquier cambio en el puerto: http://localhost:${port}`
  )
);

// Generación de instancia del manager de sockets:
import { SocketManager } from "./sockets/socketManager.js";
new SocketManager(httpServer);
