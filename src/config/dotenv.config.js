// Importación de dotenv:
import dotenv from "dotenv";
// Importación del programa de commander:
import program from "../utils/commander.js";

const { mode } = program.opts();

dotenv.config({
  path: mode === "produccion" ? "./.env.production" : "./.env.develop",
});

const configObject = {
  mongo_url: process.env.MONGO_DB_KEY,
  port: process.env.PORT,
  logger_env: process.env.ENVIRONMENT,
};

export default configObject;
