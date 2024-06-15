// BASE DE DATOS:
// Instalación de mongoose: npm i mongoose.
// Importación del módulo de mongoose:
import mongoose from "mongoose";
// Importación del objeto de configuración:
import configObject from "./config/dotenv.config.js";
// Variable que guarda la key de la base de datos de Mongo:
const { mongo_url } = configObject;
// Conexión a la base de datos de Atlas en la nube con un then y catch, este último en caso que haya que atrapar un error:
class DataBase {
  static #instance;
  //Se declara una variable estática y privada:
  constructor() {
    mongoose.connect(mongo_url);
  }

  static getInstance() {
    if (this.#instance) {
      console.log("Conexion previa");
      return this.#instance;
    }

    this.#instance = new DataBase();
    console.log("Conexión generada");
    return this.#instance;
  }
}

export default DataBase.getInstance();
