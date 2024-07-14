import mongoose from "mongoose";
import { ProductRepository } from "../src/repositories/productRepository.js";
const productRepository = new ProductRepository();
import assert from "assert";
import configObject from "./config/dotenv.config.js";
const { mongo_url } = configObject;

describe("Products test", () => {
  before(() => {
    mongoose
      .connect(mongo_url)
      .then(() =>
        console
          .log("Test de products contectado a la base de datos de MongoDB")
          .catch((error) =>
            console.log(
              "Error al intentarse conectar a la base de datos: ",
              error
            )
          )
      );
  });

  beforeEach(async () => {
    await mongoose.connection.collections.products.drop();
  });

  it("New product test", async () => {
    const newProduct = {
      title: "Producto Test",
      description: "descripción producto test",
      code: "codigo test",
      price: "1000",
      stock: "500",
      category: "categoría test",
      thumbnails: ["test"],
      owner: "admin",
    };

    const testResult = await productRepository.addProduct(newProduct);
    assert.ok(testResult._id);
  });

  after((done) => {
    mongoose.connection.close();
    done();
  });
});
