import mongoose from "mongoose";
import { CartRepository } from "../src/repositories/cartRepository.js";
const productRepository = new CartRepository();
import assert from "assert";
import configObject from "./config/dotenv.config.js";
const { mongo_url } = configObject;

describe("Carts test", () => {
  before(() => {
    mongoose
      .connect(mongo_url)
      .then(() =>
        console
          .log("Test de carts contectado a la base de datos de MongoDB")
          .catch((error) =>
            console.log(
              "Error al intentarse conectar a la base de datos: ",
              error
            )
          )
      );
  });

  beforeEach(async () => {
    await mongoose.connection.collections.carts.drop();
  });

  it("Nuevo cart test", async () => {
    const testResult = await this.cartRepository.addCart();
    assert.ok(testResult._id);
  });

  it("Traer nuevo cart test por id", async () => {
    const cart = await this.cartRepository.addCart();
    const testResult = await this.cartRepository.getCartById(result._id);
    assert.ok(testResult._id);
  });

  after((done) => {
    mongoose.connection.close();
    done();
  });
});
