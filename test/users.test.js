import mongoose from "mongoose";
import { UserController } from "../src/controllers/userController.js";
const userController = new UserController();
import assert from "assert";
import configObject from "./config/dotenv.config.js";
const { mongo_url } = configObject;

describe("Users test", () => {
  before(() => {
    mongoose
      .connect(mongo_url)
      .then(() =>
        console
          .log("Test de users contectado a la base de datos de MongoDB")
          .catch((error) =>
            console.log(
              "Error al intentarse conectar a la base de datos: ",
              error
            )
          )
      );
  });

  beforeEach(async () => {
    await mongoose.connection.collections.users.drop();
  });

  it("New user test", async () => {
    const newUser = {
      first_name: "Juan",
      last_name: "Test",
      email: "juan@test.com",
      cart: newCart._id,
      password: createHash("passwordTest"),
      age: "30",
    };

    const testResult = await userController.register(newUser);
    assert.ok(testResult._id);
  });

  after((done) => {
    mongoose.connection.close();
    done();
  });
});
