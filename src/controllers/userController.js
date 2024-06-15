import { UserModel } from "../models/user.model.js";
import { cartModel } from "../models/carts.model.js";
import jwt from "jsonwebtoken";
import { createHash, isValidPassword } from "../utils/hashbcrypt.js";
import { UserDTO } from "../dto/user.dto.js";

export class UserController {
  async register(request, response) {
    const { first_name, last_name, email, password, age } = request.body;
    try {
      const userExists = await UserModel.findOne({ email });
      if (userExists) {
        return response
          .status(400)
          .send(
            "Error. Ya existe un usuario registrado con el correo electrónico ingresado."
          );
      }

      const newCart = new cartModel();
      await newCart.save();

      const newUser = new UserModel({
        first_name,
        last_name,
        email,
        cart: newCart._id,
        password: createHash(password),
        age,
      });

      await newUser.save();

      const token = jwt.sign({ user: newUser }, "coderhouse", {
        expiresIn: "1h",
      });

      response.cookie("coderCookieToken", token, {
        maxAge: 4000000,
        httpOnly: true,
      });

      response.redirect("/api/users/profile");
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .send("Error interno del servidor al intentar registrar el usuario.");
    }
  }

  async login(request, response) {
    const { email, password } = request.body;
    try {
      const userExists = await UserModel.findOne({ email });

      if (!userExists) {
        return response
          .status(401)
          .send(
            "Error. No existe un usuario registrado con el correo electrónico ingresado."
          );
      }

      const validPassword = isValidPassword(password, userExists);
      if (!validPassword) {
        return response.status(401).send("Error. La contraseña es incorrecta.");
      }

      const token = jwt.sign({ user: userExists }, "coderhouse", {
        expiresIn: "1h",
      });

      response.cookie("coderCookieToken", token, {
        maxAge: 4000000,
        httpOnly: true,
      });

      response.redirect("/api/users/profile");
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .send("Error interno del servidor al intentar iniciar sesión.");
    }
  }

  async profile(request, response) {
    const userDTO = new UserDTO(
      request.user.first_name,
      request.user.last_name,
      request.user.role
    );
    const isAdmin = request.user.role === "admin";
    response.render("profile", { user: userDTO, isAdmin });
  }

  async logout(request, response) {
    response.clearCookie("coderCookieToken");
    response.redirect("/");
  }

  async admin(request, response) {
    if (request.user.user.role !== "admin") {
      return response
        .status(403)
        .send("Acceso denegado. Tienes que ser admin para ingresar.");
    }
    response.render("admin");
  }
}
