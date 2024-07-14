import { userModel } from "../models/user.model.js";
import { cartModel } from "../models/carts.model.js";
import jwt from "jsonwebtoken";
import { createHash, isValidPassword } from "../utils/hashbcrypt.js";
import { UserDTO } from "../dto/user.dto.js";
import { tokenReset } from "../utils/tokenReset.js";
import { EmailManager } from "../services/email.js";
const emailManager = new EmailManager();
export class UserController {
  async register(request, response) {
    const { first_name, last_name, email, password, age } = request.body;
    try {
      const userExists = await userModel.findOne({ email });
      if (userExists) {
        return response
          .status(400)
          .send(
            "Error. Ya existe un usuario registrado con el correo electrónico ingresado."
          );
      }

      const newCart = new cartModel();
      await newCart.save();

      const newUser = new userModel({
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
    const successMessage = request.query.success;
    try {
      if (successMessage) {
        response.render("login", { success: successMessage });
      }

      const userExists = await userModel.findOne({ email });

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
    const isPremium = request.user.role === "premium";
    response.render("profile", { user: userDTO, isAdmin, isPremium });
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

  async premium(request, response) {
    if (request.user.user.role !== "premium") {
      return response
        .status(403)
        .send("Acceso denegado. Tienes que ser usuario premium para ingresar.");
    }
    response.render("premium");
  }

  async passwordResetRequest(request, response) {
    const { email } = request.body;
    try {
      const user = await userModel.findOne({ email });
      if (!user) return response.status(404).send("Usuario inexistente.");
      const token = tokenReset();
      user.resetToken = {
        token: token,
        expiresAt: new Date(Date.now() + 3600000),
      };
      await user.save();
      await emailManager.passwordResetEmail(email, user.first_name, token);
      response.redirect("/password-reset");
    } catch (error) {
      console.error(error);
      response.status(500).send("Error interno del servidor.");
    }
  }

  async resetPassword(request, response) {
    const { email, password, token } = request.body;
    try {
      const user = await userModel.findOne({ email });
      if (!user)
        return response.render("password-reset", {
          error: "No existe un usuario con el correo ingresado.",
        });

      const resetToken = user.resetToken;
      console.log({ token, resetToken });
      if (!resetToken || resetToken.token !== token) {
        return response.render("request-password-reset", {
          error: "El token de restablecimiento de contraseña es inválido",
        });
      }

      const now = new Date();
      if (now > tokenReset.expiresAt)
        return response.render("password-reset", {
          error:
            "Se ha expirado la validez del token ingresado. Vuelve a iniciar el proceso de restablecimiento.",
        });

      if (isValidPassword(password, user))
        return response.render("password-reset", {
          error: "La nueva contraseña tiene que ser diferente a la anterior.",
        });

      user.password = createHash(password);
      user.resetToken = undefined;
      await user.save();
      // response.render("login", {
      //   success:
      //     "¡Contraseña reestablecida con éxito! Ya puedes iniciar sesión.",
      // });
      return response.redirect(
        "/login?success=" +
          encodeURIComponent(
            "¡Contraseña reestablecida con éxito! Ya puedes iniciar sesión."
          )
      );
    } catch (error) {
      console.error(error);
      return response.status(500).render("password-reset", {
        error: "Error interno del servidor",
      });
    }
  }

  async changeToRolePremium(request, response) {
    const { userId } = request.params;
    try {
      const user = await userModel.findById(userId);
      if (!user)
        return response.status(404).json({ message: "Usuario no encontrado" });

      const newRole = user.role === "usuario" ? "premium" : "usuario";

      const updatedRole = await userModel.findByIdAndUpdate(
        userId,
        { role: newRole },
        { new: true }
      );
      response.json(updatedRole);
    } catch (error) {
      console.error(error);
      response.status(500).json({ message: "Error interno del servidor" });
    }
  }
}
