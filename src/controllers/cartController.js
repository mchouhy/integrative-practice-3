// Importación del service de carts:
import { CartRepository } from "../repositories/cartRepository.js";
// Llamado de la función constructora:
const cartRepository = new CartRepository();
// Importación del model de tickets:
import { TicketModel } from "../models/ticket.model.js";
// Importación del model de usuarios:
import { userModel } from "../models/user.model.js";
// Importación del repo de productos:
import { ProductRepository } from "../repositories/productRepository.js";
// Llamado de la función constructora:
const productRepository = new ProductRepository();
// Importación del manejador de emails:
import { EmailManager } from "../services/email.js";
// Llamado de la función constructora:
const emailManager = new EmailManager();
// Importación de funciones de utils:
import { generateUniqueCode } from "../utils/generateUniqueCode.js";
import { calcTotal } from "../utils/calcTotal.js";

// Función de clase constructora del controlador de Carts:
export class CartController {
  newCart = async (request, response) => {
    try {
      const newCart = await cartRepository.createCart();
      response.json(newCart);
    } catch (error) {
      response.status(500).json({ error: "Error al crear el cart." });
    }
  };

  getCartById = async (request, response) => {
    const cartId = request.params.cid;
    try {
      const cartProducts = await cartRepository.getCartById(cartId);
      if (!cartProducts) {
        console.log("No existe un cart con el id ingresado.", error);
        return response
          .status(404)
          .json({ error: "Cart por id ingresado no existe." });
      }
      return response.json(cartProducts);
    } catch (error) {
      response.status(500).json({
        error: "Error. No se pudo obtener el producto del cart por id.",
      });
    }
  };

  addProduct = async (request, response) => {
    const cartId = request.params.cid;
    const prodId = request.params.pid;
    const quantity = request.body.quantity || 1;
    try {
      await cartRepository.addProduct(cartId, prodId, quantity);
      const cartID = request.user.cart.toString();
      response.redirect(`/carts/${cartID}`);
    } catch (error) {
      response
        .status(500)
        .json({ error: "Error. No se pudo agregar el producto" });
    }
  };

  deleteProductById = async (request, response) => {
    const cartId = request.params.cid;
    const prodId = request.params.pid;
    try {
      const updateCart = await cartRepository.deleteProductById(cartId, prodId);
      response.json({
        status: "success",
        message: "Producto eliminado con éxito.",
        updateCart,
      });
    } catch (error) {
      console.log("Error al eliminar el producto del cart", error);
      response.status(500).json({
        status: "error",
        error: "Error interno del servidor",
      });
    }
  };

  updateCart = async (request, response) => {
    const cartId = request.params.cid;
    // Se envía un array de productos en el body de la solicitud:
    const updatedProducts = request.body;
    try {
      const updatedCart = await cartRepository.updateCart(
        cartId,
        updatedProducts
      );
      response.json(updatedCart);
    } catch (error) {
      console.log("Error al actualizar el cart", error);
      response.status(500).json({
        status: "error",
        error: "Error interno del servidor",
      });
    }
  };

  updateProductQuantity = async (request, response) => {
    const cartId = request.params.cid;
    const prodId = request.params.pid;
    const newQuantity = request.body.quantity;
    try {
      const updatedCart = await cartRepository.updateProductQuantity(
        cartId,
        prodId,
        newQuantity
      );
      response.json({
        status: "success",
        message: "Cantidad del producto actualizada con éxito.",
        updatedCart,
      });
    } catch (error) {
      console.log(
        "Error al actualizar la cantidad de productos el cart.",
        error
      );
      response.status(500).json({
        status: "error",
        error: "Error interno del servidor.",
      });
    }
  };

  emptyCart = async (request, response) => {
    const cartId = request.params.cid;
    try {
      const updatedCart = await cartRepository.emptyCart(cartId);
      response.json({
        status: "success",
        message: "Se eliminaron con éxito los productos del cart.",
        updatedCart,
      });
    } catch (error) {
      console.log("Error al intentar vaciar el cart.", error);
      response.status(500).json({
        status: "error",
        error: "Error interno del servidor",
      });
    }
  };

  checkOut = async (request, response) => {
    const cartId = request.params.cid;
    try {
      const cart = await cartRepository.getCartById(cartId);
      const products = cart.products;
      const noStockProducts = [];

      for (const item of products) {
        const prodId = item.product;
        const product = await productRepository.getProductById(prodId);
        if (product.stock >= item.quantity) {
          product.stock -= item.quantity;
          await product.save();
        } else {
          noStockProducts.push(prodId);
        }
      }

      const cartUser = await userModel;

      const ticket = new TicketModel({
        code: generateUniqueCode(),
        purchase_datetime: new Date(),
        amount: calcTotal(cart.products),
        purchaser: cartUser._id,
      });
      await ticket.save();

      cart.products = cart.products.filter((item) =>
        noStockProducts.some((prodId) => prodId.equals(item.product))
      );
      await cart.save();

      await emailManager.checkoutEmail(
        cartUser.email,
        cartUser.first_name,
        cartUser._id
      );

      response.render("checkout", {
        client: cartUser.first_name,
        email: cartUser.email,
        ticketNumber: ticket._id,
      });
    } catch (error) {
      response.status(500).json({
        error: "Error interno del servidor al intentar hacer el checkout.",
      });
    }
  };
}
