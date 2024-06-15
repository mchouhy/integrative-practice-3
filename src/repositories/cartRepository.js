// Importación del model de carts:
import { cartModel } from "../models/carts.model.js";
import CustomError from "../services/error.custom.js";
import missingCartDataError from "../services/error.missing.data.js";
import { EErrors } from "../services/error.enum.js";
//Función de clase constructora que recibe la ruta a trabajar desde el momento de generar la instancia.
export class CartRepository {
  createCart = async () => {
    try {
      // Variable que aloja el nuevo carrito:
      const newCart = new cartModel({ products: [] });
      // Se guarda el cart en la base de datos:
      await newCart.save();
      // Se retorna el nuevo cart:
      return newCart;
    } catch (error) {
      console.log("Error al crear el cart de productos", error);
      throw error;
    }
  };

  getCartById = async (cartId) => {
    try {
      // Validación de si existe un cart con el id ingresado:
      const cart = await cartModel.findById(cartId);
      // Error en caso de que no exista.
      if (!cart) {
        throw new Error(
          `No existe un cart con el id ${cartId}. Intente nuevamente.`
        );
      }
      // Se retorna el cart seleccionado por id.
      return cart;
    } catch (error) {
      throw CustomError.createError({
        name: "Devolver carrito de compras desde el servidor",
        cause: missingCartDataError(),
        code: EErrors.DB_ERROR,
      });
    }
  };

  addProduct = async (cartId, prodId, quantity = 1) => {
    try {
      // Se trae el cart de la base datos por id.
      const cart = await this.getCartById(cartId);
      // Valicación si existe un producto con el id ingresado por parámetro.
      const existingProduct = cart.products.find(
        (item) => item.product._id.toString() === prodId
      );
      // En caso de que exista:
      if (existingProduct) {
        existingProduct.quantity += quantity;
        // En caso contrario:
      } else {
        cart.products.push({ product: prodId, quantity });
      }
      // Marcado de la modificación del quantity con markModified:
      cart.markModified("products");
      await cart.save();
      return cart;
    } catch (error) {
      console.log("Error en el servidor al buscar el cart por id", error);
      throw error;
    }
  };

  deleteProductById = async (cartId, prodId) => {
    try {
      // Se trae el cart de la base de datos por id:
      const cart = await cartModel.findById(cartId);
      // Validación para el caso de que no exista el cart ingresadoo por id:
      if (!cart) {
        throw new Error(
          `No existe un cart con el id ${cartId}. Intente nuevamente.`
        );
      }
      // Se filtra el producto a eliminar por id:
      cart.products = cart.products.filter(
        (item) => item.product._id.toString() !== prodId
      );
      // Se guarda el cart actualizado en la base de datos:
      await cart.save();
      return cart;
    } catch (error) {
      console.log(
        "Error al intentar actualizar el cart con el cartManager",
        error
      );
      throw error;
    }
  };

  updateCart = async (cartId, updatedProducts) => {
    try {
      const cart = await cartModel.findById(cartId);

      if (!cart) {
        throw new Error(
          `No existe un cart con el id ${cartId}. Intente nuevamente.`
        );
      }
      cart.products = updatedProducts;
      cart.markModified("products");
      await cart.save();
      return cart;
    } catch (error) {
      console.log(
        "Error al intentar actualizar el cart con el cartManager",
        error
      );
      throw error;
    }
  };

  updateProductQuantity = async (cartId, prodId, newQuantity) => {
    try {
      const cart = await cartModel.findById(cartId);

      if (!cart) {
        throw new Error(
          `No existe un cart con el id ${cartId}. Intente nuevamente.`
        );
      }
      const index = cart.products.findIndex(
        (item) => item.product._id.toString() !== prodId
      );
      if (index !== -1) {
        cart.products[index].quantity = newQuantity;
        cart.markModified("products");
        await cart.save();
        return cart;
      } else {
        throw new Error(`Producto no encontrado.`);
      }
    } catch (error) {
      console.log(
        "Error al intentar actualizar la cantidad del producto en el cart con el cartManager",
        error
      );
      throw error;
    }
  };

  emptyCart = async (cartId) => {
    try {
      const cart = await cartModel.findByIdAndUpdate(
        cartId,
        { products: [] },
        { new: true }
      );

      if (!cart) {
        throw new Error(
          `No existe un cart con el id ${cartId}. Intente nuevamente.`
        );
      }
    } catch (error) {
      console.log("Error al intentar vaciar el cart con el cartManager", error);
      throw error;
    }
  };
}
