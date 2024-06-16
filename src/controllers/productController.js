// Importación del service de productos:
import { ProductRepository } from "../repositories/productRepository.js";
// Llamado de la función constructora:
const productRepository = new ProductRepository();

// Función de clase constructora del controlador de Carts:
export class ProductController {
  getProducts = async (request, response) => {
    try {
      const { limit = 10, page = 1, sort, query } = request.query;
      const products = await productRepository.getProducts({
        limit: parseInt(limit),
        page: parseInt(page),
        sort,
        query,
      });
      response.json(products);
    } catch (error) {
      console.log("Error al obtener los productos de Mongo Atlas.", error);
      response.status(500).json({ error: "Error interno del servidor." });
    }
  };

  getProductById = async (request, response) => {
    // Se define la variable que aplica el request params del id a ingresar por el cliente:
    const { prodId } = request.params;
    try {
      const product = await productRepository.getProductById(prodId);
      if (!product) {
        return response.json({ error: "Producto no encontrado." });
      }
      response.json(product);
    } catch (error) {
      response
        .status(500)
        .json({ error: "No existe un producto con el id ingresado." });
    }
  };

  addProduct = async (request, response) => {
    const newProduct = request.body;
    try {
      await productRepository.addProduct(newProduct);
      response.status(201).json({ message: "Producto agregado con éxito." });
    } catch (error) {
      response
        .status(500)
        .json({ error: "Error. No se pudo agregar el producto." });
    }
  };

  updateProduct = async (request, response) => {
    const { prodId } = request.params;
    const updatedProduct = request.body;
    try {
      await productRepository.updateProduct(prodId, updatedProduct);
      response
        .status(201)
        .json({ message: "Producto actualizado exitosamente." });
    } catch (error) {
      response
        .status(500)
        .json({ error: "No se pudo actualizar el producto." });
    }
  };

  deleteProductById = async (request, response) => {
    const { prodId } = request.params;
    try {
      await productRepository.deleteProductById(prodId);
      response.status(201).json({ message: "Producto eliminado con éxito." });
    } catch (error) {
      response.status(500).json({ error: "No se pudo eliminar el producto." });
    }
  };
}
