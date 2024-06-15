import { generateProduct } from "../utils/productsMock.js";

export const getProductsMock = async (request, response) => {
  const productQuantity = 100;

  try {
    const products = [];
    for (let i = 0; i < productQuantity; i++) {
      products.push(generateProduct());
    }
    response.status(200).json(products);
  } catch (error) {
    response.status(500).json({
      message: "Error en el servidor. No se pudo traer los productos de mock.",
    });
  }
};
