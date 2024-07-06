import swaggerJSDoc from "swagger-jsdoc";

export const swaggerOptions = {
  definition: {
    openapi: "3.0.1",
    info: {
      title: "Documentación de la App de E-Commerce",
      description: "App Web dedicada a la compra de muebles para el hogar",
    },
  },
  apis: ["./src/docs/**/*.yaml"],
};

export const specs = swaggerJSDoc(swaggerOptions);
