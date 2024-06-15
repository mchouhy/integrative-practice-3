const missingUserDataError = (parameter) => {
  return `Datos incompletos o inválidos.
    Necesitamos recibir los siguientes datos: 
    - Nombre: Esperábamos un String, pero recibimos ${parameter.nombre}
    - Apellido: Esperábamos un String, pero recibimos $sa{parameter.apellido}
    - Email: Esperábamos un String, pero recibimos ${parameter.email}
    `;
};
const missingCartDataError = () => {
  return "No se ha ingresado el cartId. Necesitamos el cartId para poder devolver los productos del carrito de compras.";
};

export default { missingUserDataError, missingCartDataError };
