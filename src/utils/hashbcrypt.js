// Importación de Bcrypt:
import bcrypt from "bcrypt";

// Función que permite aplicar el hash a la contraseña del usuario:
const createHash = (password) =>
  bcrypt.hashSync(password, bcrypt.genSaltSync(10));
// Función para comparar la contraseña del usuario en el login con la almacenada en la base de datos:
const isValidPassword = (password, user) =>
  bcrypt.compareSync(password, user.password);

// Exportación de las funciones de hasheo y comparación de contraseñas:
export { createHash, isValidPassword };
