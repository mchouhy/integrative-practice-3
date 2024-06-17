import jwt from "jsonwebtoken";

export const roleChecker = (allowedRoles) => (request, response, next) => {
  const token = request.cookies.coderCookieToken;

  if (token) {
    jwt.verify(token, "coderhouse", (error, decoded) => {
      if (error) {
        response.status(403).send("Acceso denegado. Token inválido.");
      } else {
        const userRole = decoded.user.role;
        if (allowedRoles.includes(userRole)) {
          next();
        } else {
          response
            .status(403)
            .send(
              "Acceso denegado. No tienes permiso para acceder a esta página."
            );
        }
      }
    });
  } else {
    response.status(403).send("Acceso denegado. Token no proporcionado.");
  }
};
