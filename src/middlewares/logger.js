import logger from "../utils/logger.js";

export const addLogger = (request, response, next) => {
  request.logger = logger;
  request.logger.http(
    `${request.method} en ${request.url} - ${new Date().toLocaleTimeString()}`
  );
  next();
};
