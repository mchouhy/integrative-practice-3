import { EErrors } from "../services/error.enum.js";

const errorHandler = (error, request, response, next) => {
  console.log(error.cause);
  switch (error.code) {
    case EErrors.INVALID_TYPE:
      response.send({ status: "error", error: error.name });
      break;
    default:
      response.send({ status: "error", error: "Unknown error." });

    case EErrors.DB_ERROR:
      response.send({ status: "error", error: error.name });
      break;
  }
};

export default errorHandler;
