// Importación de los módulos de Passport:
import passport from "passport";
// Importación de JWT:
import jwt from "passport-jwt";
// Traemos la estrategia de JWT:
const JWTStrategy = jwt.Strategy;
// Traemos la extracción de JWT:
const ExtractJWT = jwt.ExtractJwt;
// Importación de UserModel:
import { userModel } from "../models/user.model.js";

const initializePassport = () => {
  passport.use(
    "jwt",
    new JWTStrategy(
      {
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: "coderhouse",
      },
      async (jwt_payload, done) => {
        try {
          const user = await userModel.findById(jwt_payload.user._id);
          if (!user) {
            return done(null, false);
          }
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
};

const cookieExtractor = (request) => {
  let token = null;
  if (request && request.cookies) {
    token = request.cookies["coderCookieToken"];
  }
  return token;
};

export default initializePassport;
