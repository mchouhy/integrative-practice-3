import passport from "passport";

export function authMiddleware(request, response, next) {
  passport.authenticate("jwt", { session: false }, (error, user, info) => {
    if (error) {
      return next(error);
    }
    if (!user) {
      request.user = null;
    } else {
      request.user = user;
    }
    next();
  })(request, response, next);
}
