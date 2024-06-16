import { userModel } from "../models/user.model.js";

export class UserRepository {
  async findByEmail(email) {
    return userModel.findOne({ email });
  }
}
