import { Server } from "socket.io";
import { messageModel } from "../models/message.model.js";
import { ProductRepository } from "../repositories/productRepository.js";

export class SocketManager {
  constructor(httpServer) {
    this.io = new Server(httpServer);
    this.ProductRepository = new ProductRepository();
    this.initSocketEvents();
  }

  initSocketEvents() {
    this.io.on("connection", (socket) => {
      socket.on("message", async (data) => {
        await messageModel.create(data);
        const messages = await messageModel.find();
        socket.emit("message", messages);
      });

      (async () => {
        socket.emit(
          "products",
          await this.ProductRepository.getProducts({ limit: null })
        );
      })();

      socket.on("addProduct", async (newProduct) => {
        await this.ProductRepository.addProduct(newProduct);
        this.updatedProducts(socket);
      });

      socket.on("deleteProduct", async (id) => {
        await this.ProductRepository.deleteProductById(id);
        this.updatedProducts(socket);
      });
    });
  }

  async updatedProducts(socket) {
    socket.emit(
      "products",
      await this.ProductRepository.getProducts({ limit: null })
    );
  }
}
