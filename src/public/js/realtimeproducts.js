// Console log que verifica que Handlebars está funcionando correctamente:
console.log("Handlebars funcionando correctamente.");
// Generación de una instancia de socket del lado del cliente:
const socket = io();

document.addEventListener("DOMContentLoaded", () => {
  // Variable que aloja el formulario para agregar productos.
  const addProductForm = document.getElementById("addProductForm");
  // Función que escucha el evento submit, guarda los valores ingresados y los envía al socket del lado del servidor para aplicarlo al json.
  addProductForm.addEventListener("submit", (e) => {
    e.preventDefault();
    console.log("Add product submit");
    let titleInput = document.getElementById("title").value;
    let descriptionInput = document.getElementById("description").value;
    let priceInput = parseInt(document.getElementById("price").value);
    let thumbnailsInput = document.getElementById("thumbnails").value;
    let stockInput = parseInt(document.getElementById("stock").value);
    let codeInput = document.getElementById("code").value;
    let categoryInput = document.getElementById("category").value;

    const newProduct = {
      title: titleInput,
      description: descriptionInput,
      code: codeInput,
      price: priceInput,
      stock: stockInput,
      category: categoryInput,
      thumbnails: thumbnailsInput,
    };

    socket.emit("addProduct", newProduct);

    addProductForm.reset();
  });
});

const deleteProductForm = document.getElementById("deleteProductForm");
deleteProductForm.addEventListener("submit", (e) => {
  e.preventDefault();
  console.log("Delete product submit");
  let idInput = document.getElementById("id").value;

  const prodId = idInput;

  socket.emit("deleteProduct", prodId);

  deleteProductForm.reset();
});

socket.on("products", (responseData) => {
  const productsCards = document.getElementById("productsRT");
  productsCards.innerHTML = "";
  if (Array.isArray(responseData.data)) {
    responseData.data.forEach((product) => {
      let productCard = document.createElement("div");
      productCard.className = "product-container";
      productCard.innerHTML = `
              <h2>Nombre:<br> ${product.title}</h2>
              <p>Descripción:<br> ${product.description}</p>
              <p>Precio:<br> €${product.price}</p>
              <p>Id:<br> ${product._id}</p>
              `;
      productsCards.appendChild(productCard);
    });
  }
});

socket.on("error", async (data) => {
  console.log(data);
});
