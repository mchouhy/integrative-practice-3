// Creación de una instancia de socket.io del lado del cliente:
const socket = io();

// Guardado del nombre del usuario:
let user;

// Acceso al elemento html por id:
const chatBox = document.getElementById("chatBox");

//Uso del objeto Swal y el método fire:
Swal.fire({
  title: "Identificate",
  input: "text",
  text: "Ingrese un usuario para identificarse en el chat",
  inputValidator: (value) => {
    return !value && "Necesitas escribir un nombre para continuar";
  },
  allowOutsideClick: false,
}).then((result) => {
  user = result.value;
  console.log(user);
});

// Evento que escucha las keys:
chatBox.addEventListener("keyup", (event) => {
  if (event.key === "Enter") {
    // Trim que permite sacar los espacios en blanco al principio y al final de un string:
    if (chatBox.value.trim().length > 0) {
      // Si sacando los espacios en blanco el mensaje tiene mas de 0 caracteres, se envía al servidor:
      socket.emit("message", { user: user, message: chatBox.value });
      chatBox.value = "";
    }
  }
});

// Se reciben los mensajes y se muestran por pantalla:
socket.on("message", (data) => {
  let log = document.getElementById("messagesLogs");
  let mensajes = "";
  data.forEach((mensaje) => {
    mensajes =
      mensajes +
      `<div class="flex justify-center p-1">${mensaje.user} dice: ${mensaje.message}</div><br>`;
  });
  log.innerHTML = mensajes;
});
