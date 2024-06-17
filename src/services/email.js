import nodemailer from "nodemailer";

export class EmailManager {
  constructor() {
    this.transporter = nodemailer.createTransport({
      service: "gmail",
      port: 587,
      auth: {
        user: "mchouhycoderhouse@gmail.com",
        pass: "attt uhsl vkev wloj",
      },
    });
  }

  async checkoutEmail(email, first_name, ticket) {
    try {
      const mailOptions = {
        from: "Email de prueba <mchouhycoderhouse@gmail.com>",
        to: email,
        subject: "Confirmación de compra",
        html: `
                    <h1>Confirmación de compra</h1>
                    <p>Gracias por tu compra, ${first_name}!</p>
                    <p>El número de tu orden es: ${ticket} ¡Guardalo y no lo pierdas!</p>
                `,
      };

      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      console.error("Error al enviar el correo electrónico:", error);
    }
  }

  async passwordResetEmail(email, first_name, token) {
    try {
      const mailOptions = {
        from: "mchouhycoderhouse@gmail.com",
        to: email,
        subject: "Restablecimiento de Contraseña",
        html: `
                    <h1>Restablecimiento de Contraseña</h1>
                    <br />
                    <p>Hola ${first_name},</p>
                    <p>Has solicitado restablecer tu contraseña. Utiliza el siguiente código para cambiar tu contraseña:</p>
                    <br />
                    <p><strong>${token}</strong></p>
                    <br />
                    <p>Este código expirará en 1 hora.</p>
                    <a href="http://localhost:8080/password-reset">Restablecer Contraseña</a>
                    <p>Si no solicitaste este restablecimiento, ignora este correo.</p>
                `,
      };

      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      console.error("Error al enviar correo electrónico:", error);
      throw new Error("Error al enviar correo electrónico");
    }
  }
}
