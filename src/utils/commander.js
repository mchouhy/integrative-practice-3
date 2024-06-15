// Importación de Commander:
import { Command } from "commander";
// Nueva instancia:
const program = new Command();

//1er argumento - Comando, 2do argumento - Descripcion, 3er argumento - Valor por default:
program.option("--mode <mode>", "develop mode", "develop");
program.parse();

export default program;
