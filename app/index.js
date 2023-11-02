import express from "express";
import cookieParser from "cookie-parser";
// Fix para __dirname
import path from 'path';
import { fileURLToPath } from "url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { methods as authentication } from "./controllers/authentication.controller.js";
import { methods as authorization } from "./middlewares/authorization.js";




//server
const app = express();
app.set("port", 4000);
app.listen(app.get("port"));

console.log("Servidor corriendo en puerto: ", "http://localhost:" + app.get("port"));

//configuracion 
app.use(express.static(__dirname + "/public"));
app.use(express.json());
app.use(cookieParser());



//  rutas
app.get("/", authorization.soloPublico, (req, res) => res.sendFile(__dirname + "/pages/login.html"));
app.get("/register", authorization.soloPublico, (req, res) => res.sendFile(__dirname + "/pages/register.html"));
app.get("/admin", authorization.soloAdmin, (req, res) => res.sendFile(__dirname + "/pages/admin/admin.html"));
app.post("/api/login", authentication.login);
app.post("/api/register", authentication.register);


app.use((req, res) => {
    res.status(404).send("<h1>404</h1>")
})