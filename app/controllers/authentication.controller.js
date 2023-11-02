import bcryptjs from "bcryptjs"
import jsonwebtoken from "jsonwebtoken"
import dotenv from "dotenv"

dotenv.config();

export const usuarios = [{
    user: "a",
    email: "luisferpe.20@hotmail.com",
    password: "$2a$05$CkJOvAdYZv5AlnfVnqiH9.V7COnFFJLn//RqaRpLN1PFBL2eHVOFm"
}]

async function login(req, res) {
    console.log(req.body);
    const user = req.body.user;
    const password = req.body.password;
    if (!user || !password) {
        return res.status(400).send({ status: "Error", message: "Los campos estan incompletos" })
    }
    const usuarioaRevisar = usuarios.find(usuario => usuario.user === user);
    if (!usuarioaRevisar) {
        return res.status(400).send({ status: "Error", message: "Error durante el login" })

    }

    const loginCorrecto = await bcryptjs.compare(password, usuarioaRevisar.password);
    if (!loginCorrecto) {
        return res.status(400).send({ status: "Error", message: "Error durante el login" })
    }
    const token = jsonwebtoken.sign({ user: usuarioaRevisar.user },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRATION });

    const cookieOption = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
        path: "/"
    }
    res.cookie("jwt", token, cookieOption);
    res.send({ status: 'ok', message: 'Usuario loggeado', redirect: '/admin' });

}
async function register(req, res) {
    console.log(req.body);
    const user = req.body.user;
    const password = req.body.password;
    const email = req.body.email;
    if (!user || !password || !email) {
        return res.status(400).send({ status: "Error", message: "Los campos estan incompletos" })
    }

    const usuarioaRevisar = usuarios.find(usuario => usuario.user === user);
    if (usuarioaRevisar) {
        return res.status(400).send({ status: "Error", message: "Este usuario ya existe" })

    }

    const salt = await bcryptjs.genSalt(5);
    const hasPassword = await bcryptjs.hash(password, salt);
    const nuevoUsuario = {
        user, email, password: hasPassword
    }

    usuarios.push(nuevoUsuario);
    console.log(usuarios);
    return res.status(201).send({ status: "ok", message: `Usuario ${nuevoUsuario.user} agregado`, redirect: "/" })


}

export const methods = {
    login,
    register
}