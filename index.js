const express = require('express')
const mysql = require("mysql2")
const bcrypt = require("bcryptjs")
const session = require('express-session')
const bodyParser = require('body-parser')
const path = require('path')

//Inicialização do express
const app = express()
const porta = 3000

//Configuração do MYSQL
const banco = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Gabi220408', //senha do mysql
    database: 'sistema_login'
})

//Conectar ao MYSQL
banco.connect((erro) => {
    if(erro) {
        console.erro("Erro ao conectar no mysql", erro)
        return;
    }
    console.log("Conectado ao mysql")
})

//Rotas
app.get('/', (requisicao, resposta) => {
    resposta.sendFile(path.join(__dirname, "public", "index.html"))
})
app.get('/login', (requisicao, resposta) => {
    resposta.sendFile(path.join(__dirname, "public", "login.html"))
})
app.get('/cadastro', (requisicao, resposta) => {
    resposta.sendFile(path.join(__dirname, "public", "cadastro.html"))
})

//Middleware
app.use(bodyParser.urlencoded({extend: true}))
app.use(express.static("public"))
app.use(session ({
    secret: 'segredo',
    resave: true,
    saveUninitialized: true
}))

//Rota do Registro
app.post('/cadastro', async (requisicao, resposta) => {
    const {nome, senha} = requisicao.body
    const senhaCriptografada = await bcrypt.hash(senha, 10)

    banco.query("INSERT INTO usuario (nome, senha) VALUES (?, ?)", 
        [nome, senhaCriptografada], 
        (erro, resultado) => {
            if(erro) {
                console.error("Erro ao cadastrar usuário")
                resposta.status(500).send("Erro ao cadastrar usuário")
                return;
            }
            resposta.redirect('/login')
        })
})

app.post('/login', async(requisicao, resposta) => {
    const {nome, senha} = requisicao.body
    banco.query("SELECT * FROM usuario WHERE nome = ?", [nome],
        async(erro, resultado) => {
            if(erro) {
                console.error("Erro ao fazer login", erro)
                resposta.status(500).send("Erro ao fazer login")
                return;
            }
            if (resultado.length == 0) {
                resposta.status(401).send("Usuário não encontrado")
                return;
            }
            const usuario = resultado[0]
            const senhaValida = await bcrypt.compare(senha, usuario.senha)
            if(senhaValida){
                requisicao.session.logado = true
                requisicao.session.nome = nome
                resposta.redirect("/painel")
            }
            else {
                resposta.status(401).send("Senha incorreta")
            }
        }
    )
})
//ROTA DO PAINEL (PROTEGIDA)
app.get('/painel', (requisicao, resposta) => {
    if(requisicao.session.logado) {
        resposta.sendFile(path.join(__dirname, "public", "painel.html"))
    } else {
        resposta.redirect("/login")
    }
})
//ROTA DO LOGOUT
app.get("/sair", (requisicao, resposta) => {
    requisicao.session.destroy()
    resposta.redirect("/login")
})
app.listen(porta, () => {
    console.log(`Servidor rodando em http://localhost:${porta}`)
})