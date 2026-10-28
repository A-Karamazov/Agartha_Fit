import login from "./login.html"
import home from "./home.html"
import db from "./db.ts"

const loggedUsers: any = {} 

//Cria a sessão do usuário e seta o cookie
function criarSessao(req: any, user: any) {
    const uuid = crypto.randomUUID()             
    const { password_hash, ...safeUser } = user  
    loggedUsers[uuid] = safeUser                 
    req.cookies.set("ses", uuid)                 
}

const srv = Bun.serve({
    port: 3000,
    routes: {
        "/": login,

        "/home": home,

        "/user": {
            POST: async (req) => {
                const body = await req.body?.json() 
                if (!body?.username.trim())
                    return Response.json({ msg: "É necessário informar um usuário" }, { status: 400 })

                if (body.password !== body.passwordconfirm)
                    return Response.json({ msg: "As senhas não conferem" }, { status: 400 })

                const exists = db.query(`
                    SELECT 1 FROM user_secure WHERE username=:username LIMIT 1
                `).get({ ":username": body.username })
                if (exists) return Response.json({ msg: "Usuário já existe" }, { status: 409 })
                    
                const hash = await Bun.password.hash(body.password) 

                //Insere o usuário no db
                db.query(`
                    INSERT INTO user_secure(username, password_hash) 
                    VALUES(:username, :password_hash)
                `).run({ ":username": body.username, ":password_hash": hash })

                //Busca o usuário recém-criado no db para criar a sessão
                const user: any = db.query(`
                    SELECT * FROM user_secure WHERE username=:username LIMIT 1
                `).get({ ":username": body.username })

                criarSessao(req, user) //Já deixa o usuário logado após o cadastro

                return Response.json(true, { status: 201 })
            },
        },

        "/login": {
            POST: async (req) => {
                const body = await req.body?.json()
                const query = db.query(`
                    SELECT * FROM user_secure 
                    WHERE username=:username LIMIT 1
                `)  //Busca o usuário no db
                const data: any = query.get({ ":username": body.username })

                if (!data) return Response.json({ msg: "Usuário não encontrado" }, { status: 404 })

                const isMatch = await Bun.password.verify(body.password, data.password_hash)

                if (!isMatch) return Response.json({ msg: "Senha não confere" }, { status: 401 })

                criarSessao(req, data)
                return Response.json(isMatch)
            }
        },

        "/login/user": (req) => {
            const ses = req.cookies.get("ses") //

            if (!ses || !loggedUsers[ses])
                return Response.json({ msg: "Não permitido" }, { status: 401 }) 

            return Response.json(loggedUsers[ses]) 
        }
    },
})

console.log(`Server running on ${srv.url}`)