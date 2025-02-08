import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

import { PORT, SECRET__JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()
// definir un sistema de plantillas en este caso EJS
app.set('view engine', 'ejs')
// Hacer un midleware para recuperar la data del body
/** Son funciones por donde pasa la petición o la respuesta */
app.use(express.json())
app.use(cookieParser())
app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }
  try {
    const data = jwt.verify(token, SECRET__JWT_KEY)
    req.session.user = data
  } catch {}
  next() // LLamar a la siguiente ruta o midleware
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', user)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    // El SECRET KEY no debe tener un valor por default debe ser una palabra de entorno y debe ser muy muy largo
    const token = jwt.sign({ id: user._id, username: user.username },
      SECRET__JWT_KEY,
      {
        expiresIn: '1h'
      })
    res
      .cookie('access_token', token, {
        httpOnly: true, // La cookie solo se puede acceder en el servidor
        // secure:process.env.NODE_ENV === 'production' se con https
        sameSite: 'strict', // Solo desde el mismo dominio
        maxAge: 1000 * 60 * 60 // Solo una hora
      })
      .send({ user, token })
  } catch (error) {
    res.status(401).send('unAuthorized')
  }
})

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body // El cuerpo de la petición.
    console.log('Error?')
    console.log(req.body)
    const id = await UserRepository.create({ username, password })

    const token = jwt.sign({ id, username },
      SECRET__JWT_KEY,
      {
        expiresIn: '1h'
      })
    res
      .cookie('access_token', token, {
        httpOnly: true, // La cookie solo se puede acceder en el servidor
        // secure:process.env.NODE_ENV === 'production' se con https
        sameSite: 'strict', // Solo desde el mismo dominio
        maxAge: 1000 * 60 * 60 // Solo una hora
      })
      .send({ id })
  } catch (error) {
    /**
     * Normalmente no es buena idea mandar el error del repositorio
     * res.status(400).send(error.message)
     * es posible manejar los errores con un if y dependiendo el error
     * crear un mensaje de error incluso haciendo una clase extend de Error
     * podria funcionar para manejar los errores
     **/
    res.status(400).send(error.message)
  }
})

app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .json({ message: 'Logout succesfull' })
})

/**
 * se puede crear una sessión de usuario con express-session
 * se puede guardar sesiones de usuario en redis
 * En este caso vamos a usar JWT (Json web tokens)
 * se necesitan 3 partes
 * encabezada (tipo de token)
 * payload (los datos codificados)
 * firma/footer/signature(poder decodificar la info)
 * en la firma esta una Palabra secreta que debe ser asignada como variable de entorno (nunca debe estar en el codigo)
 **/
app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Access unAuthorized')
  res.render('protected', user)
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
