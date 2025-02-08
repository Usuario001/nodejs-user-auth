import crypto from 'node:crypto'

import DBLocal from 'db-local'
import bcrypt from 'bcrypt'

import { SALT_ROUNDS } from './config.js'
const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    // 1.Validaciones de username (opcional usar zod)
    Validation.username(username)
    Validation.password(password)
    // 1.Asegurar que el username no existe
    const user = User.findOne({ username })
    if (user) throw new Error('username already exist')
    // Para crear ID con randomUUid es suficiente pero hay distintas estrategias
    const id = crypto.randomUUID()
    /**
     * el hash sync bloquea el threat principal
     * const hashedPassword = bcrypt.hashSync(password, SALT_ROUNDS) // salt el segundo parametro es el número de veces que usará bcrypt
     * por lo que será mejor hacer asincrona la función create y usar bcrypt.hash
     */
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS) // salt el segundo parametro es el número de veces que usará bcrypt

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()
    return id
  }

  static async login ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('username or password are incorrect')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('username or password is not valid')
    /**
     * por ejemplo en typescript es mejor tener una interfaz para datos publicos y otra para datos privados
     * quitar propiedades de un objeto de una forma pro pero no es mejor dependerá del contexto por que no se es explicito
     */
    const { password: _, ...publicUser } = user
    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (username.length < 3) throw new Error('username must be at least 3 characters long')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (password.length < 6) throw new Error('password must be at least 6 characters long')
  }
}
