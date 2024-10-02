import express, { Request, Response } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { User, createTables } from '../models/Usuario';
import { connectToDatabase } from '../database/database';

const app = express();
const PORT = process.env.PORT || 3001;



// Configuración del cifrado asimétrico RSA
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Middleware para manejar JSON
app.use(express.json());

app.get('/', async (req: Request, res: Response) => {
  res.send("Bienvenido al servidor");
});

// Ruta para registro con hashing de contraseña (bcrypt)
app.post('/register', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Hashing de la contraseña
  const hashedPassword = await bcrypt.hash(password, 10);

  // Guardar el usuario con la contraseña hasheada en la base de datos
  try {
    const user = await User.create({ username, password: hashedPassword });
    res.status(201).json({ message: 'User registered successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'Error creating user', details: error });
  }
});

// Ruta para login verificando con bcrypt
app.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Verificar si el usuario existe en la base de datos
  const user:any = await User.findOne({ where: { username } });
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  // Comparar la contraseña con bcrypt
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generar un token JWT como ejemplo de autenticación
  const token = jwt.sign({ username }, 'secretKey', { expiresIn: '1h' });

  res.json({ message: 'Login successful', token });
});

// Endpoint para establecer un PIN de seguridad (hashing con bcrypt)
app.post('/set-pin', async (req: Request, res: Response) => {
  const { username, pin } = req.body;

  if (!username || !pin) {
    return res.status(400).json({ error: 'Username and PIN are required' });
  }

  // Hashing del PIN
  const hashedPin = await bcrypt.hash(pin, 10);

  // Actualizar el usuario con el PIN hasheado
  try {
    await User.update({ pin: hashedPin }, { where: { username } });
    res.status(201).json({ message: 'PIN set successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error setting PIN', details: error });
  }
});

// Endpoint para verificar el PIN (hashing con bcrypt)
app.post('/verify-pin', async (req: Request, res: Response) => {
  const { username, pin } = req.body;

  if (!username || !pin) {
    return res.status(400).json({ error: 'Username and PIN are required' });
  }

  // Verificar si el usuario existe en la base de datos
  const user:any = await User.findOne({ where: { username } });
  if (!user || !user.pin) {
    return res.status(400).json({ error: 'PIN not set for this user' });
  }

  // Comparar el PIN ingresado con el hasheado
  const isMatch = await bcrypt.compare(pin, user.pin);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid PIN' });
  }

  res.json({ message: 'PIN verified successfully' });
});

// Ruta para cifrar datos de la tarjeta de crédito con RSA
app.post('/pay', (req: Request, res: Response) => {
  const { cardNumber, cardHolder, expiryDate, cvv } = req.body;

  if (!cardNumber || !cardHolder || !expiryDate || !cvv) {
    return res.status(400).json({ error: 'All card details are required' });
  }

  // Crear un objeto con los datos de la tarjeta
  const cardDetails = JSON.stringify({ cardNumber, cardHolder, expiryDate, cvv });

  // Cifrar los datos de la tarjeta con la clave pública (RSA)
  const encryptedCardDetails = crypto.publicEncrypt(publicKey, Buffer.from(cardDetails));

  res.json({
    message: 'Payment information encrypted successfully',
    encryptedCardDetails: encryptedCardDetails.toString('base64'),
  });
});

// Ruta para descifrar los datos de la tarjeta de crédito (solo para pruebas)
app.post('/decrypt-card', (req: Request, res: Response) => {
  const { encryptedCardDetails } = req.body;

  if (!encryptedCardDetails) {
    return res.status(400).json({ error: 'Encrypted card details are required' });
  }

  // Descifrar los datos de la tarjeta con la clave privada (RSA)
  const decryptedCardDetails = crypto.privateDecrypt(privateKey, Buffer.from(encryptedCardDetails, 'base64'));

  res.json({
    message: 'Card details decrypted successfully',
    cardDetails: JSON.parse(decryptedCardDetails.toString()),
  });
});

const startServer = async () => {
  await connectToDatabase();
  await createTables();

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
};

startServer();
