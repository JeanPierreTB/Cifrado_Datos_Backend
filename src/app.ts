import express, { Request, Response } from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { User, createTables } from '../models/Usuario';
import { connectToDatabase } from '../database/database';
import { sequelize, QueryTypes } from '../database/database'; // Asegúrate de importar QueryTypes
import https from 'https';
import fs from 'fs';
import { EncryptedPasswordResponse } from './interfaces';
import { IsValidResponse } from './interfaces';

const app = express();
const PORT = 3001;

// Carga los certificados SSL
const sslPrivateKey = fs.readFileSync('./config/private.key', 'utf8');  
const sslCertificate = fs.readFileSync('./config/certificate.crt', 'utf8'); 
const credentials = { key: sslPrivateKey, cert: sslCertificate };

app.use(cors());
app.use(express.json());

app.get('/', async (req: Request, res: Response) => {
  res.send("Bienvenido al servidor");
});

// Generar par de claves RSA
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});



app.post('/register', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Cifrar la contraseña usando pgcrypto
  const encryptedPassword = (await sequelize.query<EncryptedPasswordResponse>(
    'SELECT crypt($1, gen_salt(\'bf\')) AS encrypted_password',
    {
      bind: [password],
      type: QueryTypes.SELECT, // Usar QueryTypes
    }
  ))[0].encrypted_password;

  try {
    const user = await User.create({ email, password: encryptedPassword });
    res.status(201).json({ message: 'User registered successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'Error creating user', details: error });
  }
});

app.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user: any = await User.findOne({ where: { email } });
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  // Verificar la contraseña cifrada usando pgcrypto
  const isPasswordValid = await sequelize.query<IsValidResponse>(
    'SELECT crypt($1, password) AS is_valid FROM "Users" WHERE "email" = $2',
    {
      bind: [password, email],  // Cambia esto para usar bind con email
      type: QueryTypes.SELECT,
    }
  );

  if (!isPasswordValid[0].is_valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ message: 'Login successful' });
});



app.post('/pay', (req: Request, res: Response) => {
  const { cardNumber, cardName, expiryDate, cvv } = req.body;

  if (!cardNumber || !cardName || !expiryDate || !cvv) {
    return res.status(400).json({ error: 'All card details are required' });
  }

  const cardDetails = JSON.stringify({ cardNumber, cardName, expiryDate, cvv });

  const encryptedCardDetails = crypto.publicEncrypt(publicKey, Buffer.from(cardDetails));

  res.json({
    message: 'Payment information encrypted successfully',
    encryptedCardDetails: encryptedCardDetails.toString('base64'),
  });
});

app.post('/decrypt-card', (req: Request, res: Response) => {
  const { encryptedCardDetails } = req.body;

  if (!encryptedCardDetails) {
    return res.status(400).json({ error: 'Encrypted card details are required' });
  }

  const decryptedCardDetails = crypto.privateDecrypt(privateKey, Buffer.from(encryptedCardDetails, 'base64'));

  res.json({
    message: 'Card details decrypted successfully',
    cardDetails: JSON.parse(decryptedCardDetails.toString()),
  });
});

// Inicia el servidor HTTPS
const startServer = async () => {
  await connectToDatabase();
  await createTables();

  const httpsServer = https.createServer(credentials, app);
  httpsServer.listen(PORT, () => {
    console.log(`Server running on https://localhost:${PORT}`);
  });
};

startServer();
