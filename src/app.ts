import express, { Request, Response } from 'express';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3001;

// Configuración del cifrado
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32); // Clave secreta de 32 bytes
const iv = crypto.randomBytes(16);  // Vector de inicialización de 16 bytes

// Función para cifrar
function encrypt(text: string): string {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${encrypted}:${iv.toString('hex')}`;
}

// Función para descifrar
function decrypt(encryptedText: string): string {
  const [encrypted, ivHex] = encryptedText.split(':');
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivHex, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Simulación de almacenamiento en memoria (base de datos de usuarios)
const users: { [username: string]: string } = {};

// Middleware para manejar JSON
app.use(express.json());

app.get('/', (req: Request, res: Response) => {
  res.send('Bienvenido al servidor');
});

// Ruta para el registro (cifrado de la contraseña)
app.post('/register', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Cifrar la contraseña
  const encryptedPassword = encrypt(password);

  // Guardar el usuario con la contraseña cifrada
  users[username] = encryptedPassword;

  // Devolver la contraseña original y la encriptada
  res.status(201).json({
    message: 'User registered successfully',
    originalPassword: password,
    encryptedPassword: encryptedPassword
  });
});

// Ruta para el inicio de sesión (descifrado de la contraseña)
app.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Verificar si el usuario existe
  const encryptedPassword = users[username];
  if (!encryptedPassword) {
    return res.status(400).json({ error: 'User not found' });
  }

  // Desencriptar la contraseña almacenada
  const decryptedPassword = decrypt(encryptedPassword);

  // Verificar si la contraseña coincide
  if (password !== decryptedPassword) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Devolver tanto la contraseña original como la cifrada
  res.json({
    message: 'Login successful',
    originalPassword: password,
    decryptedPassword: decryptedPassword
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
