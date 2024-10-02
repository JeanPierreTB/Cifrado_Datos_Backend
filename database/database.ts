// database.ts
import { Sequelize } from 'sequelize';

// Configuración de conexión a PostgreSQL
const sequelize = new Sequelize('Cifrado_Datos', 'postgres', 'postgre', {
  host: 'localhost',
  dialect: 'postgres',
});

// Función para conectar a la base de datos
const connectToDatabase = async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection to the database has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
    process.exit(1); // Salir si no se puede conectar
  }
};

export { sequelize, connectToDatabase };
