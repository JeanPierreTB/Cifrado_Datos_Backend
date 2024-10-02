// models.ts
import { DataTypes } from 'sequelize';
import { sequelize } from '../database/database'

// Definición del modelo de usuario
const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    primaryKey: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  pin: {
    type: DataTypes.STRING,
    allowNull: true,
  },
});

// Función para crear las tablas
const createTables = async () => {
  try {
    await sequelize.sync();
    console.log('Tables created successfully.');
  } catch (error) {
    console.error('Error creating tables:', error);
  }
};

export { User, createTables };
