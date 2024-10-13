import { DataTypes } from 'sequelize';
import { sequelize } from '../database/database'

const User = sequelize.define('User', {
  email: {
    type: DataTypes.TEXT,
    allowNull: false,
    primaryKey: true,
  },
  password: {
    type: DataTypes.TEXT,
    allowNull: false,
  }
});

const createTables = async () => {
  try {
    await sequelize.sync();
    console.log('Tables created successfully.');
  } catch (error) {
    console.error('Error creating tables:', error);
  }
};

export { User, createTables };
