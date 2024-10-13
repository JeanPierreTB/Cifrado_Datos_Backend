import { Sequelize, QueryTypes } from 'sequelize';

const sequelize = new Sequelize('Cifrado_Datos', 'postgres', 'postgre', {
  host: 'localhost',
  dialect: 'postgres',
});

const connectToDatabase = async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection to the database has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
    process.exit(1);
  }
};

// Exportar sequelize y QueryTypes
export { sequelize, connectToDatabase, QueryTypes };
