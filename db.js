const { Pool } = require('pg');

const pool = new Pool({
  user: 'sepa_post_user',        
  host: 'dpg-cvsis795pdvs73bmrd0g-a.virginia-postgres.render.com',        
  database: 'sepa_post',    
  password: 'dDfgxexkenaqwFDznQJEllCRlKOuRzHZ',    
  port: 5432,      
  ssl: {
    rejectUnauthorized: false // para conexões seguras
  },
  max: 10,    
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000 
});

async function criarTabelas() {
  try {
    await pool.query(`
          CREATE TABLE IF NOT EXISTS usuarios (
              id SERIAL PRIMARY KEY NOT NULL,
              nome VARCHAR(255) NOT NULL,
              email VARCHAR(255) UNIQUE NOT NULL,
              senha VARCHAR(255) NOT NULL,
              telefone1 VARCHAR(20) NULL,
              telefone2 VARCHAR(20) NULL,
              profilePic VARCHAR(255),
              tipo VARCHAR(15) CHECK (tipo IN ('Docente', 'Administrador')) NOT NULL
          );
    `);
    console.log("Tabela 'usuarios' pronta!");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS reset_tokens (
       id SERIAL PRIMARY KEY NOT NULL,
       user_id INT NOT NULL, 
       token VARCHAR(255) NOT NULL UNIQUE,
       expires TIMESTAMP NOT NULL,
       used BOOLEAN DEFAULT FALSE,
       FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
     );
    `)
    console.log("Tabela 'reset_tokens' pronta!");

    await pool.query(`
            CREATE TABLE IF NOT EXISTS importado (
              id SERIAL PRIMARY KEY,
              nome VARCHAR(255) NOT NULL,
              descricao TEXT,
              docente VARCHAR(255),
              dias_semana VARCHAR(50) NOT NULL,  
              hora_inicio TIME NOT NULL,       
              hora_fim TIME NOT NULL,           
              localizacao VARCHAR(255),          
              descricao_localizacao TEXT,        
              data_atividade DATE NOT NULL,      
              agendado VARCHAR(50),              
              turno VARCHAR(10) NOT NULL CHECK (turno IN ('MANHÃ', 'TARDE', 'NOITE')),
              criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
    `);
    console.log("Tabela 'importado' pronta!");

  } catch (err) {
      console.error("Erro ao criar tabelas:", err);
  }
}

criarTabelas();

pool.query('SELECT 1')
  .then(() => {
    console.log("Conectado ao Postgres!");
  })
  .catch(err => console.error("Erro na conexão", err));

module.exports = pool; // Exporta o pool, NÃO fecha a conexão!!