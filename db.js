const mysql = require('mysql2/promise'); 

// Configuração da conexão com o MySQL
const pool = mysql.createPool({
  host: 'metro.proxy.rlwy.net',
  user: 'root', // Substitua pelo usuário do MySQL
  database: 'railway',
  password: 'itTNpCtsLLOhDqNPuOsaWyYrnbIFvjdP', // Substitua pela senha do MySQL
  port: 42235 , // Porta padrão do MySQL
  ssl: {
    rejectUnauthorized: false, // Necessário para conexões seguras no Tembo
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function criarTabelas() {
  try {
    await pool.query(`
      create table if not exists curso(
      id INT AUTO_INCREMENT PRIMARY KEY NOT NULL, 
      nome varchar(255) not null unique
      );
    `);
    console.log("Tabela 'curso' pronta!");

    await pool.query(`
      create table if not exists turma(
      id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
      nome VARCHAR(255) NOT NULL,
      curso_id INT NOT NULL,
      foreign key (curso_id) references curso(id) on delete cascade
      );
    `);
    console.log("Tabela 'turma' pronta!");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS laboratorio (
          id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
          cimatec int not null,
          andar int not null,
          sala varchar(50) not null
      );
    `);
    console.log("Tabela 'laboratorio' pronta!");

    await pool.query(`
          CREATE TABLE IF NOT EXISTS materia (
              id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
              uc varchar(255) not null,
              ch int not null,
              curso_id INT NOT NULL,
              foreign key (curso_id) references curso(id) on delete cascade
          );
    `);
    console.log("Tabela 'disciplina' pronta!");

    await pool.query(`
          CREATE TABLE IF NOT EXISTS usuarios (
              id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
              nome VARCHAR(255) NOT NULL,
              email VARCHAR(255) UNIQUE NOT NULL,
              senha VARCHAR(255) NOT NULL,
              telefone1 VARCHAR(20) NULL,
              telefone2 VARCHAR(20) NULL,
              profilePic VARCHAR(255),
              tipo ENUM('docente', 'adm') NOT NULL
          );
    `);
    console.log("Tabela 'usuarios' pronta!");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS reset_tokens (
       id INT AUTO_INCREMENT PRIMARY KEY,
       user_id INT NOT NULL, 
       token VARCHAR(255) NOT NULL UNIQUE,
       expires DATETIME NOT NULL,
       used BOOLEAN DEFAULT FALSE,
       FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
     );
     `)
       console.log("Tabela 'reset_tokens' pronta!");

    await pool.query(`
          CREATE TABLE IF NOT EXISTS aula (
              id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
              usuario_id int,
              foreign key (usuario_id) references usuarios(id) on delete cascade,
              curso_id int not null,
              foreign key (curso_id) references curso(id) on delete cascade,
              materia_id int,
              foreign key (materia_id) references materia(id) on delete cascade,
              turma_id int not null,
              foreign key (turma_id) references turma(id) on delete cascade,
              laboratorio_id int,
              foreign key (laboratorio_id) references laboratorio(id) on delete cascade,
              turno varchar(255) not null,
              diasSemana varchar(255) NOT NULL,
              dataInicio date not null
          );
    `);
    console.log("Tabela 'aula' pronta!");

  } catch (err) {
      console.error("Erro ao criar tabelas:", err);
  }
}

criarTabelas();

pool.getConnection()
  .then(() => {
    console.log("Conectado ao MySQL no Railway!");
  })
  .catch(err => console.error("Erro na conexão", err));

module.exports = pool; // Exporta o pool, NÃO fecha a conexão!