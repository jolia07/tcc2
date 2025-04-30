const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const excelJS = require('exceljs');
const nodemailer = require('nodemailer');
const mysql = require('mysql2/promise');
const { Pool } = require('pg');
const cors = require('cors');
const xlsx = require('xlsx');
const fileUpload = require('express-fileupload');
const app = express();
require("dotenv").config();


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

app.use(fileUpload());
app.use(cors());
app.use(express.json());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));
app.use('/img', express.static(path.join(__dirname, 'img')));


app.use(session({
  secret: 'seuSegredoAqui',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  }
}));


const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'sepa.suporte@gmail.com',
    pass: 'fidf zuqj szww fahd'
  },
  tls: {
    rejectUnauthorized: false // Adicione esta linha para ambiente local
  }
});


// Rota protegida - Página inicial
app.get('/calendario', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'calendario.html'));
});


 // Rota para perfil do usuário
app.get('/perfil', verificarAutenticacao, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'perfil.html'));
});


app.get('/notificacoes-page', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'notificacoes.html'));
});


app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/home.html');
});


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'img'));
  },
  filename: (req, file, cb) => {
    const userId = req.session.user.id;
    const ext = path.extname(file.originalname);
    cb(null, `profile_${userId}${ext}`);
  }
});


const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());




    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Apenas imagens são permitidas!'));
  }
});


// Configuração para upload de planilhas Excel
const planilhaStorage = multer.diskStorage({
  destination: path.join(__dirname, 'uploads', 'planilhas'),
  filename: (req, file, cb) => {
      cb(null, `aulas_${req.session.user.id}.xlsx`);
  }
});

const uploadPlanilha = multer({
  storage: planilhaStorage,
  fileFilter: (req, file, cb) => {
      const allowed = /xlsx/.test(path.extname(file.originalname).toLowerCase());
      if (allowed) return cb(null, true);
      cb(new Error('Somente arquivos Excel (.xlsx) são permitidos!'));
  },
  limits: {
      fileSize: 10 * 1024 * 1024 // 10MB
  }
});


// Middleware de autenticação
function verificarAutenticacao(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
}


//Rota para segundo telefone
app.post('/definirTelefone2', async (req, res) => {
  const { telefone2 } = req.body;


  if (!req.session.user) {
      return res.status(401).json({ error: "Usuário não autenticado" });
  }


  try {
      await pool.query(
          "UPDATE usuarios SET telefone2 = $1 WHERE id = $2",
          [telefone2 || null, req.session.user.id]
      );


      // Atualiza a sessão do usuário com o novo telefone
      req.session.user.telefone2 = telefone2 || null;


      req.session.save(err => {
          if (err) {
              console.error("Erro ao salvar sessão:", err);
              return res.status(500).json({ error: "Erro ao salvar sessão" });
          }
          res.json({ success: true });
      });


  } catch (err) {
      console.log("Erro ao atualizar Telefone2:", error);
  }
});


// Rota de login do sistema
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;


  try {
    const {rows} = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);


    if (rows.length === 0) {
      return res.status(401).send('E-mail ou senha incorretos!');
    }


    const usuario = rows[0];
    const senhaCorreta = await bcrypt.compare(senha, usuario.senha);


    if (!senhaCorreta) {
      return res.status(401).send('E-mail ou senha incorretos!');
    }


    req.session.user = {
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      tipo: usuario.tipo
    };


    req.session.save(() => {
      console.log('Sessão salva:', req.session.user);
      res.json({ message: "Login bem-sucedido!", user: req.session.user });
    });


  } catch (err) {
    console.error('Erro ao fazer login:', err);
    res.status(500).send('Erro no servidor.');
  }
});


app.post('/cadastro', async (req, res) => {
  const { nome, email, senha, telefone1, tipo } = req.body;

  if (!['Docente', 'Administrador'].includes(tipo)) {
    return res.status(400).json({ message: "Tipo inválido! Use 'Docente' ou 'Administrador'." });
  }

  try {
    const checkUser = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (checkUser.rows.length > 0) { 
      return res.status(409).send('Usuário já existe');
    }

    const senhaCriptografada = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nome, email, senha, telefone1, tipo) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [nome, email, senhaCriptografada, telefone1, tipo]
    );

    req.session.user = { 
      id: result.rows[0].id, 
      nome, 
      email, 
      telefone1, 
      tipo: tipo
    };

    console.log('Usuário registrado:', req.session.user);
    res.redirect('perfil');

  } catch (err) {
    console.error('Erro ao cadastrar usuário:', err);
    res.status(500).send('Erro no servidor.');
  }
});


// Rota para upload de imagem de perfil
app.post('/upload-profile-image', verificarAutenticacao, upload.single('profilePic'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Nenhum arquivo foi enviado' });
  }


  try {
    const userId = req.session.user.id;
    const imagePath = req.file.filename;


    await pool.query('UPDATE usuarios SET profilePic = $1 WHERE id = $2', [imagePath, userId]);
    res.json({ message: 'Imagem atualizada com sucesso!', filename: imagePath });


  } catch (err) {
    console.error('Erro ao atualizar foto de perfil:', err);
    res.status(500).send('Erro no servidor.');
  }
});


app.use('/uploads', express.static('uploads'));




// Rota para atualizar senha
app.post('/atualizarSenha', async (req, res) => {
  const { email, newPassword } = req.body;


  try {
    const {rows} = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.json({ success: false, message: 'Usuário não encontrado.' });
    }


    const senhaCriptografada = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE usuarios SET senha = $1 WHERE email = $2', [senhaCriptografada, email]);


    res.json({ success: true, message: 'Senha atualizada com sucesso!' });


  } catch (err) {
    console.error('Erro ao atualizar senha:', err);
    res.status(500).send('Erro no servidor.');
  }
});


app.post('/redefinirSenhaDireta', async (req, res) => {
  const { email, novaSenha } = req.body;


  try {
      const {rows} = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
      if (rows.length === 0) {
          return res.json({ success: false, message: 'E-mail não encontrado.' });
      }


      const senhaCriptografada = await bcrypt.hash(novaSenha, 10);
      await pool.query('UPDATE usuarios SET senha = $1 WHERE email = $2', [senhaCriptografada, email]);


      res.json({ success: true, message: 'Senha redefinida com sucesso!' });


  } catch (err) {
      console.error('Erro ao redefinir senha:', err);
      res.status(500).send('Erro no servidor.');
  }
});


// Rota para atualizar perfil
app.post('/atualizarPerfil', verificarAutenticacao, async (req, res) => {
  const { nome, email, senha } = req.body;
  const userId = req.session.user.id;


  try {
    const senhaCriptografada = await bcrypt.hash(senha, 10);
    await pool.query('UPDATE usuarios SET nome = $1, email = $2, senha = $3 WHERE id = $4',
      [nome, email, senhaCriptografada, userId]);


    res.json({ message: 'Perfil atualizado com sucesso!' });


  } catch (err) {
    console.error('Erro ao atualizar perfil:', err);
    res.status(500).send('Erro no servidor.');
  }
});


// Rota para solicitar redefinição de senha (app.js)
app.post('/solicitar-redefinicao', async (req, res) => {
  const { email } = req.body;
 
  try {
    console.log('Solicitação de redefinição recebida para:', email);
   
    const {user} = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (!user.length) {
      console.log('E-mail não encontrado:', email);
      return res.status(200).json({ message: 'Se existir uma conta com este email, um link foi enviado.' });
    }

    // Geração do token e link
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hora
    const resetLink = `https://sepa-api.onrender.com/redefinir-senha.html?token=${token}`;    
    await pool.query(
      'INSERT INTO reset_tokens (user_id, token, expires) VALUES ($1, $2, $3)',
      [user[0].id, token, expires.toISOString().slice(0, 19).replace('T', ' ')] // Formato MySQL
    );

    console.log('Token inserido:', token); // Log para depuração

    // Configuração do e-mail
    const mailOptions = {
      from: 'Suporte SEPA <sepa.suporte@gmail.com>',
      to: email,
      subject: 'Redefinição de Senha',
      html: `
        <h2>Redefinição de Senha</h2>
        <p>Clique no link: <a href="${resetLink}">${resetLink}</a></p>
      `
    };

    console.log('Enviando e-mail para:', email);
    const info = await transporter.sendMail(mailOptions);
    console.log('E-mail enviado:', info.response); // Alterar para info.response
   
    res.json({ message: 'Um email com instruções foi enviado!' });
  } catch (err) {
    console.error('Erro completo:', err);
    res.status(500).send('Erro no servidor');
  }
});


transporter.verify((error, success) => {
  if (error) {
    console.log('Erro na configuração do e-mail:', error);
  } else {
    console.log('Servidor de e-mail configurado corretamente');
  }
});


// Rota para redefinir a senha
app.post('/redefinir-senha', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const {tokenData} = await pool.query(
      `SELECT * FROM reset_tokens
      WHERE token = $1
      AND used = FALSE
      AND expires > (NOW() AT TIME ZONE 'UTC')`, // Usar UTC para evitar problemas de fuso
      [token]
    );

    if (!tokenData || tokenData.length === 0) {
      return res.status(400).json({ message: 'Link inválido ou expirado' });
    }

    const senhaCriptografada = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE usuarios SET senha = $1 WHERE id = $2',
        [senhaCriptografada, tokenData[0].user_id]);

    await pool.query('UPDATE reset_tokens SET used = TRUE WHERE token = $1', [token]);
     
    res.json({ message: 'Senha redefinida com sucesso! Você pode fazer login agora.' });
  }catch (err) {
    console.error('Erro detalhado:', err.message); // Log detalhado
    res.status(500).send('Erro no servidor');
  }
});


//Verificando informações
//Recebendo os usuário ao sistema
function verificarTipoUsuario(tiposPermitidos) {
  return (req, res, next) => {
      if (!req.session || !req.session.user) {
          return res.status(401).json({ erro: "Não autorizado" });
      }
      const { tipo } = req.session.user;
      if (!tiposPermitidos.includes(tipo)) {
          return res.status(403).json({ erro: "Acesso negado" });
      }
      next();
  };
}


// Rota para buscar dados do usuário
app.get('/getUserData', verificarAutenticacao, async (req, res) => {
  const userId = req.session.user.id;


  try {
    const {rows} = await pool.query('SELECT id, nome, email, telefone1, telefone2, profilePic, tipo FROM usuarios WHERE id = $1', [userId]);
   
    if (rows.length === 0) {
      return res.status(404).json({ error: "Usuário não encontrado." });
    }


    res.json(rows[0]); // Retorna o usuário com o ID
  } catch (err) {
    console.error('Erro ao buscar dados do usuário:', err);
    res.status(500).send('Erro no servidor.');
  }
});


//Buttons de cadastros para aula
//Rota ´para cadastrar curso
app.post('/curso', async (req, res) => {
  try {
      const { nome } = req.body;


      if (!nome) {
          return res.status(400).json({ error: "O nome do curso é obrigatório." });
      }


      await pool.query("INSERT INTO curso (nome) VALUES ($1)", [nome]);
      res.json({ message: "Curso cadastrado com sucesso!" });


  } catch (error) {
      if (error.code === '23505') {
          return res.status(400).json({ error: "Já existe um curso com esse nome." });
      }
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar o curso." });
  }
});


app.get('/curso', async (req, res) => {
  try {
      const {rows} = await pool.query("SELECT * FROM curso");
      res.json(rows);
  } catch (error) {
      console.error("Erro ao buscar cursos:", error);
      res.status(500).json({ error: "Erro ao buscar cursos." });
  }
});


//Rota para cadastrar turma
app.post('/turma', async (req, res) => {
  try {
      const { nome, curso_id } = req.body;


      if (!nome || !curso_id) {
          return res.status(400).json({ error: "Nome da turma e curso_id são obrigatórios." });
      }


      await pool.query("INSERT INTO turma (nome, curso_id) VALUES ($1, $2)", [nome, curso_id]);
      res.json({ message: "Turma cadastrada com sucesso!" });
  } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: "Já existe uma turma com esse nome." });
      }
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar a turma." });
  }
});


app.get('/turma', async (req, res) => {
  try {
    const {rows} = await pool.query(`
        SELECT turma.id, turma.nome AS nome, curso.nome AS curso
        FROM turma
        JOIN curso ON turma.curso_id = curso.id
    `);
    res.json(rows);
} catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao buscar turmas." });
}
});


//Rota para cadastrar laboratorio
app.post('/laboratorio', async (req, res) => {
  try {
      const { cimatec, andar, sala } = req.body;


      if (!cimatec || !andar || !sala) {
          return res.status(400).json({ error: "Todos os campos do laboratório são obrigatórios." });
      }


      await pool.query("INSERT INTO laboratorio (cimatec, andar, sala) VALUES ($1, $2, $3)", [cimatec, andar, sala]);
      res.json({ message: "Laboratório cadastrado com sucesso!" });
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar o laboratório." });
  }
});


app.get('/laboratorio', async (req, res) => {
      const {rows} = await pool.query("SELECT * FROM laboratorio");
      res.json(rows);
});


// Rota para cadastrar matéria 
app.post('/materia', async (req, res) => {
  try {
    const { uc, ch, curso_id } = req.body;

    console.log("Dados recebidos no backend:", req.body);

    if (!uc || !ch || !curso_id) {
      return res.status(400).json({ error: "Todos os campos da matéria são obrigatórios." });
    }

    // Correção na desestruturação
    const { rows: materiaExistente } = await pool.query(
      "SELECT * FROM materia WHERE uc = $1 AND curso_id = $2", 
      [uc, curso_id]
    );

    if (materiaExistente.length > 0) {
      return res.status(400).json({ error: "Esta matéria já está cadastrada para este curso!" });
    }

    // Inserção com RETURNING para obter o resultado
    const { rows } = await pool.query(
      "INSERT INTO materia (uc, ch, curso_id) VALUES ($1, $2, $3) RETURNING *", 
      [uc, ch, curso_id]
    );

    res.status(201).json({ 
      success: true,
      message: "Matéria cadastrada com sucesso!",
      materia: rows[0]
    });

  } catch (error) {
    console.error("Erro detalhado:", error);
    res.status(500).json({ 
      error: "Erro ao cadastrar a matéria.",
      details: error.message
    });
  }
});


app.get('/materia', async (req, res) => {
  try {
      const {rows} = await pool.query(`
          SELECT materia.id, materia.uc, materia.ch, curso.nome AS curso
          FROM materia
          JOIN curso ON materia.curso_id = curso.id
      `);
      res.json(rows);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Erro ao buscar matérias." });
  }
});


// Rota para cadastrar aula - Versão Corrigida
app.post('/aulas', async (req, res) => {
  try {
    // Verificar se o usuário está autenticado
    if (!req.session.user || !req.session.user.id) {
      return res.status(401).json({ error: "Usuário não autenticado." });
    }

    const { curso_id, materia_id, turma_id, laboratorio_id, turno, diasSemana, dataInicio } = req.body;
    const usuario_id = req.session.user.id;

    console.log("Recebido no backend:", req.body);
    
    // Validar campos obrigatórios
    if (!curso_id || !materia_id || !turma_id || !laboratorio_id || !turno || !diasSemana || !dataInicio) {
      return res.status(400).json({ error: "Todos os campos da aula são obrigatórios." });
    }

    // Verificar se o laboratório já está alocado no mesmo horário e turno
    const queryLaboratorio = `
      SELECT *
      FROM aula
      WHERE laboratorio_id = $1
      AND dataInicio = $2
      AND turno = $3;
    `;
    const { rows: rowsLaboratorio } = await pool.query(queryLaboratorio, [laboratorio_id, dataInicio, turno]);

    if (rowsLaboratorio.length > 0) {
      return res.status(400).json({ error: "Este laboratório já está ocupado neste horário!" });
    }

    // Verificar se a turma já tem aula no mesmo turno
    const queryTurma = `
      SELECT *
      FROM aula
      WHERE turma_id = $1
      AND dataInicio = $2
      AND turno = $3;
    `;
    const { rows: rowsTurma } = await pool.query(queryTurma, [turma_id, dataInicio, turno]);

    if (rowsTurma.length > 0) {
      return res.status(400).json({ error: "Esta turma já possui uma aula no turno selecionado!" });
    }

    // Se não houver conflitos, cadastrar a aula
    const queryInsert = `
      INSERT INTO aula 
        (usuario_id, curso_id, materia_id, turma_id, laboratorio_id, turno, diasSemana, dataInicio) 
      VALUES 
        ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `;
    
    const { rows: newAula } = await pool.query(queryInsert, [
      usuario_id, 
      curso_id, 
      materia_id, 
      turma_id, 
      laboratorio_id, 
      turno, 
      Array.isArray(diasSemana) ? diasSemana.join(',') : diasSemana, 
      dataInicio
    ]);

    res.status(201).json({ 
      success: true,
      message: "Aula cadastrada com sucesso!",
      aula: newAula[0]
    });

  } catch (error) {
    console.error("Erro detalhado:", error);
    res.status(500).json({ 
      error: "Erro ao cadastrar a aula.",
      details: error.message 
    });
  }
});


app.get('/aulas', async (req, res) => {
  if (!req.session || !req.session.user || !req.session.user.id) {
    return res.status(401).json({ error: "Usuário não autenticado" });
  }

  const usuario_id = req.session.user.id;
  const userType = req.session.user.tipo;

  try {
    let query = `
      SELECT
        a.id,
        u.nome AS professor,
        c.nome AS curso,
        m.uc AS materia,
        t.nome AS turma,
        CONCAT('CIMATEC ', l.cimatec, ' - Andar ', l.andar, ' - Sala ', l.sala) AS laboratorio,
        a.turno,
        a.diasSemana,
        a.dataInicio
      FROM aula a
      LEFT JOIN usuarios u ON a.usuario_id = u.id
      LEFT JOIN curso c ON a.curso_id = c.id
      LEFT JOIN materia m ON a.materia_id = m.id
      LEFT JOIN turma t ON a.turma_id = t.id
      LEFT JOIN laboratorio l ON a.laboratorio_id = l.id
    `;
    let values = [];

    // Se for docente, filtramos apenas as aulas que ele cadastrou
    if (userType === 'Docente') {
      query += " WHERE a.usuario_id =$1";
      values.push(usuario_id);
    }

    const {rows} = await pool.query(query, values);
    const aulasFormatadas = rows.map(aula => {
      // Converter a string de diasSemana para array
      let diasArray = [];
      if (aula.diassemana) {
        // Remove espaços em branco e divide pela vírgula
        diasArray = aula.diassemana.split(',').map(dia => dia.trim());
      }
      
      return {
        ...aula,
        diasSemana: diasArray
      };
    });

    res.json(aulasFormatadas);

  } catch (error) {
    console.error("Erro ao buscar aulas:", error);
    res.status(500).json({ error: "Erro ao buscar aulas." });
  }
});


// Rota para pegar todas as aulas (apenas admin)
app.get('/todasAulas', async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.tipo !== 'Administrador') {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const query = `
      SELECT
        a.id,
        u.nome AS professor,
        c.nome AS curso,
        m.uc AS materia,
        t.nome AS turma,
        CONCAT('CIMATEC ', l.cimatec, ' - Andar ', l.andar, ' - Sala ', l.sala) AS laboratorio,
        a.turno,
        a.diasSemana,
        a.dataInicio
      FROM aula a
      LEFT JOIN usuarios u ON a.usuario_id = u.id
      LEFT JOIN curso c ON a.curso_id = c.id
      LEFT JOIN materia m ON a.materia_id = m.id
      LEFT JOIN turma t ON a.turma_id = t.id
      LEFT JOIN laboratorio l ON a.laboratorio_id = l.id
    `;

    const { rows } = await pool.query(query);
    res.json(rows.map(aula => ({
      ...aula,
      diasSemana: aula.diassemana ? aula.diassemana.split(',').map(d => d.trim()) : []
    })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar aulas' });
  }
});


app.get('/aulasHoje', async (req, res) => {
  console.log('Sessão do usuário:', req.session.user);
  
  if (!req.session.user?.id) {
    return res.status(401).json({ error: "Não autenticado" });
  }

  const hoje = new Date();
  hoje.setHours(0, 0, 0, 0);
  const hojeFormatado = hoje.toISOString().split('T')[0];

  try {
    // 1. Busca o usuário
    const userQuery = await pool.query(
      'SELECT id, nome, email FROM usuarios WHERE id = $1', 
      [req.session.user.id]
    );
    
    if (userQuery.rows.length === 0) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }
    
    const usuario = userQuery.rows[0];

    // 2. Primeira tentativa: busca com filtro de docente
    let aulasResult = await pool.query(`
      SELECT id, nome AS materia, turno, data_atividade,
             hora_inicio, hora_fim, localizacao
      FROM importado
      WHERE (docente = $1 OR docente ILIKE $2 OR docente ILIKE $3)
        AND data_atividade = $4
      ORDER BY hora_inicio`, 
      [
        usuario.nome, 
        `%${usuario.nome}%`,
        `%${usuario.email.split('@')[0]}%`,
        hojeFormatado
      ]);

    // 3. Segunda tentativa: se não encontrou, busca todas as aulas do dia
    if (aulasResult.rows.length === 0) {
      aulasResult = await pool.query(`
        SELECT id, nome AS materia, turno, data_atividade,
               hora_inicio, hora_fim, localizacao
        FROM importado 
        WHERE data_atividade = $1
        ORDER BY hora_inicio`, 
        [hojeFormatado]);
    }

    // 4. Formata os dados para o front-end
    const aulasFormatadas = aulasResult.rows.map(aula => ({
      ...aula,
      hora_inicio: aula.hora_inicio?.substring(0, 5) || '',
      hora_fim: aula.hora_fim?.substring(0, 5) || ''
    }));

    res.json(aulasFormatadas);
  } catch (error) {
    console.error('Erro:', error);
    res.status(500).json({ 
      error: "Erro no servidor",
      details: error.message
    });
  }
});


app.get('/adm', async (req, res) => {
  try {
    if (!req.session?.user?.id) {
      return res.json({ isAdmin: false });
    }
    res.json({ isAdmin: req.session.user.tipo === 'Administrador' });
  } catch (error) {
    console.error("Erro ao verificar Administrador:", error);
    res.status(500).json({ isAdmin: false });
  }
});

app.get('/docentes', async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.tipo !== 'Administrador') {
      return res.status(403).json({ error: "Acesso não autorizado" });
    }
    const {rows} = await pool.query(
      'SELECT id, nome FROM usuarios WHERE tipo = $1 ORDER BY nome',
      ['Docente']
    );
    res.json(rows);
  } catch (error) {
    console.error("Erro ao buscar docentes:", error);
    res.status(500).json({ error: "Erro ao buscar docentes" });
  }
});

// Rota para obter docentes da tabela importado
app.get('/docentesImportado', async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.tipo !== 'Administrador') {
      return res.status(403).json({ error: "Acesso não autorizado" });
    }
    const { rows } = await pool.query(
      'SELECT DISTINCT docente as nome FROM importado WHERE docente IS NOT NULL AND docente != \'\' ORDER BY docente'
    );
    res.json(rows);
  } catch (error) {
    console.error("Erro ao buscar docentes:", error);
    res.status(500).json({ error: "Erro ao buscar docentes" });
  }
});

function getColorForMateria(materia) {
  // Usamos um hash simples para gerar um código de cor baseado no nome da matéria
  let hash = 0;
  for (let i = 0; i < materia.length; i++) {
    hash = materia.charCodeAt(i) + ((hash << 5) - hash);
  }
 
  // Gerar cores pastel
  const r = (hash & 0xFF0000) >> 16;
  const g = (hash & 0x00FF00) >> 8;
  const b = hash & 0x0000FF;
 
  // Converter para tons pastel (adicionando branco)
  const pastelR = Math.round((r + 255) / 2).toString(16).padStart(2, '0');
  const pastelG = Math.round((g + 255) / 2).toString(16).padStart(2, '0');
  const pastelB = Math.round((b + 255) / 2).toString(16).padStart(2, '0');
 
  return `FF${pastelR}${pastelG}${pastelB}`; // Formato ARGB (FF = alpha totalmente opaco)
}

// Upload e processamento do Excel
app.post('/upload-laboratorios', async (req, res) => {
  if (!req.files || !req.files.planilha) {
    return res.status(400).send('Nenhum arquivo enviado.');
  }

  try {
    const workbook = xlsx.read(req.files.planilha.data, { type: 'buffer' });
    const primeiraAba = workbook.SheetNames[0];
    const dados = xlsx.utils.sheet_to_json(workbook.Sheets[primeiraAba]);

    // Objeto para agrupar por docente
    const agrupadoPorDocente = {};

    //Na parte do código que processa os dados:
    dados.forEach(linha => {
      const docente = linha['Nome do pessoal atribuído'] || 'Sem docente';
      
      if (!agrupadoPorDocente[docente]) {
        agrupadoPorDocente[docente] = [];
      }

      // Processa as datas
      const datas = linha['Datas da atividade (Individual)'] 
        ? linha['Datas da atividade (Individual)'].split(';').map(d => d.trim())
        : [];

      // Converte os horários para formato adequado
      const horaInicio = converterHoraExcel(linha['Hora de início agendada']);
      const horaFim = converterHoraExcel(linha['Fim Agendado']);

      // Cria um registro para cada data
      datas.forEach(data => {
        agrupadoPorDocente[docente].push({
          nome: linha['Nome'],
          descricao: linha['Descrição'],
          docente,
          dias_semana: linha['Dias agendados'],
          hora_inicio: horaInicio,
          hora_fim: horaFim,
          localizacao: linha['Nome da localização atribuída'],
          descricao_localizacao: linha['Descrição da localização atribuída'],
          data_atividade: data,
          agendado: linha['Agendado'],
          turno: determinarTurno(horaInicio)
        });
      });
    });

    // Agora insere no banco de dados para cada docente
    const resultados = {};
    
    for (const [docente, registros] of Object.entries(agrupadoPorDocente)) {
      resultados[docente] = {
        total: registros.length,
        inseridos: 0,
        erros: 0,
        detalhes: []
      };

      for (const registro of registros) {
        try {
          // Formata a data para o padrão YYYY-MM-DD
          const dataFormatada = registro.data_atividade.split('/').reverse().join('-');
          
          // Insere na tabela importado
          const insertRes = await pool.query(
            `INSERT INTO importado (
              nome, descricao, docente, dias_semana, 
              hora_inicio, hora_fim, localizacao, 
              descricao_localizacao, data_atividade, 
              agendado, turno
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
            [
              registro.nome,
              registro.descricao,
              registro.docente,
              registro.dias_semana,
              registro.hora_inicio,
              registro.hora_fim,
              registro.localizacao,
              registro.descricao_localizacao,
              dataFormatada,
              registro.agendado,
              registro.turno
            ]
          );

          resultados[docente].inseridos++;
          resultados[docente].detalhes.push({
            id: insertRes.rows[0].id,
            data: registro.data_atividade,
            status: 'sucesso'
          });
        } catch (error) {
          console.error(`Erro ao inserir registro para ${docente}:`, error);
          resultados[docente].erros++;
          resultados[docente].detalhes.push({
            data: registro.data_atividade,
            status: 'erro',
            mensagem: error.message
          });
        }
      }
    }

    res.json({
      success: true,
      message: 'Processamento concluído',
      resultados
    });

  } catch (error) {
    console.error('Erro ao processar planilha:', error);
    res.status(500).json({
      success: false,
      message: 'Erro ao processar planilha',
      error: error.message
    });
  }
});

// Função para converter valores de hora do Excel para formato HH:MM
function converterHoraExcel(valor) {
  // Se já estiver no formato HH:MM, retorna direto
  if (typeof valor === 'string' && valor.match(/^\d{1,2}:\d{2}$/)) {
    return valor;
  }
  
  // Se for um número (formato Excel), converte
  if (typeof valor === 'number') {
    // Converte fração de dia para horas decimais
    const horasDecimais = valor * 24;
    const horas = Math.floor(horasDecimais);
    const minutos = Math.round((horasDecimais - horas) * 60);
    
    // Formata com zero à esquerda
    return `${horas.toString().padStart(2, '0')}:${minutos.toString().padStart(2, '0')}`;
  }
  
  // Se não reconhecer o formato, retorna um padrão
  return '00:00';
}

// Função auxiliar para determinar turno baseado no horário
function determinarTurno(hora) {
  const horaFormatada = converterHoraExcel(hora);
  const [horas] = horaFormatada.split(':').map(Number);
  
  if (horas < 12) return 'MANHÃ';
  if (horas < 18) return 'TARDE';
  return 'NOITE';
}

// No seu servidor Node.js (backend)
app.get('/importado', async (req, res) => {
  try {
      const result = await pool.query('SELECT * FROM importado ORDER BY data_atividade DESC');
      res.json(result.rows);
  } catch (error) {
      console.error('Erro ao buscar dados importados:', error);
      res.status(500).json({ error: 'Erro ao buscar dados' });
  }
});


//Rota da planilha(montagem)
app.get('/exportar-excel', async (req, res) => {
  try {
    if (!req.session || !req.session.user || !req.session.user.id) {
      return res.status(401).json({ error: "Usuário não autenticado" });
    }
      
    const isAdmin = req.session.user.tipo === 'Administrador';
    let docenteId;
    let docenteNome;

    // Lógica para obter o docente (por nome para admin, por ID para docente normal)
    if (isAdmin && req.query.docente_nome) {
      // Busca o docente pelo nome
      docenteNome = req.query.docente_nome.trim();
      
      const { rows: docenteCheck } = await pool.query(
        'SELECT id, nome FROM usuarios WHERE nome = $1 AND tipo = $2',
        [docenteNome, 'Docente']
      );
      
      if (docenteCheck.length === 0) {
        return res.status(404).json({ 
          error: "Docente não encontrado",
          details: `Nenhum docente encontrado com o nome "${docenteNome}"`
        });
      }
      
      // Se houver mais de um docente com o mesmo nome
      if (docenteCheck.length > 1) {
        return res.status(400).json({
          error: "Múltiplos docentes encontrados",
          details: `Foram encontrados ${docenteCheck.length} docentes com o nome "${docenteNome}".`,
          sugestoes: docenteCheck.map(d => ({ id: d.id, nome: d.nome }))
        });
      }
      
      docenteId = docenteCheck[0].id;
      docenteNome = docenteCheck[0].nome;
    } else {
      // Usa o ID do usuário logado (para docentes não-admins)
      docenteId = req.session.user.id;
    }
      
    // Buscar dados do docente
    const {rows: userData} = await pool.query(
       'SELECT nome, email, telefone1, telefone2 FROM usuarios WHERE id = $1',
       [docenteId]
    );
      
      if (userData.length === 0) {
       return res.status(404).json({ error: "Usuário não encontrado" });
      }
      
    const docente = userData[0];
    docenteNome = docente.nome; 
      
    const {rows: aulas} = await pool.query(`
     SELECT
      a.id,
     u.nome AS professor,
     c.nome AS curso,
      m.uc AS materia,
     m.ch AS cargaHoraria,
     t.nome AS turma,
     CONCAT('CIMATEC ', l.cimatec, ' - Andar ', l.andar, ' - Sala ', l.sala) AS laboratorio,
     a.turno,
     a.diasSemana,
     a.dataInicio
      FROM aula a
       LEFT JOIN usuarios u ON a.usuario_id = u.id
       LEFT JOIN curso c ON a.curso_id = c.id
       LEFT JOIN materia m ON a.materia_id = m.id
       LEFT JOIN turma t ON a.turma_id = t.id
       LEFT JOIN laboratorio l ON a.laboratorio_id = l.id
       WHERE a.usuario_id = $1
    `, [docenteId]);
      
    if (aulas.length === 0) {
      const msg = isAdmin
      ? `Nenhuma aula encontrada para o docente ${docente.nome}`
      : "Nenhuma aula cadastrada para o seu usuário";
     return res.status(404).json({ error: msg });
    }

    const planilha = new excelJS.Workbook();
    const aba = planilha.addWorksheet('Aulas');
    // Preencher informações do docente
    aba.getCell('B2').value = docente.nome;    // Nome do docente
    aba.getCell('B3').value = docente.email;   // E-mail
    aba.getCell('B4').value = docente.telefone1 || '';  // Telefone 1
    aba.getCell('B5').value = docente.telefone2 || '';  // Telefone 2
    // Configuração dos horários
    const horariosDia = [
      "07:30 - 08:30", "08:30 - 09:30", "09:30 - 10:30", "10:30 - 11:30", "",
      "13:00 - 14:00", "14:00 - 15:00", "15:00 - 16:00", "16:00 - 17:00", "",
      "18:40 - 21:40", ""
    ];
   
    const linhaHorario = [12, 27, 42, 57, 72, 87, 102, 117, 132, 147, 162, 177];

    // Preencher horários na coluna A
    linhaHorario.forEach((linhaBase) => {
      horariosDia.forEach((horario, indice) => {
        const linhaAtual = linhaBase + indice;
        aba.getCell(linhaAtual, 1).value = horario;
        aba.getCell(linhaAtual, 1).fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FFD9D9D9' },
        };
      });
    });

    // Configuração de mesclagem de células
    aba.mergeCells('B1:F1');
    aba.mergeCells('B2:F2');
    aba.mergeCells('B3:F3');
    aba.mergeCells('B4:F4');
    aba.mergeCells('B5:F5');
    aba.mergeCells('A6:AF6');
    aba.mergeCells('H1:R1');
    aba.mergeCells('AF1:AF5');
    aba.mergeCells('G1:G5');

    // Mesclagem de células dos meses
    aba.mergeCells('A9:AF9');
    aba.mergeCells('A8:AF8');
    aba.mergeCells('A24:AD24');
    aba.mergeCells('A39:AF39');
    aba.mergeCells('A54:AE54');
    aba.mergeCells('A69:AF69');
    aba.mergeCells('A84:AE84');
    aba.mergeCells('A99:AF99');
    aba.mergeCells('A114:AF114');
    aba.mergeCells('A129:AE129');
    aba.mergeCells('A144:AF144');
    aba.mergeCells('A159:AE159');
    aba.mergeCells('A174:AF174');

    // Cabeçalhos e títulos
    aba.getCell('B1').value = "Dados do Docente";
    aba.getCell('A8').value = "Cronograma do período letivo";


    // Nomes dos meses
    const meses = [
      {nome: "Janeiro", linha: 9},
      {nome: "Fevereiro", linha: 24},
      {nome: "Março", linha: 39},
      {nome: "Abril", linha: 54},
      {nome: "Maio", linha: 69},
      {nome: "Junho", linha: 84},
      {nome: "Julho", linha: 99},
      {nome: "Agosto", linha: 114},
      {nome: "Setembro", linha: 129},
      {nome: "Outubro", linha: 144},
      {nome: "Novembro", linha: 159},
      {nome: "Dezembro", linha: 174}
    ];

    meses.forEach(mes => {
      aba.getCell(`A${mes.linha}`).value = mes.nome;
    });

    // Centralização
    aba.getCell('B1').alignment = { horizontal: 'center', vertical: 'middle' };
    aba.getCell('H1').alignment = { horizontal: 'center', vertical: 'middle' };

    const linhasParaCentralizar = [8, ...meses.map(m => m.linha)];
    linhasParaCentralizar.forEach(linha => {
      aba.getCell(`A${linha}`).alignment = {
        horizontal: 'center',
        vertical: 'middle'
      };
    });

    // Cabeçalho dos meses (JAN, FEV, etc.)
    const mesesAbreviados = ["JAN", "FEV", "MAR", "ABR", "MAI", "JUN", "JUL", "AGO", "SET", "OUT", "NOV", "DEZ"];
    mesesAbreviados.forEach((mes, indice) => {
      const celula = aba.getCell(1, indice + 20);
      celula.value = mes;
      celula.alignment = { horizontal: 'center' };
    });

    // Estilo do cabeçalho
    aba.getRow(1).eachCell((celula) => {
      celula.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF1E3A5F' }
      };
      celula.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' }
      };
    });

    // Labels e legendas
    aba.getCell('A2').value = "Docente:";
    aba.getCell('A3').value = "E-mail:";
    aba.getCell('A4').value = "Tel.1:";
    aba.getCell('A5').value = "Tel.2:";
    aba.getCell('S2').value = "Dias Úteis:";
    aba.getCell('S3').value = "Horas Úteis:";
    aba.getCell('S4').value = "Horas Alocadas:";
    aba.getCell('H1').value = "Legenda";

    const materiasUnicas = [...new Set(aulas.map(aula => aula.materia))];

    let colunaAtual = 8;

    materiasUnicas.forEach((materia, index) => {
      const corMateria = getColorForMateria(materia);
      const colunaLetra = String.fromCharCode(64 + colunaAtual);
     
      // Célula com nome da matéria
      aba.getCell(`${colunaLetra}2`).value = materia;
      aba.getCell(`${colunaLetra}2`).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: corMateria }
      };
      aba.getCell(`${colunaLetra}2`).font = {
        bold: true,
        color: { argb: 'FF000000' } // Texto preto para melhor contraste
      };
      aba.getCell(`${colunaLetra}2`).alignment = {
        horizontal: 'center',
        vertical: 'middle',
        wrapText: true
      };
      aba.getCell(`${colunaLetra}2`).border = {
        top: { style: 'thin', color: { argb: 'FF000000' } },
        left: { style: 'thin', color: { argb: 'FF000000' } },
        bottom: { style: 'thin', color: { argb: 'FF000000' } },
        right: { style: 'thin', color: { argb: 'FF000000' } }
      };
     
      // Ajustar largura da coluna
      aba.getColumn(colunaAtual).width = 20;
     
      colunaAtual++;
     
      // Limitar a quantidade de matérias para não ultrapassar o limite da planilha
      if (colunaAtual > 50) return; // Limite arbitrário para não estourar colunas
    });
    

    // Estilo dos meses
    meses.forEach(mes => {
      const celula = aba.getCell(`A${mes.linha}`);
      celula.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF33658A' }
      };
      celula.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' }
      };
    });

    // Estilo das células de cabeçalho
    ["A8", "A1", "A2", "A3", "A4", "A5", "A6", "S1", "S2", "S3", "S4", 'S5', 'AF1', 'G1', 'S1'].forEach(endereco => {
      const celula = aba.getCell(endereco);
      celula.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF1E3A5F' }
      };
      celula.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' }
      };
    });

    // Configuração dos dias da semana e dias do mês
    const semanaPorMes = {
      "Dom": [85],
      "Seg": [130, 175],
      "Ter": [55, 100],
      "Qua": [10, 145],
      "Qui": [70],
      "Sex": [115],
      "Sáb": [25, 40, 160],
    };
   
    const diasPorMes = {
      31: [11, 41, 71, 101, 116, 146, 176],
      30: [56, 86, 131, 161],
      29: [26]
    };
   
    const diasDaSemana = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sáb"];
   
    const mapaInicioSemana = {};
    Object.entries(semanaPorMes).forEach(([dia, linhas]) => {
      linhas.forEach(linhaSemana => {
        mapaInicioSemana[linhaSemana + 1] = dia;
      });
    });

    const gerarDiasDoMes = (quantidade) => Array.from({ length: quantidade }, (_, i) => (i + 1).toString().padStart(2, '0'));
   
    Object.entries(diasPorMes).forEach(([quantidadeDias, linhasMes]) => {
      const totalDias = Number(quantidadeDias);
   
      linhasMes.forEach(linhaMes => {
        const linhaSemana = linhaMes - 1;
        const diaInicial = mapaInicioSemana[linhaMes];
   
        if (!diaInicial) {
          console.warn(`Não foi possível identificar o dia da semana para a linha ${linhaMes}`);
          return;
        }
   
        const indiceInicial = diasDaSemana.indexOf(diaInicial);
        const diasSemana = Array.from({ length: totalDias }, (_, i) =>
          diasDaSemana[(indiceInicial + i) % 7]
        );
   
        const diasMes = gerarDiasDoMes(totalDias);
   
        diasSemana.forEach((dia, indice) => {
          aba.getCell(linhaSemana, indice + 2).value = dia;
        });
   
        diasMes.forEach((dia, indice) => {
          aba.getCell(linhaMes, indice + 2).value = dia;
        });
      });
    });  
   
    // Estilo dos dias do mês
    [11, 26, 41, 56, 71, 86, 101, 116, 131, 146, 161, 176].forEach((linhaDia) => {
      aba.getRow(linhaDia).eachCell({ includeEmpty: true }, (celula) => {
        celula.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FFB7B7B7' }
        };
        celula.font = {
          bold: true,
          color: { argb: 'FFFFFFFF' }
        };
        celula.alignment = {
          horizontal: 'center',
          vertical: 'middle'
        };
      });
    });
   
    // Estilo dos dias da semana
    [10, 25, 40, 55, 70, 85, 100, 115, 130, 145, 160, 175].forEach((linha) => {
      aba.getRow(linha).eachCell({ includeEmpty: true }, (celula) => {
        celula.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FF5A7D9A' }
        };
        celula.font = {
          bold: true,
          color: { argb: 'FFFFFFFF' }
        };
        celula.alignment = {
          horizontal: 'center',
          vertical: 'middle'
        };
      });
    });

    // Mapeamento de meses para linhas na planilha
    const mesesLinhas = {
      0: 12,   // Janeiro
      1: 27,   // Fevereiro
      2: 42,   // Março
      3: 57,   // Abril
      4: 72,   // Maio
      5: 87,   // Junho
      6: 102,  // Julho
      7: 117,  // Agosto
      8: 132,  // Setembro
      9: 147,  // Outubro
      10: 162, // Novembro
      11: 177  // Dezembro
    };

    // Mapeamento de dias da semana para colunas
    const diasColunas = {
      "Dom": 1,
      "Seg": 2,
      "Ter": 3,
      "Qua": 4,
      "Qui": 5,
      "Sex": 6,
      "Sáb": 7
    };

    // Mapeamento de turnos para linhas de horário
    const turnoHorarios = {
      "Matutino": {
        linhas: [0, 1, 2, 3], // 07:30-08:30, 08:30-09:30, 09:30-10:30, 10:30-11:30
        horarios: ["07:30 - 08:30", "08:30 - 09:30", "09:30 - 10:30", "10:30 - 11:30"]
      },
      "Vespertino": {
        linhas: [5, 6, 7, 8], // 13:00-14:00, 14:00-15:00, 15:00-16:00, 16:00-17:00
        horarios: ["13:00 - 14:00", "14:00 - 15:00", "15:00 - 16:00", "16:00 - 17:00"]
      },
      "Noturno": {
        linhas: [10], // 18:40-21:40
        horarios: ["18:40 - 21:40"]
      }
    };
   
    // Agrupar aulas por matéria para a legenda
    const materias = {};
        aulas.forEach(aula => {
        if (!materias[aula.materia]) {
        materias[aula.materia] = {
          color: getColorForMateria(aula.materia),
          curso: aula.curso,
          turma: aula.turma
        };
      }
    });

   
    // Ajustar largura das colunas da legenda
    aba.getColumn('A').width = 15; // Coluna estreita para os quadrados de cor
    aba.getColumn('B').width = 30; // Coluna mais larga para as descrições


    // Processar cada aula
    // Modifique a parte de processamento das aulas para:
aulas.forEach(aula => {
  try {
    // Padroniza os nomes dos campos (convertendo para camelCase)
    const aulaPadronizada = {
      id: aula.id,
      materia: aula.materia,
      professor: aula.professor,
      turma: aula.turma,
      diasSemana: aula.diasSemana || aula.diassemana || aula.diaSemana, // Corrige para o nome do campo
      dataInicio: aula.dataInicio || aula.datainicio, // Corrige para o nome do campo
      turno: aula.turno,
      cargaHoraria: aula.cargaHoraria || aula.cargahoraria // Corrige para o nome do campo
    };

    // Validação robusta dos dados
    if (!aulaPadronizada.diasSemana || !aulaPadronizada.dataInicio || !aulaPadronizada.turno) {
      console.error('Aula com dados incompletos:', aulaPadronizada);
      return;
    }

    const dataInicio = new Date(aulaPadronizada.dataInicio);
    if (isNaN(dataInicio.getTime())) {
      console.error(`Data inválida: ${aulaPadronizada.dataInicio}`);
      return;
    }

    // Função auxiliar para converter dias completos para abreviações
    const diasAula = aulaPadronizada.diasSemana.split(',')
      .map(dia => {
        const diaLimpo = dia.trim();
        // Converte dias completos para abreviações
        if (diaLimpo === 'Segunda') return 'Seg';
        if (diaLimpo === 'Terça') return 'Ter';
        if (diaLimpo === 'Quarta') return 'Qua';
        if (diaLimpo === 'Quinta') return 'Qui';
        if (diaLimpo === 'Sexta') return 'Sex';
        if (diaLimpo === 'Sábado' || diaLimpo === 'Sabado') return 'Sáb';
        if (diaLimpo === 'Domingo') return 'Dom';
        return diaLimpo.substring(0, 3); // Pega os 3 primeiros caracteres
      });

    if (diasAula.length === 0) {
      console.error(`Dias da semana inválidos: ${aulaPadronizada.diasSemana}`);
      return;
    }

    console.log(`Processando aula ${aulaPadronizada.id} nos dias: ${diasAula.join(', ')}`);

    const materiaColor = getColorForMateria(aulaPadronizada.materia);
    let dataAtual = new Date(dataInicio);
    
    // Configuração de carga horária
    const cargaHoraria = parseInt(aulaPadronizada.cargaHoraria) || 60;
    const horasPorDia = aulaPadronizada.turno === "Noturno" ? 3 : 4;
    let totalHorasAgendadas = 0;
    let diasProcessados = 0;
    const maxDias = 180; // Limite de 6 meses para busca

    // Loop de agendamento
    while (totalHorasAgendadas < cargaHoraria && diasProcessados < maxDias) {
      diasProcessados++;
      const mes = dataAtual.getMonth();
      const diaMes = dataAtual.getDate();
      const diaSemana = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'][dataAtual.getDay()];

      // Verificar se é um dia de aula válido
      if (!diasAula.includes(diaSemana)) {
        dataAtual.setDate(dataAtual.getDate() + 1);
        continue;
      }

      // Encontrar a linha do mês
      const linhaMes = mesesLinhas[mes];
      if (!linhaMes) {
        dataAtual.setDate(dataAtual.getDate() + 1);
        continue;
      }

      // Encontrar coluna do dia
      let colunaDia = 0;
      for (let col = 2; col <= 32; col++) {
        const celulaDia = aba.getCell(linhaMes - 1, col);
        if (parseInt(celulaDia.value) === diaMes) {
          colunaDia = col;
          break;
        }
      }

      if (!colunaDia) {
        dataAtual.setDate(dataAtual.getDate() + 1);
        continue;
      }

      // Verificar turno e horários
      const turno = turnoHorarios[aulaPadronizada.turno];
      if (!turno) {
        dataAtual.setDate(dataAtual.getDate() + 1);
        continue;
      }

      // Preencher horários
      let horariosPreenchidos = 0;
      for (const offset of turno.linhas) {
        const linha = linhaMes + offset;
        const celula = aba.getCell(linha, colunaDia);

        // Verificar se célula já está ocupada
        if (celula.value) {
          console.log(`Célula ocupada: linha ${linha}, coluna ${colunaDia}`);
          continue;
        }

        // Preencher célula
        celula.value = {
          richText: [
            { text: `${aulaPadronizada.materia}\n`, font: { bold: true } },
            { text: `${aulaPadronizada.professor}\n` },
            { text: `${aulaPadronizada.turma}` }
          ]
        };

        celula.alignment = { 
          wrapText: true, 
          vertical: 'middle', 
          horizontal: 'center' 
        };

        celula.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: materiaColor }
        };

        celula.border = {
          top: { style: 'thin', color: { argb: 'FF000000' } },
          left: { style: 'thin', color: { argb: 'FF000000' } },
          bottom: { style: 'thin', color: { argb: 'FF000000' } },
          right: { style: 'thin', color: { argb: 'FF000000' } }
        };

        horariosPreenchidos++;
        totalHorasAgendadas += (aulaPadronizada.turno === "Noturno" ? 3 : 1);

        if (totalHorasAgendadas >= cargaHoraria) break;
      }

      dataAtual.setDate(dataAtual.getDate() + 1);
    }

    if (totalHorasAgendadas < cargaHoraria) {
      console.warn(`Carga horária incompleta para ${aulaPadronizada.materia}: ${totalHorasAgendadas}/${cargaHoraria}h`);
    }

  } catch (error) {
    console.error(`Erro ao processar aula ${aula?.id}:`, error);
  }
});

    // Ajustar largura das colunas
    function cmParaUnidadeExcel(cm) {
      const cmPorUnidade = 0.144;
      return cm / cmPorUnidade;
    }

    const largura = cmParaUnidadeExcel(2.3);
    aba.columns.forEach((coluna, index) => {
      coluna.width = largura;
    });

    // Enviar a planilha
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    // res.setHeader('Content-Disposition', 'attachment; filename=Aulas.xlsx');
    res.setHeader('Content-Disposition', `attachment; filename=Aulas_${docente.nome.replace(/\s+/g, '_')}.xlsx`);
    await planilha.xlsx.write(res);
    res.end();
  } catch (error) {
    console.error("Erro ao gerar planilha:", error);
    res.status(500).send("Erro ao gerar planilha");
  }
});

app.get('/exportar-excel-importado', async (req, res) => {
  try {
    if (!req.session || !req.session.user || !req.session.user.id) {
      return res.status(401).json({ error: "Usuário não autenticado" });
    }
   
    let docenteNome = req.query.docente_nome;

    if (!docenteNome) {
      return res.status(400).json({ error: "Nome do docente não fornecido" });
    }

    // Buscar dados do docente importado - ajustado para os campos reais da tabela
    const {rows: aulasImportadas} = await pool.query(
      `SELECT
        id,
        nome,
        docente,
        dias_semana,
        data_atividade,
        hora_inicio,
        hora_fim,
        turno,
        COALESCE(descricao_localizacao, localizacao) AS laboratorio,
        'Importado' AS curso,
        'Importado' AS turma
      FROM importado
      WHERE docente = $1
      ORDER BY data_atividade, hora_inicio`,
      [docenteNome]);
   
    if (aulasImportadas.length === 0) {
      return res.status(404).json({
        error: "Nenhuma aula importada encontrada",
        details: `Nenhuma aula encontrada para o docente "${docenteNome}" na base de dados importada`
      });
    }

    const planilha = new excelJS.Workbook();
    const aba = planilha.addWorksheet('Aulas');

    aba.getCell('B2').value = docenteNome;    // Nome do docente
    aba.getCell('B3').value = "";            // E-mail 
    aba.getCell('B4').value = "";            // Telefone 1 
    aba.getCell('B5').value = "";            // Telefone 2 

    // Configuração dos horários
    const horariosDia = [
      "07:30 - 08:30", "08:30 - 09:30", "09:30 - 10:30", "10:30 - 11:30", "",
      "13:00 - 14:00", "14:00 - 15:00", "15:00 - 16:00", "16:00 - 17:00", "",
      "18:40 - 21:40", ""
    ];
   
    const linhaHorario = [12, 27, 42, 57, 72, 87, 102, 117, 132, 147, 162, 177];

    // Preencher horários na coluna A
    linhaHorario.forEach((linhaBase) => {
      horariosDia.forEach((horario, indice) => {
        const linhaAtual = linhaBase + indice;
        const cell = aba.getCell(linhaAtual, 1);
        
        cell.value = horario;
        cell.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FFD9D9D9' }
        };
        cell.font = {  
          size: 18    
        };
        cell.alignment = { 
          horizontal: 'center', 
          vertical: 'middle'
        };
      });
    });

    // Configuração de mesclagem de células (igual ao original)
    aba.mergeCells('B1:F1');
    aba.mergeCells('B2:F2');
    aba.mergeCells('B3:F3');
    aba.mergeCells('B4:F4');
    aba.mergeCells('B5:F5');
    aba.mergeCells('A6:AF6');
    aba.mergeCells('H1:R1');
    aba.mergeCells('AF1:AF5');
    aba.mergeCells('G1:G5');

    // Mesclagem de células dos meses (igual ao original)
    aba.mergeCells('A9:AF9');
    aba.mergeCells('A8:AF8');
    aba.mergeCells('A24:AD24');
    aba.mergeCells('A39:AF39');
    aba.mergeCells('A54:AE54');
    aba.mergeCells('A69:AF69');
    aba.mergeCells('A84:AE84');
    aba.mergeCells('A99:AF99');
    aba.mergeCells('A114:AF114');
    aba.mergeCells('A129:AE129');
    aba.mergeCells('A144:AF144');
    aba.mergeCells('A159:AE159');
    aba.mergeCells('A174:AF174');

    // Cabeçalhos e títulos (igual ao original)
    aba.getCell('B1').value = "Dados do Docente";
    aba.getCell('A8').value = "Cronograma do período letivo";

    // Nomes dos meses (igual ao original)
    const meses = [
      {nome: "Janeiro", linha: 9},
      {nome: "Fevereiro", linha: 24},
      {nome: "Março", linha: 39},
      {nome: "Abril", linha: 54},
      {nome: "Maio", linha: 69},
      {nome: "Junho", linha: 84},
      {nome: "Julho", linha: 99},
      {nome: "Agosto", linha: 114},
      {nome: "Setembro", linha: 129},
      {nome: "Outubro", linha: 144},
      {nome: "Novembro", linha: 159},
      {nome: "Dezembro", linha: 174}
    ];

    meses.forEach(mes => {
      aba.getCell(`A${mes.linha}`).value = mes.nome;
    });

    // Centralização (igual ao original)
    aba.getCell('B1').alignment = { horizontal: 'center', vertical: 'middle' };
    aba.getCell('H1').alignment = { horizontal: 'center', vertical: 'middle' };

    const linhasParaCentralizar = [8, ...meses.map(m => m.linha)];
    linhasParaCentralizar.forEach(linha => {
      aba.getCell(`A${linha}`).alignment = {
        horizontal: 'center',
        vertical: 'middle'
      };
    });

    const centralizadorDeLinhasEColunas = [1, 2, 3, 4, 5, 6];
    centralizadorDeLinhasEColunas.forEach(linha => {
      for (let coluna = 0; coluna < 33; coluna++) {
          const cell = aba.getCell(linha, coluna + 1);
          cell.alignment = { 
            horizontal: 'center', 
            vertical: 'middle' 
          };
          cell.font = {
            size: 18,
            bold: true
          }
      }
    });


    // Cabeçalho dos meses (JAN, FEV, etc.) (igual ao original)
    const mesesAbreviados = ["JAN", "FEV", "MAR", "ABR", "MAI", "JUN", "JUL", "AGO", "SET", "OUT", "NOV", "DEZ"];
    mesesAbreviados.forEach((mes, indice) => {
      const celula = aba.getCell(1, indice + 20);
      celula.value = mes;
      celula.alignment = { horizontal: 'center' };
    });

    // Estilo do cabeçalho (igual ao original)
    aba.getRow(1).eachCell((celula) => {
      celula.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF1E3A5F' }
      };
      celula.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' }
      };
    });

    // Labels e legendas (igual ao original)
    aba.getCell('A2').value = "Docente:";
    aba.getCell('A3').value = "E-mail:";
    aba.getCell('A4').value = "Tel.1:";
    aba.getCell('A5').value = "Tel.2:";
    aba.getCell('S2').value = "Dias Úteis:";
    aba.getCell('S3').value = "Horas Úteis:";
    aba.getCell('S4').value = "Horas Alocadas:";
    aba.getCell('H1').value = "Legenda";

    const materiasUnicas = [...new Set(aulasImportadas.map(aula => aula.nome))];

    let colunaAtual = 8;

    materiasUnicas.forEach((materia, index) => {
      const corMateria = getColorForMateria(materia);
      const colunaLetra = String.fromCharCode(64 + colunaAtual);
     
      // Célula com nome da matéria
      aba.getCell(`${colunaLetra}2`).value = materia;
      aba.getCell(`${colunaLetra}2`).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: corMateria }
      };
      aba.getCell(`${colunaLetra}2`).font = {
        bold: true,
        color: { argb: 'FF000000' },
        size: 14
      };
      aba.getCell(`${colunaLetra}2`).alignment = {
        horizontal: 'center',
        vertical: 'middle',
        wrapText: true
      };
      aba.getCell(`${colunaLetra}2`).border = {
        top: { style: 'thin', color: { argb: 'FF000000' } },
        left: { style: 'thin', color: { argb: 'FF000000' } },
        bottom: { style: 'thin', color: { argb: 'FF000000' } },
        right: { style: 'thin', color: { argb: 'FF000000' } }
      };
     
      aba.getColumn(colunaAtual).width = 20;
      colunaAtual++;
     
      if (colunaAtual > 50) return;
    });
   
    // Estilo dos meses (igual ao original)
    meses.forEach(mes => {
      const celula = aba.getCell(`A${mes.linha}`);
      celula.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF33658A' }
      };
      celula.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' },
        size: 24
      };
    });

    // Estilo das células de cabeçalho (igual ao original)
    ["A8", "A1", "A2", "A3", "A4", "A5", "A6", "S1", "S2", "S3", "S4", 'S5', 'AF1', 'G1', 'S1'].forEach(endereco => {
      const celula = aba.getCell(endereco);
      celula.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF1E3A5F' }
      };
      celula.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' },
        size: 20
      };
    });

    // Configuração dos dias da semana e dias do mês (igual ao original)
    const semanaPorMes = {
      "Dom": [85],
      "Seg": [130, 175],
      "Ter": [55, 100],
      "Qua": [10, 145],
      "Qui": [70],
      "Sex": [115],
      "Sáb": [25, 40, 160],
    };
   
    const diasPorMes = {
      31: [11, 41, 71, 101, 116, 146, 176],
      30: [56, 86, 131, 161],
      29: [26]
    };
   
    const diasDaSemana = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sáb"];
   
    const mapaInicioSemana = {};
    Object.entries(semanaPorMes).forEach(([dia, linhas]) => {
      linhas.forEach(linhaSemana => {
        mapaInicioSemana[linhaSemana + 1] = dia;
      });
    });

    const gerarDiasDoMes = (quantidade) => Array.from({ length: quantidade }, (_, i) => (i + 1).toString().padStart(2, '0'));
   
    Object.entries(diasPorMes).forEach(([quantidadeDias, linhasMes]) => {
      const totalDias = Number(quantidadeDias);
   
      linhasMes.forEach(linhaMes => {
        const linhaSemana = linhaMes - 1;
        const diaInicial = mapaInicioSemana[linhaMes];
   
        if (!diaInicial) {
          console.warn(`Não foi possível identificar o dia da semana para a linha ${linhaMes}`);
          return;
        }
   
        const indiceInicial = diasDaSemana.indexOf(diaInicial);
        const diasSemana = Array.from({ length: totalDias }, (_, i) =>
          diasDaSemana[(indiceInicial + i) % 7]
        );
   
        const diasMes = gerarDiasDoMes(totalDias);
   
        diasSemana.forEach((dia, indice) => {
          aba.getCell(linhaSemana, indice + 2).value = dia;
        });
   
        diasMes.forEach((dia, indice) => {
          aba.getCell(linhaMes, indice + 2).value = dia;
        });
      });
    });  
   
    // Estilo dos dias do mês (igual ao original)
    [11, 26, 41, 56, 71, 86, 101, 116, 131, 146, 161, 176].forEach((linhaDia) => {
      aba.getRow(linhaDia).eachCell({ includeEmpty: true }, (celula) => {
        celula.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FFB7B7B7' }
        };
        celula.font = {
          bold: true,
          color: { argb: 'FFFFFFFF' },
          size: 20
        };
        celula.alignment = {
          horizontal: 'center',
          vertical: 'middle'
        };
      });
    });
   
    // Estilo dos dias da semana (igual ao original)
    [10, 25, 40, 55, 70, 85, 100, 115, 130, 145, 160, 175].forEach((linha) => {
      aba.getRow(linha).eachCell({ includeEmpty: true }, (celula) => {
        celula.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FF5A7D9A' }
        };
        celula.font = {
          bold: true,
          color: { argb: 'FFFFFFFF' },
          size: 22
        };
        celula.alignment = {
          horizontal: 'center',
          vertical: 'middle'
        };
      });
    });

    const celulasParaFormatar = ['B1', 'H1', 'T1', 'U1', 'V1', 'W1', 'X1', 'Y1', 'Z1', 'AA1', 'AB1', 'AC1', 'AD1', 'AE1'];
    celulasParaFormatar.forEach(celula => {
      aba.getCell(celula).font = {
        size: 20,
        blod: true
      };
    });

    celulaCronograma = ['A8'];
    celulaCronograma.forEach(celula =>{
      aba.getCell(celula).font = {
        size: 24,
        bold: true
      }
    })

    // Mapeamento de meses para linhas na planilha (igual ao original)
    const mesesLinhas = {
      0: 12,   // Janeiro
      1: 27,   // Fevereiro
      2: 42,   // Março
      3: 57,   // Abril
      4: 72,   // Maio
      5: 87,   // Junho
      6: 102,  // Julho
      7: 117,  // Agosto
      8: 132,  // Setembro
      9: 147,  // Outubro
      10: 162, // Novembro
      11: 177  // Dezembro
    };

    // Mapeamento de turnos para linhas de horário (ajustado para os valores da tabela)
    const turnoHorarios = {
      "MANHÃ": {
        linhas: [0, 1, 2, 3], // 07:30-08:30, 08:30-09:30, 09:30-10:30, 10:30-11:30
        horarios: ["07:30 - 08:30", "08:30 - 09:30", "09:30 - 10:30", "10:30 - 11:30"]
      },
      "TARDE": {
        linhas: [5, 6, 7, 8], // 13:00-14:00, 14:00-15:00, 15:00-16:00, 16:00-17:00
        horarios: ["13:00 - 14:00", "14:00 - 15:00", "15:00 - 16:00", "16:00 - 17:00"]
      },
      "NOITE": {
        linhas: [10], // 18:40-21:40
        horarios: ["18:40 - 21:40"]
      }
    };
   
    function formatarDuracao(horaInicio, horaFim) {
      return `${horaInicio.substring(0, 5)} - ${horaFim.substring(0, 5)}`;
    }
    // Processar cada aula importada (ajustado para os dados da tabela)
    aulasImportadas.forEach(aula => {
      try {
        // Padroniza os nomes dos campos usando os dados diretamente do banco
        const aulaPadronizada = {
          id: aula.id,
          materia: aula.nome,  // Usando o campo 'nome' da tabela
          professor: aula.docente,
          diasSemana: aula.dias_semana,
          data_atividade: aula.data_atividade,
          hora_inicio: aula.hora_inicio,
          hora_fim: aula.hora_fim,
          turno: aula.turno,
          laboratorio: aula.laboratorio || "Importado",
          curso: aula.curso,
          turma: aula.turma
        };
   
        // Validação dos dados obrigatórios
        if (!aulaPadronizada.diasSemana || !aulaPadronizada.data_atividade ||
            !aulaPadronizada.turno || !aulaPadronizada.hora_inicio || !aulaPadronizada.hora_fim) {
          console.error('Aula importada com dados incompletos:', aulaPadronizada);
          return;
        }
   
        const dataAula = new Date(aulaPadronizada.data_atividade);
        if (isNaN(dataAula.getTime())) {
          console.error(`Data inválida: ${aulaPadronizada.data_atividade}`);
          return;
        }
   
        // Converter dias da semana para abreviações padrão
        const diasAula = aulaPadronizada.diasSemana.split(',')
          .map(dia => {
            const diaLimpo = dia.trim().toLowerCase();
            switch(diaLimpo) {
              case 'segunda-feira': return 'Seg';
              case 'terça-feira': case 'terca': return 'Ter';
              case 'quarta-feira': return 'Qua';
              case 'quinta-feira': return 'Qui';
              case 'sexta-feira': return 'Sex';
              case 'sábado': case 'sabado': return 'Sáb';
              case 'domingo': return 'Dom';
              default: return diaLimpo.substring(0, 3);
            }
          })
          .filter(dia => ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom'].includes(dia));
   
        if (diasAula.length === 0) {
          console.error(`Dias da semana inválidos: ${aulaPadronizada.diasSemana}`);
          return;
        }
   
        const materiaColor = getColorForMateria(aulaPadronizada.materia);
        const mes = dataAula.getMonth();
        const diaMes = dataAula.getDate();
        const diaSemana = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'][dataAula.getDay()];
   
        // Verificar se o dia da semana está nos dias da aula
        if (!diasAula.includes(diaSemana)) {
          return;
        }
   
        const linhaMes = mesesLinhas[mes];
        if (!linhaMes) {
          return;
        }
   
        // Encontrar coluna do dia no Excel
        let colunaDia = 0;
        for (let col = 2; col <= 32; col++) {
          const celulaDia = aba.getCell(linhaMes - 1, col);
          if (parseInt(celulaDia.value) === diaMes) {
            colunaDia = col;
            break;
          }
        }
   
        if (!colunaDia) {
          return;
        }
   
        // Determinar linha do horário baseado no turno e hora
        const turnoInfo = turnoHorarios[aulaPadronizada.turno];
        if (!turnoInfo) {
          console.error(`Turno inválido: ${aulaPadronizada.turno}`);
          return;
        }
   
        // Processar horário de início e fim
        const horaInicio = aulaPadronizada.hora_inicio.substring(0, 5); // Formato HH:MM
        const horaFim = aulaPadronizada.hora_fim.substring(0, 5);
       
        // Calcular duração em horas
        const inicio = parseInt(horaInicio.split(':')[0]) + parseInt(horaInicio.split(':')[1])/60;
        const fim = parseInt(horaFim.split(':')[0]) + parseInt(horaFim.split(':')[1])/60;
        const duracaoHoras = fim - inicio;
   
        // Encontrar o slot de horário mais adequado
        let melhorSlot = 0;
        let menorDiferenca = Infinity;
       
        for (let i = 0; i < turnoInfo.horarios.length; i++) {
          const horaSlot = turnoInfo.horarios[i];
          const horaSlotNum = parseInt(horaSlot.split(':')[0]) + parseInt(horaSlot.split(':')[1])/60;
          const diferenca = Math.abs(horaSlotNum - inicio);
         
          if (diferenca < menorDiferenca) {
            menorDiferenca = diferenca;
            melhorSlot = i;
          }
        }
   
        // Calcular quantos slots serão necessários
        const slotsNecessarios = Math.ceil(duracaoHoras); // Arredonda para cima
       
        // Preencher os slots necessários
        for (let i = 0; i < slotsNecessarios && (melhorSlot + i) < turnoInfo.linhas.length; i++) {
          const linha = linhaMes + turnoInfo.linhas[melhorSlot + i];
          const celula = aba.getCell(linha, colunaDia);
   
          if (celula.value) {
            console.log(`Célula ocupada: linha ${linha}, coluna ${colunaDia}`);
            continue;
          }
   
          // Preencher célula com informações da aula
          celula.value = {
            richText: [
              { text: `${aulaPadronizada.materia}\n`, font: { bold: true } },
              { text: `${aulaPadronizada.laboratorio}` }
            ]
          };
   
          celula.alignment = {
            wrapText: true,
            vertical: 'middle',
            horizontal: 'center'
          };
   
          celula.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: materiaColor }
          };
   
          celula.border = {
            top: { style: 'thin', color: { argb: 'FF000000' } },
            left: { style: 'thin', color: { argb: 'FF000000' } },
            bottom: { style: 'thin', color: { argb: 'FF000000' } },
            right: { style: 'thin', color: { argb: 'FF000000' } }
          };

          celula.font = {
            size: 11,
            bold: true
          }
        }
   
      } catch (error) {
        console.error(`Erro ao processar aula importada ${aula?.id}:`, error);
      }
    });

    aba.views = [
      {
        zoomScale: 36
      }
    ];
    
    // Ajustar largura das colunas (igual ao original)
    function cmParaUnidadeExcel(cm) {
      const cmPorUnidade = 0.144;
      return cm / cmPorUnidade;
    }

    const largura = cmParaUnidadeExcel(5);
    aba.columns.forEach((coluna, index) => {
      coluna.width = largura;
    });

    function cmParaAlturaExcel(cm) {
      return cm * 28.3465; 
    }
  
    const altura = cmParaAlturaExcel(2);
    aba.eachRow(row => {
      row.height = altura;
    });


   
    // Enviar a planilha
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=Aulas_Importadas_${docenteNome.replace(/\s+/g, '_')}.xlsx`);
    await planilha.xlsx.write(res);
    res.end();
  } catch (error) {
    console.error("Erro ao gerar planilha de dados importados:", error);
    res.status(500).json({
      error: "Erro ao gerar planilha",
      details: error.message
    });
  }
});

// Rota para a API de notificações (JSON)
app.get('/api/notificacoes', verificarAutenticacao, async (req, res) => {
  try {
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);
    const hojeFormatado = hoje.toISOString().split('T')[0];
    
    const { rows } = await pool.query(`
      SELECT 
        id,
        nome AS materia,
        turno,
        data_atividade AS data,
        hora_inicio,
        hora_fim,
        localizacao,
        docente AS professor,
        dias_semana
      FROM importado 
      WHERE data_atividade >= $1
      ORDER BY data_atividade ASC, hora_inicio ASC
      LIMIT 20`,
      [hojeFormatado]);

    const notificacoes = rows.map(aula => ({
      ...aula,
      hora_inicio: aula.hora_inicio?.substring(0, 5) || '--:--',
      hora_fim: aula.hora_fim?.substring(0, 5) || '--:--',
      data: new Date(aula.data).toLocaleDateString('pt-BR'),
      dias_semana: aula.dias_semana || ''
    }));

    res.json(notificacoes);
  } catch (error) {
    console.error('Erro na API de notificações:', error);
    res.status(500).json({ 
      error: 'Erro ao buscar notificações',
      details: error.message 
    });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
      if (err) {
          console.error('Erro ao destruir sessão:', err);
          return res.status(500).json({ success: false });
      }
      res.clearCookie('connect.sid');
      res.json({ success: true }); // Envia resposta JSON em vez de redirecionar
  });
});

// Inicializar servidor
app.listen(5505, () => {
  console.log('Servidor rodando na porta 5505');
});
