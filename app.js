const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const excelJS = require('exceljs');
const nodemailer = require('nodemailer');
const mysql = require('mysql2/promise'); // Usando mysql2
const app = express();
require("dotenv").config();




// Configuração do pool de conexões MySQL
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




app.use(express.json());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));
app.use('/img', express.static(path.join(__dirname, 'img')));




// Configuração da sessão
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


app.get('/notificacoes', verificarAutenticacao, (req,res) =>{
  res.send|File(path.join(__dirname, 'public', 'notificacoes.html'));
})


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
          "UPDATE usuarios SET telefone2 = ? WHERE id = ?",
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
    const [rows] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);


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


// Rota de cadastro
app.post('/cadastro', async (req, res) => {
  const { nome, email, senha, telefone1, tipo } = req.body;


  if (!['docente', 'adm'].includes(tipo)) {
    return res.status(400).json({ message: "Tipo inválido! Use 'docente' ou 'adm'." });
  }


  try {
    const [checkUser] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (checkUser.length > 0) {
      return res.status(409).send('Usuário já existe');
    }


    const senhaCriptografada = await bcrypt.hash(senha, 10);
    const [result] = await pool.query(
      'INSERT INTO usuarios (nome, email, senha, telefone1, tipo) VALUES (?, ?, ?, ?, ?)',
      [nome, email, senhaCriptografada, telefone1, tipo]
    );


    req.session.user = { id: result.insertId, nome, email, telefone1, tipo };
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


    await pool.query('UPDATE usuarios SET profilePic = ? WHERE id = ?', [imagePath, userId]);
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
    const [rows] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.json({ success: false, message: 'Usuário não encontrado.' });
    }


    const senhaCriptografada = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE usuarios SET senha = ? WHERE email = ?', [senhaCriptografada, email]);


    res.json({ success: true, message: 'Senha atualizada com sucesso!' });


  } catch (err) {
    console.error('Erro ao atualizar senha:', err);
    res.status(500).send('Erro no servidor.');
  }
});


app.post('/redefinirSenhaDireta', async (req, res) => {
  const { email, novaSenha } = req.body;


  try {
      const [rows] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);
      if (rows.length === 0) {
          return res.json({ success: false, message: 'E-mail não encontrado.' });
      }


      const senhaCriptografada = await bcrypt.hash(novaSenha, 10);
      await pool.query('UPDATE usuarios SET senha = ? WHERE email = ?', [senhaCriptografada, email]);


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
    await pool.query('UPDATE usuarios SET nome = ?, email = ?, senha = ? WHERE id = ?',
      [nome, email, senhaCriptografada, userId]);


    res.json({ message: 'Perfil atualizado com sucesso!' });


  } catch (err) {
    console.error('Erro ao atualizar perfil:', err);
    res.status(500).send('Erro no servidor.');
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
    const [rows] = await pool.query('SELECT id, nome, email, telefone1, telefone2, profilePic, tipo FROM usuarios WHERE id = ?', [userId]);
   
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


      await pool.query("INSERT INTO curso (nome) VALUES (?)", [nome]);
      res.json({ message: "Curso cadastrado com sucesso!" });


  } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: "Já existe um curso com esse nome." });
      }
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar o curso." });
  }
});


app.get('/curso', async (req, res) => {
  try {
      const [rows] = await pool.query("SELECT * FROM curso");
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


      await pool.query("INSERT INTO turma (nome, curso_id) VALUES (?, ?)", [nome, curso_id]);
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
    const [rows] = await pool.query(`
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


      await pool.query("INSERT INTO laboratorio (cimatec, andar, sala) VALUES (?, ?, ?)", [cimatec, andar, sala]);
      res.json({ message: "Laboratório cadastrado com sucesso!" });
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar o laboratório." });
  }
});


app.get('/laboratorio', async (req, res) => {
      const [rows] = await pool.query("SELECT * FROM laboratorio");
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


      const [materiaExistente] = await pool.query("SELECT * FROM materia WHERE uc = ? AND curso_id = ?", [uc, curso_id]);
      if (materiaExistente.length > 0) {
          return res.status(400).json({ error: "Esta matéria já está cadastrada para este curso!" });
      }


      await pool.query("INSERT INTO materia (uc, ch, curso_id) VALUES (?, ?, ?)", [uc, ch, curso_id]);
      res.json({ message: "Matéria cadastrada com sucesso!" });
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar a matéria." });
  }
});


app.get('/materia', async (req, res) => {
  try {
      const [rows] = await pool.query(`
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




// Rota para solicitar redefinição de senha (app.js)
app.post('/solicitar-redefinicao', async (req, res) => {
  const { email } = req.body;
 
  try {
    console.log('Solicitação de redefinição recebida para:', email);
   
    const [user] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (!user.length) {
      console.log('E-mail não encontrado:', email);
      return res.status(200).json({ message: 'Se existir uma conta com este email, um link foi enviado.' });
    }


    // Geração do token e link
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hora
    const resetLink = `http://localhost:5505/redefinir-senha.html?token=${token}`;    
    await pool.query(
      'INSERT INTO reset_tokens (user_id, token, expires) VALUES (?, ?, ?)',
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
    const [tokenData] = await pool.query(
      `SELECT * FROM reset_tokens
      WHERE token = ?
      AND used = FALSE
      AND expires > UTC_TIMESTAMP()`, // Usar UTC para evitar problemas de fuso
      [token]
    );


    if (!tokenData || tokenData.length === 0) {
      return res.status(400).json({ message: 'Link inválido ou expirado' });
    }
 


      const senhaCriptografada = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE usuarios SET senha = ? WHERE id = ?',
          [senhaCriptografada, tokenData[0].user_id]);


      await pool.query('UPDATE reset_tokens SET used = TRUE WHERE token = ?', [token]);
     
      res.json({ message: 'Senha redefinida com sucesso! Você pode fazer login agora.' });
  }catch (err) {
    console.error('Erro detalhado:', err.message); // Log detalhado
    res.status(500).send('Erro no servidor');
  }
 
});


// Rota para cadastrar aula
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
      WHERE laboratorio_id = ?
      AND dataInicio = ?
      AND turno = ?;
    `;
    const [rowsLaboratorio] = await pool.query(queryLaboratorio, [laboratorio_id, dataInicio, turno]);


    if (rowsLaboratorio.length > 0) {
      return res.status(400).json({ error: "Este laboratório já está ocupado neste horário!" });
    }


    // Verificar se a turma já tem aula no mesmo turno
    const queryTurma = `
      SELECT *
      FROM aula
      WHERE turma_id = ?
      AND turno = ?;
    `;
    const [rowsTurma] = await pool.query(queryTurma, [turma_id, turno]);


    if (rowsTurma.length > 0) {
      return res.status(400).json({ error: "Esta turma já possui uma aula no turno selecionado!" });
    }


    // Se não houver conflitos, cadastrar a aula
    await pool.query(
      "INSERT INTO aula (usuario_id, curso_id, materia_id, turma_id, laboratorio_id, turno, diasSemana, dataInicio) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [usuario_id, curso_id, materia_id, turma_id, laboratorio_id, turno, diasSemana.join(','), dataInicio]
    );


    res.json({ message: "Aula cadastrada com sucesso!" });


  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao cadastrar a aula." });
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
    if (userType === 'docente') {
      query += " WHERE a.usuario_id = ?";
      values.push(usuario_id);
    }


    const [rows] = await pool.query(query, values);
    res.json(rows);


  } catch (error) {
    console.error("Erro ao buscar aulas:", error);
    res.status(500).json({ error: "Erro ao buscar aulas." });
  }
});


// Rota para retornar aulas do dia
app.get('/aulasHoje', async (req, res) => {
  if (!req.session || !req.session.user || !req.session.user.id) {
      return res.status(401).json({ error: "Usuário não autenticado" });
  }
  const userId = req.session.user.id;
  const hoje = new Date().toISOString().split('T')[0];


  try {
      const query = `
          SELECT
              a.id,
              m.uc AS materia,
              t.nome AS turma,
              a.turno,
              a.dataInicio
          FROM aula a
          LEFT JOIN materia m ON a.materia_id = m.id
          LEFT JOIN turma t ON a.turma_id = t.id
          WHERE a.usuario_id = ? AND DATE(a.dataInicio) = ?  
      `;


      const [rows] = await pool.query(query, [userId, hoje]);
      res.json(rows);
  } catch (error) {
      console.error("Erro ao buscar aulas de hoje:", error);
      res.status(500).json({ error: "Erro ao buscar aulas de hoje." });
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

//Rota da planilha(montagem)
app.get('/exportar-excel', async (req, res) => {
  try {
    if (!req.session || !req.session.user || !req.session.user.id) {
      return res.status(401).json({ error: "Usuário não autenticado" });
     }
      
    const isAdmin = req.session.user.tipo === 'adm';
    const docenteId = isAdmin && req.query.docente_id
       ? req.query.docente_id
       : req.session.user.id;
      
   // Validação para admin
    if (isAdmin && req.query.docente_id) {
       const [docenteCheck] = await pool.query(
      'SELECT id, tipo FROM usuarios WHERE id = ? AND tipo = "docente"',
      [docenteId]
      );
      if (docenteCheck.length === 0) {
        return res.status(400).json({ error: "Docente não encontrado" });
      }
    }
      
   // Buscar dados do docente
    const [userData] = await pool.query(
       'SELECT nome, email, telefone1, telefone2 FROM usuarios WHERE id = ?',
       [docenteId]
    );
      
       if (userData.length === 0) {
       return res.status(404).json({ error: "Usuário não encontrado" });
       }
      
      const docente = userData[0];
      
      
      const [aulas] = await pool.query(`
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
       WHERE a.usuario_id = ?
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
  aulas.forEach(aula => {


    const materiaColor = getColorForMateria(aula.materia);
    const dataInicio = new Date(aula.dataInicio);
    let dataAtual = new Date(dataInicio);
   
    // Obter os dias da semana selecionados
    const diasAula = aula.diasSemana.split(',').map(dia => dia.trim().substring(0, 3));
   
    // Validar carga horária
    const cargaHoraria = aula.cargaHoraria; // Default 60h se não definido
    const horasPorDia = aula.turno === "Noturno" ? 3 : 4; // 3h para noturno, 4h para outros
   
    // Calcular total de dias necessários com arredondamento para cima
    const totalDiasAula = Math.ceil(cargaHoraria / horasPorDia);
    let diasAgendados = 0;
    let totalHorasAgendadas = 0;
    const maxDias = 365 * 2; // Limite de segurança (2 anos)
    let diasProcessados = 0;


    // Enquanto não completar a carga horária
    while (totalHorasAgendadas < cargaHoraria && diasProcessados < maxDias) {
        diasProcessados++;
        const mes = dataAtual.getMonth();
        const diaMes = dataAtual.getDate();
        const diaSemanaNum = dataAtual.getDay();
        const diasSemanaMap = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sáb"];
        const diaSemana = diasSemanaMap[diaSemanaNum];
       
        // Verificar se é um dia de aula válido
        if (!diasAula.includes(diaSemana)) {
            dataAtual.setDate(dataAtual.getDate() + 1);
            continue;
        }
       
        // Verificar se o mês existe no mapeamento
        if (mesesLinhas[mes] === undefined) {
            dataAtual = new Date(dataAtual.getFullYear() + 1, 0, 1);
            continue;
        }
       
        const linhaMes = mesesLinhas[mes];
        const linhaDias = linhaMes - 1;
        let colunaDia = 0;
       
        // Encontrar a coluna do dia atual
        for (let col = 2; col <= 32; col++) {
            const celulaDia = aba.getCell(linhaDias, col);
            if (parseInt(celulaDia.value) === diaMes) {
                colunaDia = col;
                break;
            }
        }
       
        if (colunaDia === 0) {
            dataAtual.setDate(dataAtual.getDate() + 1);
            continue;
        }
       
        // Verificar dia da semana na planilha
        const linhaSemana = linhaMes - 2;
        const celulaDiaSemana = aba.getCell(linhaSemana, colunaDia);
        if (celulaDiaSemana.value !== diaSemana) {
            dataAtual.setDate(dataAtual.getDate() + 1);
            continue;
        }
       
        // Obter horários do turno
        const horariosTurno = turnoHorarios[aula.turno];
        if (!horariosTurno) {
            dataAtual.setDate(dataAtual.getDate() + 1);
            continue;
        }
       
        // Agendar horários
        let horariosAgendados = 0;
        for (let i = 0; i < horariosTurno.linhas.length && horariosAgendados < horasPorDia; i++) {
            const offset = horariosTurno.linhas[i];
            const linha = linhaMes + offset;
            const celula = aba.getCell(linha, colunaDia);
           
            if (celula.value) continue;
           
            // Preencher informações completas
            celula.value = {
                richText: [
                    {text: `${aula.materia}\n`, font: {bold: true}},
                    {text: `${aula.professor}\n`},
                    {text: `${aula.turma}`}
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
           
            horariosAgendados++;
            totalHorasAgendadas += (aula.turno === "Noturno" ? 3 : 1);
        }
       
        if (horariosAgendados > 0) {
            diasAgendados++;
        }
       
        dataAtual.setDate(dataAtual.getDate() + 1);
    }
   
    // Verificar se completou a carga horária
    if (totalHorasAgendadas < cargaHoraria) {
        console.warn(`Atenção: Aula ${aula.materia} não completou carga horária. Agendadas ${totalHorasAgendadas}h de ${cargaHoraria}h`);
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



//Rota de notificações
app.get('/notificao', (req, res) => {
  const hoje = new Date().toISOString().split('T')[0]; // Data de hoje no formato YYYY-MM-DD
  const query = `SELECT * FROM aula WHERE dataInicio >= ? ORDER BY dataInicio ASC`;


  pool.query(query, [hoje], (err, results) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      res.json(results);
  });
});


// Rota de logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
      if (err) return res.status(500).send('Erro ao encerrar sessão.');
      res.clearCookie('connect.sid'); // Limpa o cookie de sessão
      res.redirect('/'); // Redireciona para a página inicial
  });
});


// Inicializar servidor
app.listen(5505, () => {
  console.log('Servidor rodando na porta 5505');
});