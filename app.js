require("dotenv").config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto'); 
const excelJS = require('exceljs');
const nodemailer = require('nodemailer');
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const mysql = require('mysql2/promise'); // Usando mysql2
const app = express();


// Configuração do pool de conexões MySQL
const pool = mysql.createPool({
  host: 'metro.proxy.rlwy.net',
  user: 'root', // Substitua pelo usuário do MySQL
  database: 'railway',
  password: 'rgqWvFdLQYylJOeBffxARDNTEZvrlIPu', // Substitua pela senha do MySQL
  port: 22537 , // Porta padrão do MySQL
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
    pass: 'zbyi lwxw hkrv mduu'
  },
  tls: {
    rejectUnauthorized: false // Adicione esta linha para ambiente local
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID:  process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:5505/auth/google/callback",
      scope: ["profile", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const nome = profile.displayName;
  
        // Verifica se o usuário já existe no banco de dados
        const [rows] = await pool.query("SELECT * FROM usuarios WHERE email = ?", [email]);
  
        let usuario;
        if (rows.length === 0) {
          // Gerando uma senha aleatória para evitar erro de "NULL"
          const randomPassword = crypto.randomBytes(16).toString('hex');

          // Insere novo usuário com senha aleatória
          const [result] = await pool.query(
            "INSERT INTO usuarios (nome, email, senha, telefone1, tipo) VALUES (?, ?, ?, ?, ?)",
            [nome, email, randomPassword, null, 'pendente']
          );
          usuario = { id: result.insertId, nome, email, tipo: 'pendente' };
        } else {
          usuario = rows[0];
        }
  
        return done(null, usuario);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await pool.query("SELECT * FROM usuarios WHERE id = ?", [id]);
    done(null, rows[0]);
  } catch (error) {
    done(error, null);
  }
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

//Inicializando o login e autenticação com o Google
app.use(passport.initialize());
app.use(passport.session());

// Rota inicial
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/home.html'));
});

app.get('/auth/google', passport.authenticate('google', 
  { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  async (req, res) => {
    if (!req.user) {
      return res.redirect('/');
    }
    req.session.user = req.user; // Armazena os dados do usuário na sessão
    res.redirect('/perfil.html'); // Redireciona para a página principal
  }
);

//Rota para 
app.get('/acessandoUsuario', (req, res) => {
  if (!req.session.user) {
    return res.json({ authenticated: false });
  }
  res.json({ authenticated: true, user: req.session.user });
});

//Rota para usuario com Google escolher o tipo de usuário
app.post('/definirTipo', async (req, res) => {
  const { tipo } = req.body;
  if (!req.session.user) return res.status(401).json({ error: "Usuário não autenticado" });

  try {
    await pool.query("UPDATE usuarios SET tipo = ? WHERE id = ?", [tipo, req.session.user.id]);
    req.session.user.tipo = tipo; // Atualiza a sessão
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Erro ao definir o tipo" });
  }
});

//Rota para defini rambos telefones(serve com ou sem Google)
app.post('/definirTelefones', async (req, res) => {
  const { telefone1, telefone2 } = req.body;
  
  if (!req.session.user) {
    return res.status(401).json({ error: "Usuário não autenticado" });
  }

  try {
    await pool.query(
      "UPDATE usuarios SET telefone1 = ?, telefone2 = ? WHERE id = ?", 
      [telefone1, telefone2 || null, req.session.user.id]
    );

    req.session.user.telefone1 = telefone1;
    req.session.user.telefone2 = telefone2 || null;

    req.session.save(err => {
      if (err) {
        console.error("Erro ao salvar sessão:", err);
        return res.status(500).json({ error: "Erro ao salvar sessão" });
      }
      res.json({ success: true });
    });

  } catch (error) {
    console.error("Erro ao definir os telefones:", error);
    res.status(500).json({ error: "Erro ao definir os telefones" });
  }
});

//Rota para segundo telefone
app.post('/atualizarTelefone2', async (req, res) => {
  const { telefone2 } = req.body;

  if (!req.session.user) {
      return res.status(401).json({ error: "Usuário não autenticado" });
  }

  try {
      await pool.query(
          "UPDATE usuarios SET telefone2 = ? WHERE id = ?",
          [telefone2 || null, req.session.user.id]
      );

      req.session.user.telefone2 = telefone2 || null;

      req.session.save(err => {
          if (err) {
              console.error("Erro ao salvar sessão:", err);
              return res.status(500).json({ error: "Erro ao salvar sessão" });
          }
          res.json({ success: true });
      });

  } catch (error) {
      console.error("Erro ao atualizar Telefone2:", error);
      res.status(500).json({ error: "Erro ao atualizar Telefone2" });
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
      email: usuario.email
    };

    console.log('Usuário logado:', req.session.user);
    res.redirect('perfil');

  } catch (err) {
    console.error('Erro ao fazer login:', err);
    res.status(500).send('Erro no servidor.');
  }
});

// Rota de cadastro
app.post('/cadastro', async (req, res) => {
  const { nome, email, senha, telefone1, tipo } = req.body;

  if (!['docente', 'adm', 'aula'].includes(tipo)) {
    return res.status(400).json({ message: "Tipo inválido! Use 'docente', 'adm' ou 'aula'." });
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

    req.session.user = { id: result.insertId, email, telefone1, tipo };
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
      [user[0].id, token, expires]
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
    console.log('E-mail enviado:', info.messageId);
    
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
      AND expires > NOW()`, // Usar UTC para evitar problemas de fuso
      [token]
    );

      if (!tokenData.length) {
          return res.status(400).json({ message: 'Link inválido ou expirado' });
      }

      const senhaCriptografada = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE usuarios SET senha = ? WHERE id = ?', 
          [senhaCriptografada, tokenData[0].user_id]);

      await pool.query('UPDATE reset_tokens SET used = TRUE WHERE token = ?', [token]);
      
      res.json({ message: 'Senha redefinida com sucesso! Você pode fazer login agora.' });
  } catch (err) {
      console.error('Erro:', err);
      res.status(500).send('Erro no servidor');
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

app.get('/home', (req, res) => {
  res.sendFile(__dirname + '/public/home.html'); 
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
    const [rows] = await pool.query('SELECT nome, email, telefone1, telefone2, profilePic, tipo FROM usuarios WHERE id = ?', [userId]);
    res.json(rows[0]);
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
    const [rows] = await pool.query("SELECT * FROM curso");
    res.json(rows);
});

//Rota para cadastrar turma
app.post('/turma', async (req, res) => {
  try {
      const { nome, curso_id } = req.body;

      if (!nome || !curso_id) {
          return res.status(400).json({ error: "Nome da turma e curso_id são obrigatórios." });
      }

      const [curso] = await pool.query("SELECT id FROM curso WHERE id = ?", [curso_id]);
      if (curso.length === 0) {
          return res.status(400).json({ error: "O curso especificado não existe." });
      }

      await pool.query("INSERT INTO turma (nome, curso_id) VALUES (?, ?)", [nome, curso_id]);
      res.json({ message: "Turma cadastrada com sucesso!" });

  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar a turma." });
  }
});

app.get('/turma', async (req, res) => {
      const [rows] = await pool.query(`
          SELECT turma.id, turma.nome AS turma, curso.nome AS curso 
          FROM turma 
          JOIN curso ON turma.curso_id = curso.id
      `);
      res.json(rows);
});

//Rota para cadastrar laboratorio
app.post('/laboratorio', async (req, res) => {
  try {
      const { cimatec, andar, sala } = req.body;

      if (!cimatec || !andar || !sala) {
          return res.status(400).json({ error: "Os campos cimatec, andar e sala são obrigatórios." });
      }

      // Impede duplicação de laboratório no mesmo local
      const [existingLab] = await pool.query(
          "SELECT id FROM laboratorio WHERE cimatec = ? AND andar = ? AND sala = ?", 
          [cimatec, andar, sala]
      );

      if (existingLab.length > 0) {
          return res.status(400).json({ error: "Já existe um laboratório cadastrado nesse local." });
      }

      await pool.query("INSERT INTO laboratorio (cimatec, andar, sala) VALUES (?, ?, ?)", 
                       [cimatec, andar, sala]);
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
app.post('/materias', async (req, res) => {
  const { uc, ch, curso_id } = req.body;
  await pool.query("INSERT INTO materia (uc, ch, curso_id) VALUES (?, ?, ?)", [uc, ch, curso_id]);
  res.json({ message: "Matéria cadastrada com sucesso!" });
});


// Rota para buscar matérias
app.get('/materias', async (req, res) => {
    const [rows] = await pool.query("SELECT * FROM materia");
    res.json(rows);
});


// Rota para cadastrar aulas
app.post('/aulas', async (req, res) => {
  const { materia_id, turma, laboratorio, turno, diasSemana, horarios } = req.body;
 
  // Verifique se horarios não está undefined
  console.log(horarios); // Isso deve ser um array de horários ou uma string
 
  if (!horarios || horarios.length === 0) {
      return res.status(400).json({ error: "Horários não selecionados" });
  }

  await pool.query("INSERT INTO aula (materia_id, turma, laboratorio, turno, diasSemana, horarios) VALUES (?, ?, ?, ?, ?, ?)",
      [materia_id, turma, laboratorio, turno, diasSemana.join(', '), horarios.join(', ')]);
  res.json({ message: "Aula cadastrada!" });
});

app.get('/aulas', async(req, res) => {
    const [rows] = await pool.query("SELECT * FROM aula");
    res.json(rows);
})

//Rota da planilha(montagem)
app.get('/exportar-excel', async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM aula");


  const workbook = new excelJS.Workbook();
  const worksheet = workbook.addWorksheet('Aulas');


  const horariosDia = [
    "Horários","07:00", "08:00", "09:00", "10:00", "11:00", "12:00", "13:00", "14:00",
    "15:00", "16:00", "17:00", "18:00", "19:00", "20:00", "21:00", "22:00",
  ];
  // Adicionando os horários para cada mês (JAN à DEZ)
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(11 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(31 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(51 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(71 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(91 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(111 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(131 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(151 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(171 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(191 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(211 + index, 1).value = horario;
  });
  horariosDia.forEach((horario, index) => {
    worksheet.getCell(231 + index, 1).value = horario;
  });


  // Linha 1 - Cabeçalhos Mesclados e Personalizados
  worksheet.mergeCells('B1:F1'); // Mescla "Dados do Docente/Administrador"
  worksheet.mergeCells('B2:F2'); //Mescla "Docente"
  worksheet.mergeCells('B3:F3'); //Mescla "Email"
  worksheet.mergeCells('B4:F4'); //Mescla "Tel1.:"
  worksheet.mergeCells('B5:F5'); //Mescla "Tel2.:"


  worksheet.mergeCells('T1:T6'); // Mescla COLUNA pras fazer uma divisão
  worksheet.mergeCells('A6:S6'); // Mescla LINHAS pras fazer uma divisão

  // Colunas mescladas do meses (JAN à DEZ)
  worksheet.mergeCells('A9:H9');
  worksheet.mergeCells('A8:H8');
  worksheet.mergeCells('A29:H29');
  worksheet.mergeCells('A49:H49');
  worksheet.mergeCells('A69:H69');
  worksheet.mergeCells('A89:H89');
  worksheet.mergeCells('A109:H109');
  worksheet.mergeCells('A129:H129');
  worksheet.mergeCells('A149:H149');
  worksheet.mergeCells('A169:H169');
  worksheet.mergeCells('A189:H189');
  worksheet.mergeCells('A209:H209');
  worksheet.mergeCells('A229:H229');
  worksheet.mergeCells('A249:H249');



  worksheet.getCell('B1').value = "Dados do Docente";

  // Celulas dos meses
  worksheet.getCell('A9').value = "Janeiro";
  worksheet.getCell('A29').value = "Fevereiro";
  worksheet.getCell('A49').value = "Março";
  worksheet.getCell('A69').value = "Abril";
  worksheet.getCell('A89').value = "Maio";
  worksheet.getCell('A109').value = "Junho";
  worksheet.getCell('A129').value = "Julho";
  worksheet.getCell('A149').value = "Agosto";
  worksheet.getCell('A169').value = "Setembro";
  worksheet.getCell('A189').value = "Outubro";
  worksheet.getCell('A209').value = "Novembro";
  worksheet.getCell('A229').value = "Dezembro";


  worksheet.getCell('A8').value = "Cronograma do período letivo"
 
  worksheet.getCell('B1').alignment = { horizontal: 'center', vertical: 'middle' };

  // Alinhando as mesclagens dos meses (JAN à DEZ) no centro
  worksheet.getCell('A9').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A8').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A29').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A49').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A69').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A89').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A109').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A129').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A149').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A169').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A189').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A209').alignment = { horizontal: 'center', vertical: 'middle' };
  worksheet.getCell('A229').alignment = { horizontal: 'center', vertical: 'middle' };


  const meses = ["JAN", "FEV", "MAR", "ABR", "MAI", "JUN", "JUL", "AGO", "SET", "OUT", "NOV", "DEZ"];
  meses.forEach((mes, index) => {
    worksheet.getCell(1, index + 8).value = mes;
  });


  // Aplicando cor de fundo para toda a linha 1
  worksheet.getRow(1).eachCell((cell) => {
    cell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF1E3A5F' }
    };
    cell.font = {
      bold: true,
      color: { argb: 'FFFFFFFF' }
    };
  });
 


  worksheet.getCell('A2').value = "Docente:";
  worksheet.getCell('A3').value = "E-mail:";
  worksheet.getCell('A4').value = "Tel.1:";
  worksheet.getCell('A5').value = "Tel.2:";


  worksheet.getCell('G2').value = "Dias Úteis:";
  worksheet.getCell('G3').value = "Horas Úteis:";
  worksheet.getCell('G4').value = "Horas Alocadas:";

// Adionando cor aos merge's dos meses (JAN à DEZ)
  ["A9", "A29", "A49", "A69", "A89", "A109", "A129", "A149", "A169", "A189", "A209", "A229"].forEach(cellAddress => {
    const cell = worksheet.getCell(cellAddress);
    cell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF33658A' }
    };
    cell.font = {
      bold: true,
      color: { argb: 'FFFFFFFF' }
    };
  });


  ["A8", "T1", "A1", "G1", "H6", "A2", "A3", "A4", "A5", "G1", "G2", "G3", "G4", "G5"].forEach(cellAddress => {
    const cell = worksheet.getCell(cellAddress);
    cell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF1E3A5F' }
    };
    cell.font = {
      bold: true,
      color: { argb: 'FFFFFFFF' }
    };
  });


  const diasDaSemana = ["","Domingo", "Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"];

  // Linha de dias da semana sendo adicionadas após o Mês (JAN à DEZ)
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(10, index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(30, index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(50 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(70 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(90 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(110 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(130 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(150 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(170 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(190 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(210 , index + 1).value = dia;
  });
  diasDaSemana.forEach((dia, index) => {
    worksheet.getCell(230 , index + 1).value = dia;
  });

  [10, 30, 50, 70, 90, 110, 130, 150, 170, 190, 210, 230].forEach((linha) => {
    worksheet.getRow(linha).eachCell((cell) => {
      cell.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF5A7D9A' }
      };
      cell.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' }
      };
    });
  });
  

  // Ajustar automaticamente a largura das colunas
  worksheet.columns.forEach((column) => {
    let maxLength = 0;
    column.eachCell({ includeEmpty: true }, (cell) => {
      const cellValue = cell.value ? cell.value.toString() : "";
      maxLength = Math.max(maxLength, cellValue.length);
    });
    column.width = maxLength + 5;
  });


  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename=Aulas.xlsx');
  await workbook.xlsx.write(res);
  res.end();
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

