const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcrypt');
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
      email: usuario.email
    };

    console.log('Usuário logado:', req.session.user);
    req.session.save(() => {
      res.redirect('perfil');
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
        if (!req.session.user || !req.session.user.id) {
          return res.status(401).json({ error: "Usuário não autenticado." });
      }
      
      const {curso_id, materia_id, turma_id, laboratorio_id, turno, diasSemana, dataInicio } = req.body;
      const usuario_id = req.session.user.id;

      console.log("Recebido no backend:", req.body);

      if (!curso_id || !materia_id || !turma_id || !laboratorio_id || !turno || !diasSemana || !dataInicio) {
          return res.status(400).json({ error: "Todos os campos da aula são obrigatórios." });
      }

      await pool.query(
          "INSERT INTO aula (usuario_id, curso_id, materia_id, turma_id, laboratorio_id, turno, diasSemana, dataInicio) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          [usuario_id ,curso_id, materia_id, turma_id, laboratorio_id, turno, diasSemana.join(','), dataInicio]
      );
      res.json({ message: "Aula cadastrada com sucesso!" });
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Erro ao cadastrar a aula." });
  }
});

app.get('/aulas', async (req, res) => {
  try {
    const [rows] = await pool.query(`
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
LEFT JOIN laboratorio l ON a.laboratorio_id = l.id;
    `);
    res.json(rows);
  } catch (error) {
    console.error("Erro ao buscar aulas:", error);
    res.status(500).json({ error: "Erro ao buscar aulas." });
  }
});

//Rota da planilha(montagem)
app.get('/exportar-excel', async (req, res) => {
  const [linhas] = await pool.query("SELECT * FROM aula");


  const planilha = new excelJS.Workbook();
  const aba = planilha.addWorksheet('Aulas');


  const horariosDia = [
    "07:30 - 08:30", "08:30 - 09:30", "09:30 - 10:30", "10:30 - 11:30", "",
    "13:00 - 14:00", "14:00 - 15:00", "15:00 - 16:00", "16:00 - 17:00", "",
    "18:40 - 21:40", ""
  ];
 
  const linhaHorario = [12, 27, 42, 57, 72, 87, 102, 117, 132, 147, 162, 177];

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


  aba.mergeCells('B1:F1');
  aba.mergeCells('B2:F2');
  aba.mergeCells('B3:F3');
  aba.mergeCells('B4:F4');
  aba.mergeCells('B5:F5');
  aba.mergeCells('A6:AF6');
  aba.mergeCells('H1:R1');
  aba.mergeCells('AF1:AF5');
  aba.mergeCells('G1:G5');


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



  aba.getCell('B1').value = "Dados do Docente";
  aba.getCell('A8').value = "Cronograma do período letivo";


  aba.getCell('A9').value = "Janeiro";
  aba.getCell('A24').value = "Fevereiro";
  aba.getCell('A39').value = "Março";
  aba.getCell('A54').value = "Abril";
  aba.getCell('A69').value = "Maio";
  aba.getCell('A84').value = "Junho";
  aba.getCell('A99').value = "Julho";
  aba.getCell('A114').value = "Agosto";
  aba.getCell('A129').value = "Setembro";
  aba.getCell('A144').value = "Outubro";
  aba.getCell('A159').value = "Novembro";
  aba.getCell('A174').value = "Dezembro";



  aba.getCell('B1').alignment = { horizontal: 'center', vertical: 'middle' };
  aba.getCell('H1').alignment = { horizontal: 'center', vertical: 'middle' };


  const linhasParaCentralizar = [8, 9, 24, 39, 54, 69, 84, 99, 114, 129, 144, 159, 174];


  linhasParaCentralizar.forEach((linha) => {
    aba.getCell(`A${linha}`).alignment = {
      horizontal: 'center',
      vertical: 'middle'
    };
  });


  const meses = ["JAN", "FEV", "MAR", "ABR", "MAI", "JUN", "JUL", "AGO", "SET", "OUT", "NOV", "DEZ"];


  meses.forEach((mes, indice) => {
    const celula = aba.getCell(1, indice + 20);
    celula.value = mes;
    celula.alignment = { horizontal: 'center' };
  });


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


  aba.getCell('A2').value = "Docente:";
  aba.getCell('A3').value = "E-mail:";
  aba.getCell('A4').value = "Tel.1:";
  aba.getCell('A5').value = "Tel.2:";
  aba.getCell('S2').value = "Dias Úteis:";
  aba.getCell('S3').value = "Horas Úteis:";
  aba.getCell('S4').value = "Horas Alocadas:";
  aba.getCell('H1').value = "Legenda";


  ["A9", "A24", "A39", "A54", "A69", "A84", "A99", "A114", "A129", "A144", "A159", "A174"].forEach(endereco => {
    const celula = aba.getCell(endereco);
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

  
  // Função para converter centímetros em unidades de largura de coluna
  function cmParaUnidadeExcel(cm) {
    const cmPorUnidade = 0.144; // Aproximadamente 0.144 cm por unidade de largura de coluna
    return cm / cmPorUnidade;
  }

  // Ajustar a largura de todas as colunas para 2,3 cm
  const largura = cmParaUnidadeExcel(2.3);

  // Iterar por todas as colunas e ajustar a largura
  aba.columns.forEach((coluna, index) => {
    coluna.width = largura;
  });


  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename=Aulas.xlsx');
  await planilha.xlsx.write(res);
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