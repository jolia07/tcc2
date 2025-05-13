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
// Adicione esta rota no seu app.js
app.post('/atualizar-telefone2', async (req, res) => {
    if (!req.session || !req.session.user || !req.session.user.id) {
        return res.status(401).json({ success: false, message: 'Usuário não autenticado' });
    }

    const { telefone2 } = req.body;
    
    // Validação básica
    if (!telefone2 || telefone2.length < 10 || telefone2.length > 11) {
        return res.status(400).json({ 
            success: false, 
            message: 'Telefone inválido. Deve ter 10 ou 11 dígitos.' 
        });
    }

    try {
        // Atualiza no banco de dados
        const result = await pool.query(
            'UPDATE usuarios SET telefone2 = $1 WHERE id = $2 RETURNING *',
            [telefone2, req.session.user.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuário não encontrado' 
            });
        }

        // Atualiza na sessão
        req.session.user.telefone2 = telefone2;
        
        return res.json({ 
            success: true, 
            message: 'Telefone secundário atualizado com sucesso' 
        });
    } catch (error) {
        console.error('Erro ao atualizar telefone:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Erro interno ao atualizar telefone' 
        });
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
   
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (!rows.length) {
      console.log('E-mail não encontrado:', email);
      return res.status(200).json({ message: 'Se existir uma conta com este email, um link foi enviado.' });
    }
    const usuario = rows[0];

    // Geração do token e link
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hora
    const resetLink = `https://sepa-api.onrender.com/redefinir-senha.html?token=${token}`;    
    await pool.query(
      'INSERT INTO reset_tokens (user_id, token, expires) VALUES ($1, $2, $3)',
      [rows[0].id, token, expires.toISOString().slice(0, 19).replace('T', ' ')] // Formato MySQL
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
    const { rows } = await pool.query(
      `SELECT * FROM reset_tokens
       WHERE token = $1
       AND used = FALSE
       AND expires > (NOW() AT TIME ZONE 'UTC')`,
      [token]
    );

    if (rows.length === 0) {
      return res.status(400).json({ message: 'Link inválido ou expirado' });
    }

    const tokenData = rows[0];

    const senhaCriptografada = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE usuarios SET senha = $1 WHERE id = $2',
        [senhaCriptografada, tokenData.user_id]);

    await pool.query('UPDATE reset_tokens SET used = TRUE WHERE token = $1', [token]);

    res.json({ message: 'Senha redefinida com sucesso! Você pode fazer login agora.' });

  } catch (err) {
    console.error('Erro detalhado:', err.message);
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


app.get('/eventos', async (req, res) => {
  try {
    const userType = req.session.user?.tipo;
    const userName = req.session.user?.nome;

    let query = `
      SELECT
        id,
        descricao AS materia,
        nome as turma,
        docente,
        dias_semana AS diasSemana,
        data_atividade AS dataInicio,
        turno,
        COALESCE(descricao_localizacao, localizacao) AS laboratorio,
        'Importado' AS curso,
        'Importado' AS turma
      FROM importado
    `;

    let params = [];
    if (userType === 'Docente') {
      query += " WHERE docente = $1";
      params.push(userName);
    }

    query += " ORDER BY data_atividade, hora_inicio";

    const { rows } = await pool.query(query, params);

    const eventos = [];

    for (const aula of rows) {
      const diasSemana = (aula.diasSemana || '').split(',').map(dia => dia.trim());
      const inicioBase = new Date(aula.dataInicio);

      const diaParaNumero = {
        'Domingo': 0, 'Segunda': 1, 'Terça': 2,
        'Quarta': 3, 'Quinta': 4, 'Sexta': 5, 'Sábado': 6, 'Sabado': 6
      };

      const diasNumeros = diasSemana.map(d => {
        const diaNormalizado = d === 'Sabado' ? 'Sábado' : d;
        return diaParaNumero[diaNormalizado];
      });

      // Gera eventos para 12 semanas
      for (let semana = 0; semana < 12; semana++) {
        diasNumeros.forEach(diaNumero => {
          const dataEvento = new Date(inicioBase);
          let diasAdicionais = (semana === 0) ? 0 : (diaNumero - dataEvento.getDay() + 7) % 7 + (semana * 7);
          dataEvento.setDate(dataEvento.getDate() + diasAdicionais);

          let horaInicio = 8, horaFim = 12;
          if (aula.turno === 'TARDE') {
            horaInicio = 13; horaFim = 17;
          } else if (aula.turno === 'NOITE') {
            horaInicio = 19; horaFim = 22;
          }

          const inicio = new Date(dataEvento);
          inicio.setHours(horaInicio, 0, 0, 0);
          const fim = new Date(dataEvento);
          fim.setHours(horaFim, 0, 0, 0);

          eventos.push({
            id: `${aula.id}-${semana}-${diaNumero}`,
            text: `${aula.materia}\nTurma: ${aula.turma}\nLab: ${aula.laboratorio}`,
            start_date: inicio,
            end_date: fim,
            tipo: "AULA",
            color: "#37516d",
            textColor: "#fff",
            docente: aula.docente // Adicionamos a propriedade docente
          });
        });
      }
    }

    res.json(eventos);
  } catch (error) {
    console.error('Erro ao carregar eventos:', error);
    res.status(500).json({ error: "Erro ao carregar eventos" });
  }
});

// Rota para pegar todas as aulas 
app.get('/todasAulas', async (req, res) => {
  try {
    if (!req.session?.user) {
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
    // 1. Buscar informações do usuário
    const userQuery = await pool.query(
      'SELECT id, nome, email, tipo FROM usuarios WHERE id = $1',
      [req.session.user.id]
    );
    
    if (userQuery.rows.length === 0) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }
    
    const usuario = userQuery.rows[0];

    // 2. Lógica diferente para docentes e outros usuários
    let aulasResult;
    if (usuario.tipo === 'Docente') {
      // Para docentes: buscar apenas aulas onde o nome do docente coincide
      aulasResult = await pool.query(`
        SELECT id, nome, docente, turno, data_atividade,
               hora_inicio, hora_fim, localizacao
        FROM importado
        WHERE docente = $1 AND data_atividade = $2
        ORDER BY hora_inicio`,
        [usuario.nome, hojeFormatado]);
    } else {
      // Para outros usuários: buscar todas as aulas do dia
      aulasResult = await pool.query(`
        SELECT id, nome, docente, turno, data_atividade,
               hora_inicio, hora_fim, localizacao
        FROM importado 
        WHERE data_atividade = $1
        ORDER BY hora_inicio`,
        [hojeFormatado]);
    }

    // 3. Formatar os resultados
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

// Nova rota para listar planilhas
app.get('/listar-planilhas-importadas', async (req, res) => {
  if (!req.session.user) {
      return res.status(403).json({ success: false, message: 'Acesso negado' });
  }


  try {
      const result = await pool.query('SELECT DISTINCT nome_planilha FROM importado');
      res.json({
          success: true,
          planilhas: result.rows
      });
  } catch (error) {
      console.error('Erro ao listar planilhas:', error);
      res.status(500).json({
          success: false,
          message: 'Erro ao listar planilhas',
          error: error.message
      });
  }
});


//Rota de ADM para limpar as informações do banco(planilhas)
app.delete('/limpar-dados-importados', async (req, res) => {
  if (!req.session.user) {
      return res.status(403).json({ success: false, message: 'Acesso negado' });
  }

  const { planilha } = req.query;

  try {
      // Cria backup (opcional) com filtro por planilha se especificado
      const backupQuery = planilha 
          ? 'SELECT * FROM importado WHERE nome_planilha = $1'
          : 'SELECT * FROM importado';
      const backupParams = planilha ? [planilha] : [];
      const backup = await pool.query(backupQuery, backupParams);
     
      // Deleta os dados com filtro por planilha se especificado
      const deleteQuery = planilha 
          ? 'DELETE FROM importado WHERE nome_planilha = $1 RETURNING *'
          : 'DELETE FROM importado RETURNING *';
      const result = await pool.query(deleteQuery, backupParams);
     
      res.json({
          success: true,
          message: planilha 
              ? `Dados da planilha "${planilha}" removidos (${result.rowCount} registros)`
              : `Todos os dados removidos (${result.rowCount} registros)`,
          backup_count: backup.rowCount,
          deleted: result.rows
      });
  } catch (error) {
      console.error('Erro ao limpar dados:', error);
      res.status(500).json({
          success: false,
          message: 'Erro ao limpar dados',
          error: error.message
      });
  }
});

// Rota para obter docentes da tabela importado
app.get('/docentesImportado', async (req, res) => {
  try {
    if (!req.session?.user) {
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

function getColorForMateria(descricao) {
  // Usamos um hash simples para gerar um código de cor baseado no nome da matéria
  let hash = 0;
  for (let i = 0; i < descricao.length; i++) {
    hash = descricao.charCodeAt(i) + ((hash << 5) - hash);
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

app.post('/upload-laboratorios', async (req, res) => {
  if (!req.files || !req.files.planilha) {
    return res.status(400).send('Nenhum arquivo enviado.');
  }

  try {
    const nomePlanilha = req.body.nomePlanilha || 'planilha_sem_nome';

     // Verifica se a planilha já foi importada antes
    const planilhaExistente = await pool.query(
      'SELECT 1 FROM importado WHERE nome_planilha = $1 LIMIT 1',
      [nomePlanilha]
    );

    if (planilhaExistente.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Esta planilha (${nomePlanilha}) já foi importada anteriormente.`
      });
    }

    const workbook = xlsx.read(req.files.planilha.data, { type: 'buffer' });
    const primeiraAba = workbook.SheetNames[0];
    const dados = xlsx.utils.sheet_to_json(workbook.Sheets[primeiraAba]);

    const agrupadoPorDocente = {};

    dados.forEach(linha => {
      const docente = linha['Nome do pessoal atribuído'] || 'Sem docente';
      
      if (!agrupadoPorDocente[docente]) {
        agrupadoPorDocente[docente] = [];
      }

      const datas = linha['Datas da atividade (Individual)'] 
        ? linha['Datas da atividade (Individual)'].split(';').map(d => d.trim())
        : [];

      const horaInicio = converterHoraExcel(linha['Hora de início agendada']);
      const horaFim = converterHoraExcel(linha['Fim Agendado']);

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
          turno: determinarTurno(horaInicio),
          nome_planilha: nomePlanilha // Adiciona o nome da planilha
        });
      });
    });

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
          const dataFormatada = registro.data_atividade.split('/').reverse().join('-');
          
          // Modifique a query SQL para incluir nome_planilha
          const insertRes = await pool.query(
            `INSERT INTO importado (
              nome, descricao, docente, dias_semana, 
              hora_inicio, hora_fim, localizacao, 
              descricao_localizacao, data_atividade, 
              agendado, turno, nome_planilha
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`,
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
              registro.turno,
              registro.nome_planilha // Adiciona o nome da planilha
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

app.get('/importado', async (req, res) => {
  try {
      let query = 'SELECT * FROM importado';
      let params = [];
     
      // Se foi passado o parâmetro docente, filtra os resultados
      if (req.query.docente) {
          query += ' WHERE docente = $1';
          params = [req.query.docente];
      }
     
      query += ' ORDER BY data_atividade, hora_inicio';
     
      const { rows } = await pool.query(query, params);
      res.json(rows);
  } catch (error) {
      console.error('Erro ao buscar dados importados:', error);
      res.status(500).json({ error: 'Erro ao buscar dados importados' });
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

     // Buscar dados do perfil do docente autenticado
    const { rows: docentePerfil } = await pool.query(
      `SELECT email, telefone1, telefone2 
       FROM usuarios 
       WHERE nome = $1`,
      [docenteNome]
    );

    // Buscar dados do docente importado - ajustado para os campos reais da tabela
     const {rows: aulasImportadas} = await pool.query(
      `SELECT
        id,
        descricao,
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
    aba.getCell('B3').value = docentePerfil.length > 0 ? docentePerfil[0].email : "";    // E-mail 
    aba.getCell('B4').value = docentePerfil.length > 0 ? docentePerfil[0].telefone1 : ""; // Telefone 1 
    aba.getCell('B5').value = docentePerfil.length > 0 ? docentePerfil[0].telefone2 : ""; // Telefone 2 


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
          size: 24    
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
    aba.mergeCells('H1:S1');
    aba.mergeCells('AF1:AF5');
    aba.mergeCells('G1:G5');
    aba.mergeCells('S2:S5')

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

    const linhasParaCentralizar = [1, 8, ...meses.map(m => m.linha)];
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
            size: 26,
            bold: true
          }
      }
    });

    // Cabeçalho dos meses (JAN, FEV, etc.) (igual ao original)
    const mesesAbreviados = ["JAN", "FEV", "MAR", "ABR", "MAI", "JUN", "JUL", "AGO", "SET", "OUT", "NOV", "DEZ"];
    mesesAbreviados.forEach((mes, indice) => {
      const celula = aba.getCell(1, indice + 20);
      celula.value = mes;
      celula.alignment = { horizontal: 'center', vertical: "middle" };
      celula.font = { size: 26, bold: true}
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
    aba.getCell('H1').value = "Legenda";

    try {
      if (!aba) {
          throw new Error('A aba/worksheet não foi definida corretamente');
      }
  
      const materiasUnicas = [...new Set(aulasImportadas.map(aula => aula.descricao ))];
      const maxColunas = 18; // AE é a coluna 31 (A=1, B=2, ..., AE=31)
      const maxLinhas = 5;   // Limite até a linha 5
      let materiasExcedentes = 0;
  
      let colunaAtual = 8; // H é a coluna 8
      let linhaAtual = 2;   // Começa na linha 2
  
      for (const descricao of materiasUnicas) {
          // Verifica se ultrapassou o limite máximo de linhas
          if (linhaAtual > maxLinhas) {
              materiasExcedentes++;
              continue;
          }
  
          // Verifica se precisa mudar de linha
          if (colunaAtual > maxColunas) {
              linhaAtual++;
              colunaAtual = 8; // Volta para a coluna H
              
              // Verifica se a nova linha existe, se não, cria
              if (!aba.getRow(linhaAtual)) {
                  aba.addRow({});
              }
              
              // Se ultrapassou o limite de linhas após mudança
              if (linhaAtual > maxLinhas) {
                  materiasExcedentes++;
                  continue;
              }
          }
  
          const row = aba.getRow(linhaAtual);
          if (!row) {
              throw new Error(`Falha ao obter/criar a linha ${linhaAtual}`);
          }
  
          const corMateria = getColorForMateria(descricao);
          
          // Verificar se a coluna existe antes de acessar
          if (!aba.getColumn(colunaAtual)) {
              aba.columns[colunaAtual] = { width: 20 };
          }
  
          // Acessar a célula de forma segura
          const cell = row.getCell(colunaAtual);
          if (!cell) {
              throw new Error(`Falha ao acessar célula na coluna ${colunaAtual}`);
          }
  
          // Definir os valores
          cell.value = descricao;
          cell.fill = {
              type: 'pattern',
              pattern: 'solid',
              fgColor: { argb: corMateria }
          };
          cell.font = {
              bold: true,
              color: { argb: 'FF000000' }
          };
          cell.alignment = {
              horizontal: 'center',
              vertical: 'middle',
              wrapText: true
          };
          cell.border = {
              top: { style: 'thin', color: { argb: 'FF000000' } },
              left: { style: 'thin', color: { argb: 'FF000000' } },
              bottom: { style: 'thin', color: { argb: 'FF000000' } },
              right: { style: 'thin', color: { argb: 'FF000000' } }
          };
          cell.font = {
            size: 16
          }
  
          // Garantir largura da coluna
          aba.getColumn(colunaAtual).width = 20;
          
          colunaAtual++;
      }
  
      if (materiasExcedentes > 0) {
          console.warn(`Atenção: Limite de legendas atingido. ${materiasExcedentes} matérias não foram incluídas.`);
          // Você pode também exibir um alerta para o usuário aqui
          alert(`Limite de legendas atingido. ${materiasExcedentes} matérias não foram incluídas.`);
      }
  
      console.log('Matérias adicionadas com sucesso');
  } catch (error) {
      console.error('Erro detalhado:', error);
      throw new Error(`Falha ao gerar planilha: ${error.message}`);
  }
   
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
        size: 28
      };
    });

    // Estilo das células de cabeçalho (igual ao original)
    ["A8", "A1", "A2", "A3", "A4", "A5", "A6", 'AF1', 'G1', 'S2'].forEach(endereco => {
      const celula = aba.getCell(endereco);
      celula.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF1E3A5F' }
      };
      celula.font = {
        bold: true,
        color: { argb: 'FFFFFFFF' },
        size: 26
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
          size: 26
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
          size: 26
        };
        celula.alignment = {
          horizontal: 'center',
          vertical: 'middle'
        };
      });
    });

    const celulasParaFormatar = ['B1', 'H1'];
    celulasParaFormatar.forEach(celula => {
      aba.getCell(celula).font = {
        size: 26,
        bold: true
      };
      aba.getCell(celula).alignment = {
        horizontal: 'center',
        vertical: 'middle'
      }
    });

    celulaCronograma = ['A8'];
    celulaCronograma.forEach(celula =>{
      aba.getCell(celula).font = {
        size: 30,
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
          descricao: aula.descricao,
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
   
        const materiaColor = getColorForMateria(aulaPadronizada.descricao );
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
              { text: `${aulaPadronizada.descricao}\n`, font: { size: 13, bold: true } },
              { text: `${aulaPadronizada.laboratorio}`  }
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
            size: 13,
            bold: true
          }
        }
   
      } catch (error) {
        console.error(`Erro ao processar aula importada ${aula?.id}:`, error);
      }
    });

    aba.views = [
      {
        zoomScale: 28
      }
    ];
    
    // Ajustar largura das colunas (igual ao original)
    function cmParaUnidadeExcel(cm) {
      const cmPorUnidade = 0.144;
      return cm / cmPorUnidade;
    }

    const largura = cmParaUnidadeExcel(7);
    aba.columns.forEach((coluna, index) => {
      coluna.width = largura;
    });

    function cmParaAlturaExcel(cm) {
      return cm * 28.3465; 
    }
  
    const altura = cmParaAlturaExcel(3);
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
  if (!req.session.user) {
    return res.status(403).json({ success: false, message: 'Acesso negado' });
  }


  try {
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);
    const hojeFormatado = hoje.toISOString().split('T')[0];
   
    // Consulta base
    let query = `
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
      WHERE data_atividade >= $1`;
   
    // Parâmetros da query
    let params = [hojeFormatado];
   
    // Se for docente, adiciona filtro por nome
    if (req.session.user.tipo === 'Docente') {
      query += ' AND docente = $2';
      params.push(req.session.user.nome);
    }
   
    // Ordenação e limite
    query += ' ORDER BY data_atividade ASC, hora_inicio ASC LIMIT 20';
   
    const { rows } = await pool.query(query, params);


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
