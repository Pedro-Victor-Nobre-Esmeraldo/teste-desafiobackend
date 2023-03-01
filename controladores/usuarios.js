const bcrypt = require("bcrypt");
const { pool } = require("../conexao");
const jwt = require("jsonwebtoken");
const senhaJwt = require("../senhaJwt");

const cadastrarUsuario = async (req, res) => {
  const { nome, email, senha } = req.body;

  try {
    if (!nome || !email || !senha) {
      return res.status(400).json({
        mensagem: "Os campos obrigratórios precisam ser preenchidos.",
      });
    }
    const verificarEmailExiste = await pool.query(
      "select * from usuarios where email = $1",
      [email]
    );

    if (verificarEmailExiste.rowCount > 0) {
      return res.status(400).json({
        mensagem: "Já existe usuário cadastrado com o e-mail informado.",
      });
    }

    const senhaCriptografada = bcrypt.hash(senha, 10);

    const query = `
        insert into usuarios (nome,email,senha)
        values ($1,$2,$3) returning *
        `;

    const { rows } = await pool.query(query, [nome, email, senhaCriptografada]);

    const { senha: _, ...usuario } = rows;
    return res.status(201).json(usuario);
  } catch (error) {
    return res.status(500).json({ mensagem: "erro interno do servidor" });
  }
};

const login = async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ mensagem: "Usuário e/ou senha inválidos" });
  }

  try {
    const { rows, rowCount } = await pool.query(
      "select * from usuarios where email = $1",
      [email]
    );

    if (rowCount === 0) {
      return res.status(400).json({ mensagem: "Email ou senha inválida." });
    }

    const { senha: senhaUsuario, ...usuario } = rows[0];

    const senhaCorreta = await bcrypt.compare(senha, senhaUsuario);

    if (!senhaCorreta) {
      return res.status(400).json({ mensagem: "Email ou senha inválida." });
    }

    const token = jwt.sign({ id: usuario.id }, senhaJwt, { expiresIn: "8h" });

    return res.json({
      usuario,
      token,
    });
  } catch (error) {
    return res.status(500).json({ mensagem: "erro interno do servidor" });
  }
};

const detalharUsuario = async (req, res) => {
  const { id } = req.params;

  try {
    const { rows, rowCount } = await pool.query(
      "select * from usuarios where id = $1",
      [id]
    );

    if (rowCount === 0) {
      return res.status(401).json({
        mensagem:
          "Para acessar este recurso um token de autenticação válido deve ser enviado.",
      });
    }

    const { senha: _, ...usuarioCerto } = rows[0];

    return res.json({ usuarioCerto });
  } catch (error) {
    return res.status(500).json({ mensagem: "Erro interno do servidor." });
  }
};

const atualizarUsuario = async (req, res) => {
  const { id } = req.params;

  const { nome, email, senha } = req.body;

  try {
    if (!nome || !email || !senha) {
      return res
        .status(401)
        .json({ mensagem: "Preencha todos os campos obrigatorios." });
    }

    const { rowCount } = await pool.query(
      "select* from usuarios where email = $1",
      [email]
    );

    if (rowCount > 0) {
      return res.status(401).json({
        mensagem:
          "O e-mail informado já está sendo utilizado por outro usuário.",
      });
    }

    const senhaCriptografada = bcrypt.hash(senha, 10);

    pool.query(
      "update usuarios nome = $1, email = $2, senha =$3 where id = $4",
      [nome, email, senhaCriptografada, id]
    );

    return res.status(204);
  } catch (error) {
    return res.status(500).json({ mensagem: "Erro interno do servidor." });
  }
};

module.exports = {
  cadastrarUsuario,
  login,
  detalharUsuario,
  atualizarUsuario,
};
