const btnLoginPopup = document.querySelector('.btnLogin-popup');
const wrapper = document.querySelector('.wrapper');
const overlay = document.querySelector('.overlay');
const iconClose = document.querySelector('.icon-close');
const registerLink = document.querySelector('.register-link');
const loginLink = document.querySelector('.login-link');
const updateLink = document.querySelector('.update-link');
const senhaInput = document.querySelector(".input-senha");
const checkbox = document.querySelectorAll(".verSenha");
const iconBack = document.querySelector('.icon-back');

// Abre o popup de login ao clicar no botão de login
btnLoginPopup.addEventListener('click', () => {
    wrapper.classList.add('show');
    overlay.classList.add('show');
    wrapper.querySelector('.form-box.login').style.display = 'block'; // Mostra o formulário de login
    wrapper.querySelector('.form-box.register').style.display = 'none'; // Oculta o formulário de registro
    wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
    iconBack.style.display = 'none';
});

function openLoginPopup(link) {
    wrapper.classList.add('show');
    overlay.classList.add('show');
    wrapper.querySelector('.form-box.login').style.display = 'block'; // Mostra o formulário de login
    wrapper.querySelector('.form-box.register').style.display = 'none'; // Oculta o formulário de registro
    wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
    iconClose.style.display = 'flex';
    iconBack.style.display = 'none';
}

// Abre o formulário de registro
registerLink.addEventListener('click', (e) => {
    e.preventDefault();
    wrapper.querySelector('.form-box.login').style.display = 'none'; // Oculta login
    wrapper.querySelector('.form-box.register').style.display = 'block'; // Exibe registro
    wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
});

// Abre o formulário de login
loginLink.addEventListener('click', (e) => {
    e.preventDefault();
    wrapper.querySelector('.form-box.register').style.display = 'none'; // Oculta registro
    wrapper.querySelector('.form-box.login').style.display = 'block'; // Exibe login
    wrapper.querySelector('.form-box.update').style.display = 'none'; // Oculta o formulário de atualização
});

// Abre o formulário de atualização de senha ao clicar em "Esqueceu sua senha?"
updateLink.addEventListener('click', (e) => {
    e.preventDefault();
    wrapper.querySelector('.form-box.login').style.display = 'none';
    wrapper.querySelector('.form-box.register').style.display = 'none';
    wrapper.querySelector('.form-box.update').style.display = 'block';

    iconBack.style.display = 'flex';
    iconClose.style.display = 'none';
});

// Fecha o popup
iconClose.addEventListener('click', () => {
    wrapper.classList.remove('show');
    overlay.classList.remove('show');
});

// Voltar para o formulário de login ao clicar na seta de voltar
iconBack.addEventListener('click', () => {
    openLoginPopup();
});