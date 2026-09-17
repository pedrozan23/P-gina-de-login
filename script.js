const container = document.getElementById('container');
const loginBtn = document.getElementById('login');
const registerBtn = document.getElementById('registro');

registerBtn.addEventListener('click', () => {
    container.classList.add('active');
});

loginBtn.addEventListener('click', () => {
    container.classList.remove('active');
});
