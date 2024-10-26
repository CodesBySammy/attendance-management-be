document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();
  
    const email = document.getElementById('email').value;
    const registrationNumber = document.getElementById('registrationNumber').value;
    const password = document.getElementById('password').value;
  
    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, registrationNumber, password })
      });
  
      const data = await response.json();
  
      if (response.ok) {
        localStorage.setItem('token', data.token);
        if (data.role === 'admin') {
          window.location.href = '/admin.html';
        } else if (data.role === 'user') {
          window.location.href = '/user.html';
        }
      } else {
        document.getElementById('error').textContent = data.msg;
      }
    } catch (error) {
      console.error('Error logging in:', error);
    }
  });
  
  // Redirect if already logged in
  window.onload = function () {
    const token = localStorage.getItem('token');
    if (token) {
      const { role } = JSON.parse(atob(token.split('.')[1]));
      if (role === 'admin') window.location.href = '/admin.html';
      if (role === 'user') window.location.href = '/user.html';
    }
  };
  