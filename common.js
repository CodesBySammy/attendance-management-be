// Login Form Submission
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const registrationNumber = document.getElementById('registrationNumber').value;
  const password = document.getElementById('password').value;

  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, registrationNumber, password })
    });

    const data = await response.json();
    if (data.token) {
      localStorage.setItem('token', data.token);
      window.location.href = data.role === 'admin' ? 'admin.html' : 'user.html';
    } else {
      document.getElementById('errorMessage').textContent = data.msg;
    }
  } catch (error) {
    console.error('Login error:', error);
  }
});

// Fetch User Events and Attendance
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const response = await fetch('/user/events', {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
    });
    const attendanceData = await response.json();

    const userAttendanceTableBody = document.getElementById('userAttendanceTableBody');
    userAttendanceTableBody.innerHTML = '';
    attendanceData.forEach(record => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${record.eventName}</td>
        <td>${record.eventDate}</td>
        <td>${record.status}</td>
      `;
      userAttendanceTableBody.appendChild(row);
    });
  } catch (error) {
    console.error('Error fetching attendance:', error);
  }

  // Logout
  document.getElementById('logoutButton')?.addEventListener('click', () => {
    localStorage.removeItem('token');
    window.location.href = 'index.html';
  });
});
