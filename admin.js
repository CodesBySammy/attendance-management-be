document.addEventListener('DOMContentLoaded', () => {
  const createEventBtn = document.getElementById('createEvent');
  const postAttendanceBtn = document.getElementById('postAttendance');
  const viewAttendanceBtn = document.getElementById('viewAttendance');
  const downloadAttendanceBtn = document.getElementById('downloadAttendance');
  const studentsTableBody = document.getElementById('studentsTableBody');
  const attendanceTableBody = document.getElementById('attendanceTableBody');
  const eventMessage = document.getElementById('eventMessage');

  // Fetch Students for Attendance
  createEventBtn.addEventListener('click', async () => {
    try {
      const response = await fetch('/admin/students', {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
      });
      const students = await response.json();

      studentsTableBody.innerHTML = '';
      students.forEach(student => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${student.registrationNumber}</td>
          <td>${student.email}</td>
          <td>
            <select data-student-id="${student._id}">
              <option value="present">Present</option>
              <option value="absent">Absent</option>
            </select>
          </td>
        `;
        studentsTableBody.appendChild(row);
      });
    } catch (error) {
      console.error('Error fetching students:', error);
    }
  });

  // Post Attendance
  postAttendanceBtn.addEventListener('click', async () => {
    const eventName = document.getElementById('eventName').value;
    const eventDate = document.getElementById('eventDate').value;
    const attendance = Array.from(document.querySelectorAll('[data-student-id]')).map(select => ({
      studentId: select.dataset.studentId,
      status: select.value,
    }));

    try {
      const response = await fetch('/admin/post-attendance', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
        body: JSON.stringify({ eventName, eventDate, attendance }),
      });

      const data = await response.json();
      eventMessage.textContent = data.message;
    } catch (error) {
      console.error('Error posting attendance:', error);
    }
  });

  // View Attendance
  viewAttendanceBtn.addEventListener('click', async () => {
    const viewEventName = document.getElementById('viewEventName').value;
    const viewEventDate = document.getElementById('viewEventDate').value;

    try {
      const response = await fetch(`/admin/view-attendance?eventName=${viewEventName}&eventDate=${viewEventDate}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
      });
      const attendance = await response.json();

      attendanceTableBody.innerHTML = '';
      attendance.forEach(record => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${record.name}</td>
          <td>${record.registrationNumber}</td>
          <td>${record.status}</td>
        `;
        attendanceTableBody.appendChild(row);
      });
    } catch (error) {
      console.error('Error viewing attendance:', error);
    }
  });

  // Download Attendance as Excel
  document.getElementById('downloadAttendance')?.addEventListener('click', async () => {
    const eventName = document.getElementById('viewEventName').value;
    const eventDate = document.getElementById('viewEventDate').value;
  
    try {
      const response = await fetch(`/admin/download-attendance?eventName=${eventName}&eventDate=${eventDate}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
      });
  
      if (!response.ok) throw new Error('Failed to download attendance');
  
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `attendance_${eventName}_${eventDate}.xlsx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading attendance:', error);
    }
  });
  
  // Logout
  document.getElementById('logoutButton').addEventListener('click', () => {
    localStorage.removeItem('token');
    window.location.href = 'index.html';
  });
});
