document.addEventListener('DOMContentLoaded', async () => {
    const userAttendanceTableBody = document.getElementById('userAttendanceTableBody');
  
    // Fetch Events and User Attendance
    try {
      const response = await fetch('/admin/view-attendance', {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
      });
  
      const events = await response.json();
  
      userAttendanceTableBody.innerHTML = '';
      events.forEach(event => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${event.eventName}</td>
          <td>${event.eventDate}</td>
          <td>${event.status || 'Not recorded'}</td>
          <td>
            <button class="viewAttendanceBtn" data-event-name="${event.eventName}" data-event-date="${event.eventDate}">View Attendance</button>
          </td>
        `;
        userAttendanceTableBody.appendChild(row);
      });
  
      // Add Event Listeners to View Attendance Buttons
      document.querySelectorAll('.viewAttendanceBtn').forEach(button => {
        button.addEventListener('click', async () => {
          const eventName = button.getAttribute('data-event-name');
          const eventDate = button.getAttribute('data-event-date');
          const attendanceResponse = await fetch(`/admin/view-attendance?eventName=${eventName}&eventDate=${eventDate}`, {
            headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
          });
          const attendanceData = await attendanceResponse.json();
  
          // Display User Attendance Status
          const userAttendanceStatus = attendanceData.find(record => record.registrationNumber === JSON.parse(localStorage.getItem('user')).registrationNumber);
          alert(`Your attendance status for ${eventName} on ${eventDate}: ${userAttendanceStatus ? userAttendanceStatus.status : 'Not recorded'}`);
        });
      });
    } catch (error) {
      console.error('Error fetching user attendance:', error);
    }
  });
  
  // Logout
  document.getElementById('logoutButton').addEventListener('click', () => {
    localStorage.removeItem('token');
    window.location.href = 'index.html';
  });
  