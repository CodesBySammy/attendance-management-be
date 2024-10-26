const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const xlsx = require('xlsx');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

const cors = require('cors');
const allowedOrigins = ['https://exc-attendance.vercel.app/'];
app.use(cors(/*{
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
}*/));

// Connect to MongoDB Atlas
const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://samosa:Laudalele@mine.nlznt.mongodb.net/?retryWrites=true&w=majority&appName=mine';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  registrationNumber: String,
  password: String,
  role: { type: String, default: 'user' },
});
const User = mongoose.model('User', userSchema);

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
  eventName: String,
  eventDate: String,
  records: [{ studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, status: String }],
});
const Attendance = mongoose.model('Attendance', attendanceSchema);

// Login Route
app.post('/login', async (req, res) => {
  const { email, registrationNumber, password } = req.body;
  const user = await User.findOne({ email, registrationNumber });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.json({ msg: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token, role: user.role });
});

// Middleware to Protect Routes
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Get Events and User Attendance Status
app.get('/user/events', authenticateToken, async (req, res) => {
  const events = await Attendance.find().populate({
    path: 'records.studentId',
    select: 'name registrationNumber email',
  });

  const userAttendance = events.map(event => {
    const record = event.records.find(r => r.studentId._id.toString() === req.user.userId.toString());
    return {
      eventName: event.eventName,
      eventDate: event.eventDate,
      status: record ? record.status : 'Not marked',
    };
  });

  res.json(userAttendance);
});

// Get Student List (Admin)
app.get('/admin/students', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const students = await User.find({ role: 'user' }).select('email registrationNumber name');
  res.json(students);
});

// Post Attendance (Admin)
app.post('/admin/post-attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  const { eventName, eventDate, attendance } = req.body;
  const existingEvent = await Attendance.findOne({ eventName, eventDate });
  if (existingEvent) return res.json({ message: 'Event with this date already exists' });

  await Attendance.create({ eventName, eventDate, records: attendance });
  res.json({ message: 'Attendance posted successfully' });
});

// View Attendance (Admin)
app.get('/admin/view-attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  const { eventName, eventDate } = req.query;
  const attendanceData = await Attendance.findOne({ eventName, eventDate }).populate({
    path: 'records.studentId',
    select: 'name registrationNumber email',
  });

  if (!attendanceData) return res.json({message: "This event does not exist."});

  const response = attendanceData.records.map(record => ({
    name: record.studentId?.name || "Name not found",
    registrationNumber: record.studentId?.registrationNumber || "Registration not found",
    email:record.studentId?.email || "Email id not found",
    status: record.status,
  }));
  res.json(response);
});

// Download Attendance as Excel (Admin)
app.get('/admin/download-attendance', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

  const { eventName, eventDate } = req.query;
  const attendanceData = await Attendance.findOne({ eventName, eventDate }).populate({
    path: 'records.studentId',
    select: 'name registrationNumber email',
  });

  if (!attendanceData) return res.sendStatus(404);

  const workbook = xlsx.utils.book_new();
  const data = attendanceData.records.map(record => ({
    Name: record.studentId?.name || "Name not found",
    RegistrationNumber: record.studentId?.registrationNumber || "Registration not found",
    Email:record.studentId?.email || "Email id not found",
    Status: record.status,
  }));

  const worksheet = xlsx.utils.json_to_sheet(data);
  xlsx.utils.book_append_sheet(workbook, worksheet, 'Attendance');

  // Set headers for direct download without saving
  res.setHeader('Content-Disposition', `attachment; filename=attendance_${eventName}_${eventDate}.xlsx`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

  // Write workbook directly to response
  const buffer = xlsx.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  res.send(buffer);
});


// Start Server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
