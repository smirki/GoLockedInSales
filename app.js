const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const http = require('http');
const socketio = require('socket.io');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const cors = require('cors');
const axios = require('axios');  // Add this line to require axios

const app = express();
const server = http.createServer(app);
const io = socketio(server);

app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const usersFilePath = path.join(__dirname, 'data/users.json');
const getUserChatFilePath = (userId) => path.join(__dirname, 'data', 'chats', `${userId}.json`);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

const initChatDirectory = () => {
  const chatDir = path.join(__dirname, 'data', 'chats');
  if (!fs.existsSync(chatDir)) {
    fs.mkdirSync(chatDir, { recursive: true });
  }
};

initChatDirectory();

const readUsers = () => {
  try {
    const usersData = fs.readFileSync(usersFilePath);
    return JSON.parse(usersData);
  } catch (error) {
    if (error.code === 'ENOENT') {
      logger.warn('Users file not found, creating a new one');
      return [];
    }
    logger.error('Error reading users file', { error });
    return [];
  }
};

const writeUsers = (users) => {
  try {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
  } catch (error) {
    logger.error('Error writing users file', { error });
  }
};

const readChat = (userId) => {
  try {
    const chatData = fs.readFileSync(getUserChatFilePath(userId));
    return JSON.parse(chatData);
  } catch (error) {
    if (error.code === 'ENOENT') {
      const users = readUsers();
      const user = users.find(user => user.id === userId);
      logger.warn('Chat file not found, creating a new one', { userId });
      return { userId, username: user.nickname, messages: [], lockedBy: null };
    }
    logger.error('Error reading chat file', { error });
    return { userId, username: `User${userId}`, messages: [], lockedBy: null };
  }
};

const writeChat = (chat) => {
  try {
    fs.writeFileSync(getUserChatFilePath(chat.userId), JSON.stringify(chat, null, 2));
  } catch (error) {
    logger.error('Error writing chat file', { error });
  }
};

let chatLocks = {}; // Track chat locks

// User routes

app.use((req, res, next) => {
  if ((req.path === '/login.html' || req.path === '/register.html') && req.cookies.token) {
    res.redirect('/chat.html');
  } else {
    next();
  }
});

app.post('/api/users/register', async (req, res) => {
  try {
    const { name, nickname, description, goals, email, username, password } = req.body;
    const users = readUsers();
    const userExists = users.find(user => user.username === username);

    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = users.length ? users[users.length - 1].id + 1 : 1;
    users.push({ id: userId, name, nickname, description, goals, email, username, password: hashedPassword });
    writeUsers(users);

    // Create default chat file with welcome message
    const defaultChat = {
      userId,
      username: nickname,
      messages: [
        {
          sender: 'Staff',
          text: "hey! welcome to the site. Send a message to get started with your goals!",
          timestamp: new Date().toISOString(),
          read: false
        }
      ],
      lockedBy: null
    };
    writeChat(defaultChat);

    logger.info('User registered', { userId, username });

    const token = jwt.sign({ id: userId, username }, 'secret', { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.status(201).json({ message: 'User registered and logged in successfully', userId, username });
  } catch (error) {
    logger.error('Error in user registration', { error });
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/users/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = readUsers();
    const user = users.find(user => user.username === username);

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, 'secret', { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    logger.info('User logged in', { userId: user.id, username: user.username });
    res.json({ message: 'Login successful', userId: user.id, username: user.username });
  } catch (error) {
    logger.error('Error in user login', { error });
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/users/logout', (req, res) => {
  res.clearCookie('token');
  logger.info('User logged out');
  res.json({ message: 'Logout successful' });
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/index.html'); // Redirect to homepage if no token
  }

  try {
    const decoded = jwt.verify(token, 'secret');
    req.user = decoded;
    next();
  } catch (err) {
    logger.error('Invalid token', { error: err });
    return res.redirect('/index.html'); // Redirect to homepage if invalid token
  }
};

app.get('/api/users/me', verifyToken, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
});

app.get('/api/staff/dashboard', verifyToken, (req, res) => {
  const users = readUsers();
  const chats = users.map(user => readChat(user.id));
  res.json(chats);
});

app.get('/goals/:username', (req, res) => {
  const username = req.params.username;
  const users = readUsers();
  const user = users.find(u => u.username === username);

  if (user) {
    res.json({ goals: user.goals });
  } else {
    res.status(404).json({ message: 'User not found' });
  }
});

app.get('/user/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const users = readUsers();
  const user = users.find(u => u.id === userId);

  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ message: 'User not found' });
  }
});

// Socket.io chat handling
io.on('connection', (socket) => {
  logger.info('New WebSocket connection');

  socket.on('joinChat', ({ userId, username }) => {
    socket.join(userId.toString());
    logger.info('User joined chat', { userId, username });
  });

  socket.on('chatMessage', (msg) => {
    try {
      const { userId, username, text } = msg;
      let chat = readChat(userId);

      if (!chat.username) chat.username = username; // Set the username if not present

      const newMessage = { sender: username, text, timestamp: new Date().toISOString(), read: false };
      chat.messages.push(newMessage);
      chat.needsResponse = true; // Mark chat as needing response
      writeChat(chat);

      // Emit message to the specific user and staff room
      io.to(userId.toString()).emit('message', newMessage);
      io.to('staff').emit('newUserMessage', { userId, message: newMessage });

      // Send notification to staff using axios
      axios.post('https://ntfy.sh/golockedinstaff', 
        `New user message received:
From: ${username}
Message: ${text}
Time: ${new Date().toLocaleString()}`,
        {
          headers: {
            'Title': `From: ${username}`,
            'Priority': 'high',
            'Tags': 'speech_balloon,exclamation',
            'Click': 'https://chat.golockedin.com/staff.html',
            'Actions': 'view, Open Staff Chat, https://chat.golockedin.com/staff.html'
          }
        })
        .then(response => {
          logger.info('Notification sent successfully', { response: response.data });
        })
        .catch(error => {
          logger.error('Error sending notification', { error });
        });

      logger.info('Chat message sent', { userId, username });
    } catch (error) {
      logger.error('Error processing chat message', { error });
    }
  });

  socket.on('responseMessage', (msg) => {
    try {
      const { userId, text, staffUsername } = msg;
      if (chatLocks[userId] && chatLocks[userId] !== socket.id) {
        socket.emit('lockError', { message: 'This chat is locked by another staff member.' });
        return;
      }
      chatLocks[userId] = socket.id;

      let chat = readChat(userId);
      const newMessage = { sender: 'Staff', text, timestamp: new Date().toISOString(), read: false };
      chat.messages.push(newMessage);
      chat.needsResponse = false; // Mark chat as responded to
      writeChat(chat);

      io.to(userId.toString()).emit('message', newMessage);
      io.to('staff').emit('staffMessageSent', { userId, message: newMessage });

      // Send notification to staff using axios
      axios.post('https://ntfy.sh/golockedinstaff', {
        title: 'Staff Response Sent',
        message: `Staff (${staffUsername}) responded to ${chat.username}: ${text}`,
        priority: 'high'
      })
      .then(response => {
        logger.info('Notification sent successfully', { response: response.data });
      })
      .catch(error => {
        logger.error('Error sending notification', { error });
      });

      logger.info('Staff response sent', { userId });
    } catch (error) {
      logger.error('Error processing staff response', { error });
    }
  });

  socket.on('staffJoin', () => {
    socket.join('staff');
    logger.info('Staff joined chat');
  });

  socket.on('markAsRead', (userId) => {
    try {
      let chat = readChat(userId);

      if (chat) {
        chat.messages.forEach((message) => {
          if (message.sender !== 'Staff') {
            message.read = true;
          }
        });
        writeChat(chat);
        logger.info('Messages marked as read', { userId });
      } else {
        logger.warn('Chat not found for marking as read', { userId });
      }
    } catch (error) {
      logger.error('Error marking messages as read', { error });
    }
  });

  socket.on('staffViewing', ({ userId }) => {
    socket.join(`viewing_${userId}`);
    const room = io.sockets.adapter.rooms.get(`viewing_${userId}`);
    const size = room ? room.size : 0;
    io.to('staff').emit('viewingCount', { userId, count: size });
  });

  socket.on('stopViewing', ({ userId }) => {
    socket.leave(`viewing_${userId}`);
    const room = io.sockets.adapter.rooms.get(`viewing_${userId}`);
    const size = room ? room.size : 0;
    io.to('staff').emit('viewingCount', { userId, count: size });
  });

  socket.on('sharedTextboxUpdate', ({ userId, text, typingStaff }) => {
    io.to(`viewing_${userId}`).emit('sharedTextboxUpdate', { userId, text, typingStaff });
  });

  socket.on('disconnect', () => {
    logger.info('User disconnected');
    // Remove locks held by the disconnected staff member
    Object.keys(chatLocks).forEach((userId) => {
      if (chatLocks[userId] === socket.id) {
        delete chatLocks[userId];
      }
    });
  });
});

app.post('/api/subscribe', (req, res) => {
  const { email } = req.body;

  // Basic email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email address' });
  }

  const subscribersFile = path.join(__dirname, 'data', 'subscribers.json');

  // Read existing subscribers, if file exists
  let subscribers = [];
  if (fs.existsSync(subscribersFile)) {
    const fileContent = fs.readFileSync(subscribersFile, 'utf-8');
    subscribers = JSON.parse(fileContent);
  }

  // Avoid duplicate email entries
  if (subscribers.includes(email)) {
    return res.status(409).json({ message: 'Email already subscribed' });
  }

  // Add new email and save
  subscribers.push(email);
  fs.writeFileSync(subscribersFile, JSON.stringify(subscribers, null, 2));

  res.status(200).json({ message: 'Subscription successful' });
});


const PORT = process.env.PORT || 3009;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});