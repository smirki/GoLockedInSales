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

// Socket.io chat handling
io.on('connection', socket => {
    logger.info('New WebSocket connection');
  
    socket.on('joinChat', ({ userId, username }) => {
      socket.join(userId.toString());
      logger.info('User joined chat', { userId, username });
    });
  
    socket.on('chatMessage', msg => {
      try {
        const { userId, username, text } = msg;
        let chat = readChat(userId);
  
        if (!chat.username) chat.username = username; // Set the username if not present
  
        const newMessage = { sender: username, text, timestamp: new Date().toISOString(), read: false };
        chat.messages.push(newMessage);
        chat.needsResponse = true; // Mark chat as needing response
        writeChat(chat);
  
        io.to(userId.toString()).emit('message', newMessage);
        io.to('staff').emit('newUserMessage', { userId, message: newMessage });
        logger.info('Chat message sent', { userId, username });
      } catch (error) {
        logger.error('Error processing chat message', { error });
      }
    });
  
    socket.on('responseMessage', msg => {
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
        logger.info('Staff response sent', { userId });
      } catch (error) {
        logger.error('Error processing staff response', { error });
      }
    });
  
    socket.on('staffJoin', () => {
      socket.join('staff');
      logger.info('Staff joined chat');
    });
  
    socket.on('markAsRead', userId => {
      try {
        let chat = readChat(userId);
  
        if (chat) {
          chat.messages.forEach(message => {
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
      Object.keys(chatLocks).forEach(userId => {
        if (chatLocks[userId] === socket.id) {
          delete chatLocks[userId];
        }
      });
    });
  });

const PORT = process.env.PORT || 3009;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
