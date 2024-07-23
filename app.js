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

// Setup Winston logger
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

const app = express();
const server = http.createServer(app);
const io = socketio(server);

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const usersFilePath = path.join(__dirname, 'data/users.json');
const chatsFilePath = path.join(__dirname, 'data/chats.json');

const readUsers = () => {
    try {
        const usersData = fs.readFileSync(usersFilePath);
        return JSON.parse(usersData);
    } catch (error) {
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

const readChats = () => {
    try {
        const chatsData = fs.readFileSync(chatsFilePath);
        return JSON.parse(chatsData);
    } catch (error) {
        logger.error('Error reading chats file', { error });
        return [];
    }
};

const writeChats = (chats) => {
    try {
        fs.writeFileSync(chatsFilePath, JSON.stringify(chats, null, 2));
    } catch (error) {
        logger.error('Error writing chats file', { error });
    }
};

const staffViewingChat = new Map(); // Track staff viewing each chat

// User routes
app.post('/api/users/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const users = readUsers();
        const userExists = users.find(user => user.username === username);

        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = users.length ? users[users.length - 1].id + 1 : 1;
        users.push({ id: userId, username, password: hashedPassword });
        writeUsers(users);

        logger.info('User registered', { userId, username });
        res.status(201).json({ message: 'User registered successfully' });
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
        logger.info('User logged in', { userId: user.id, username });
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
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, 'secret');
        req.user = decoded;
        next();
    } catch (err) {
        logger.error('Invalid token', { error: err });
        return res.status(401).json({ message: 'Invalid token' });
    }
};

app.get('/api/users/me', verifyToken, (req, res) => {
    res.json({ id: req.user.id, username: req.user.username });
});

app.get('/api/staff/dashboard', verifyToken, (req, res) => {
    const chats = readChats();
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
            const chats = readChats();
            const { userId, username, text } = msg;
            let chat = chats.find(chat => chat.userId === userId);

            if (!chat) {
                chat = { userId, username, messages: [], needsResponse: true };
                chats.push(chat);
            } else {
                chat.needsResponse = true; // Mark chat as needing a response
            }

            const newMessage = { sender: username, text, timestamp: new Date().toISOString(), read: false };
            chat.messages.push(newMessage);
            writeChats(chats);

            io.to(userId.toString()).emit('message', newMessage);
            io.to('staff').emit('newUserMessage', { userId, message: newMessage });
            logger.info('Chat message sent', { userId, username });
        } catch (error) {
            logger.error('Error processing chat message', { error });
        }
    });

    socket.on('responseMessage', msg => {
        try {
            const chats = readChats();
            const { userId, text } = msg;
            const chat = chats.find(chat => chat.userId === userId);

            if (chat) {
                const newMessage = { sender: 'Staff', text, timestamp: new Date().toISOString(), read: false };
                chat.messages.push(newMessage);
                chat.needsResponse = false; // Mark chat as responded to
                writeChats(chats);
                io.to(userId.toString()).emit('message', newMessage);
                io.to('staff').emit('staffMessageSent', { userId, message: newMessage });
                logger.info('Staff response sent', { userId });
            } else {
                logger.warn('Chat not found for staff response', { userId });
            }
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
            const chats = readChats();
            const chat = chats.find(chat => chat.userId === userId);

            if (chat) {
                chat.messages.forEach(message => {
                    if (message.sender !== 'Staff') {
                        message.read = true;
                    }
                });
                writeChats(chats);
                logger.info('Messages marked as read', { userId });
            } else {
                logger.warn('Chat not found for marking as read', { userId });
            }
        } catch (error) {
            logger.error('Error marking messages as read', { error });
        }
    });

    socket.on('staffViewing', ({ userId }) => {
        if (!staffViewingChat.has(userId)) {
            staffViewingChat.set(userId, 0);
        }
        staffViewingChat.set(userId, staffViewingChat.get(userId) + 1);
        io.to('staff').emit('viewingCount', { userId, count: staffViewingChat.get(userId) });
    });

    socket.on('stopViewing', ({ userId }) => {
        if (staffViewingChat.has(userId)) {
            staffViewingChat.set(userId, staffViewingChat.get(userId) - 1);
            io.to('staff').emit('viewingCount', { userId, count: staffViewingChat.get(userId) });
        }
    });

    socket.on('sharedTextboxUpdate', ({ userId, text }) => {
        io.to('staff').emit('sharedTextboxUpdate', { userId, text });
    });
    

    socket.on('disconnect', () => {
        logger.info('User disconnected');
        // Handle disconnecting staff members from the chat viewing count
        // This is just a placeholder, additional logic to determine the userId might be needed
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});
