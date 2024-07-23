const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const chatsFilePath = path.join(__dirname, '../data/chats.json');

const readChats = () => {
    const chatsData = fs.readFileSync(chatsFilePath);
    return JSON.parse(chatsData);
};

const writeChats = (chats) => {
    fs.writeFileSync(chatsFilePath, JSON.stringify(chats, null, 2));
};

router.get('/dashboard', (req, res) => {
    const chats = readChats();
    res.json(chats);
});

router.post('/respond', (req, res) => {
    const { userId, response } = req.body;
    const chats = readChats();
    const chat = chats.find(chat => chat.userId === userId);

    if (chat) {
        chat.responses.push(response);
        writeChats(chats);
        return res.status(200).json({ message: 'Response sent' });
    }

    res.status(400).json({ message: 'Chat not found' });
});

module.exports = router;
