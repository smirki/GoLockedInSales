const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const chatsFilePath = path.join(__dirname, '../data/chats.json');
const usersFilePath = path.join(__dirname, '../data/users.json');

const GROQ_API_KEY = "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";

const readChats = () => {
  const chatsData = fs.readFileSync(chatsFilePath);
  return JSON.parse(chatsData);
};

const readUsers = () => {
  const usersData = fs.readFileSync(usersFilePath);
  return JSON.parse(usersData);
};

router.get('/generate-response/:userId', async (req, res) => {
    const userId = parseInt(req.params.userId, 10);
    const chats = readChats();
    const users = readUsers();
    const chat = chats.find(chat => chat.userId === userId);
    const user = users.find(user => user.id === userId);
  
    if (!chat || !user) {
      return res.status(404).json({ message: 'Chat or user not found' });
    }
  
    const last15Messages = chat.messages.slice(-15).map(msg => msg.text).join('\n');
    const userGoals = user.goals;
  
    try {
      const response = await axios.post(
        'https://api.groq.com/openai/v1/chat/completions',
        {
          messages: [
            {
              role: 'system',
              content: `User's goals: ${userGoals}`,
            },
            {
              role: 'user',
              content: last15Messages,
            }
          ],
          model: 'llama3-8b-8192',
        },
        {
          headers: {
            'Authorization': `Bearer ${GROQ_API_KEY}`,
            'Content-Type': 'application/json',
          }
        }
      );
  
      if (!response.data || !response.data.choices || !response.data.choices.length) {
        throw new Error('Invalid response from Groq API');
      }
  
      const generatedResponse = response.data.choices[0].message.content;
      res.json({ response: generatedResponse });
    } catch (error) {
      console.error('Error generating response:', error.response ? error.response.data : error.message);
      res.status(500).json({ message: 'Error generating response' });
    }
  });
  

module.exports = router;
