const express = require('express');
const app = express();

app.use(express.json());

app.post('/jenkins-webhook', (req, res) => {

    console.log('*********************************************************************:', req.body);
    res.status(200).send('Webhook received');
});

app.listen(3000, () => console.log('Webhook server running on port 3000'));

app.post('/webhook', (req, res) => {

    console.log('####################################################################:', req.body);
    res.status(200).send('Webhook received');
});
