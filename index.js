const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());


app.listen(3000, () => console.log('Webhook server running on port 5000'));

app.get('/', async (req, res) => {
    try {

        const response = await axios.get(`http://3.111.41.177:8080/api/json`, {
            auth: {
                username: 'thecodingguy19',
                password: '117d8de29ef68dbb6a0a82a23b3118eab6'
            }
        });

        if (response.status === 200) {
            console.log("hua");
            return res.json({ success: true, message: 'Valid Token' });
        }
    } catch (error) {
        console.log("huahinhi");
        return res.status(403).json({ success: false, error: 'Invalid Token or Unauthorized' });
    }
});


