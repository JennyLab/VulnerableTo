/*
   ExpressJS: Vulnerable to Parameter Polutions 


Payload:

{
  "__proto__": {
    "isAdmin": true
  }
}


*/

const express = require('express');
const app = express();
app.use(express.json());

let systemConfig = { status: "active" };

function merge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

app.post('/settings', (req, res) => {
    const userSettings = req.body;
    const profile = {};
    
    merge(profile, userSettings);
    
    res.json({ success: true });
});

app.listen(3000);
