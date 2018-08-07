var express = require('express');
var app = express();
var path = require('path');

app.use(express.static(path.join(__dirname, 'public')))

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, "public/home.html"))
    
})

app.listen(8000, () => {
    console.log("server is running...")
})