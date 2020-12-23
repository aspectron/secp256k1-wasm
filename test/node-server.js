const express = require('express');
const path = require('path');
const app = express()
const port = 3000;
const HTTP = path.join(__dirname,"..","http");

app.get('/', (req, res) => {
  res.sendFile(path.join(HTTP, "index.html"));
})

app.use(express.static(HTTP))

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})

