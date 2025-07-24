const express = require("express");
const app = express();
const port = 5000;

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello backend");
});

app.listen(port, () => console.log("server is running on port 5000"));
