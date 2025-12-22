const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET_TOKEN || 'changeme';

// Whitelisted command names (first token only)
const WHITELIST = new Set(['dir','ipconfig','echo','ping','whoami','ver']);

app.use(cors());
app.use(express.json());

// Serve static site from current directory
app.use(express.static(path.join(__dirname)));

function containsDangerousChars(s){
  return /[&|;<>`$]/.test(s);
}

app.post('/run', (req, res) => {
  const token = req.headers['x-secret-token'] || req.body.token;
  if(!token || token !== SECRET){
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const cmd = (req.body && req.body.cmd) ? String(req.body.cmd).trim() : '';
  if(!cmd) return res.status(400).json({ error: 'No command provided' });
  if(containsDangerousChars(cmd)) return res.status(403).json({ error: 'Forbidden characters' });

  const first = cmd.split(/\s+/)[0].toLowerCase();
  if(!WHITELIST.has(first)) return res.status(403).json({ error: 'Command not allowed' });

  // Execute command
  exec(cmd, { windowsHide: true, timeout: 30000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
    if(err && err.killed){
      return res.status(500).json({ error: 'Command timed out' });
    }
    res.json({ stdout: stdout && String(stdout), stderr: stderr && String(stderr), code: err && err.code ? err.code : 0 });
  });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
