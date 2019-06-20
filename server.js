const app = require("./app.js");
const config = require("./config");

const fs = require('fs');

if (config.ssl) {
    const https = require('https');
    const privateKey = fs.readFileSync(config.sslKey, 'utf8');
    const certificate = fs.readFileSync(config.sslCert, 'utf8');
    const credentials = { key: privateKey, cert: certificate };
    const httpsServer = https.createServer(credentials, app);
    httpsServer.listen(8443, () => {
        console.log("We're live on port 8443 [HTTPS]");
    });
} else {
    const http = require('http');
    const httpServer = http.createServer(app);
    httpServer.listen(8000, () => {
        console.log("We're live on port 8000 [HTTP]");
    });
}

// app.listen(8000, () => {
//     console.log("We're live on port 8000 bois");
// });