const fs = require('fs');
const http = require('http');
const https = require('https');
const certificates = require('../src/certificates');
const forge = require('node-forge');

const certificateAttributes = [{
    name: 'commonName',
    value: 'localhost'
  }, {
    name: 'countryName',
    value: 'GB'
  }, {
    shortName: 'ST',
    value: 'Northamptonshire'
  }, {
    name: 'localityName',
    value: 'Corby'
  }, {
    name: 'organizationName',
    value: 'RS Components'
  }, {
    shortName: 'OU',
    value: 'Core Quality Team'
  }];

const ca = {
    privateKey: fs.readFileSync('/Users/c0953973/code/localhost-certificate-authority/ca/ca.key').toString(),
    certificate: fs.readFileSync('/Users/c0953973/code/localhost-certificate-authority/ca/ca.crt').toString()
};

certificates.generate({ useAvailableIps: true, attributes: certificateAttributes, ca: ca }, 'localhost', 'docker', 'web')
.then((cert) => {    
    var credentials = {
        key: cert.key, 
        cert: cert.certificate
    };

    var express = require('express');
    var app = express();
    const certificate = forge.pki.certificateFromPem(cert.certificate)
    
    app.get('/', (req,res) => {
        res.send(certificate);
    })
    
    var httpServer = http.createServer(app);
    var httpsServer = https.createServer(credentials, app);
    
    httpServer.listen(8080);
    httpsServer.listen(8443);

    console.log('Server is listeneing on https://localhost:8443');
})
