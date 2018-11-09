const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const os = require('os');

module.exports = {
    generate: function(options, ...domains) {
        return new Promise((resolve, reject) => {
            if(!options) {
                options = {
                    useAvailableIps: true
                }
            }

            const mainDomain = domains.pop();

            let validFrom = new Date();

            // If no attributes passed in, generate them automatically
            if(!options.attributes) {
                options.attributes = [{ name: 'commonName', value: mainDomain }]
            }

            var keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1}, function(err, keypair) {
                if(err) {
                    return reject(err);
                }

                let signingKey = keypair.privateKey;
                let issuer = options.attributes;

                if(options.ca) {
                    const caPrivateKey = forge.pki.privateKeyFromPem(options.ca.privateKey)
                    const caCertificate = forge.pki.certificateFromPem(options.ca.certificate);

                    signingKey = caPrivateKey;
                    issuer = caCertificate.issuer.attributes;
                }

                let cert = forge.pki.createCertificate();
                cert.publicKey = keypair.publicKey;
                cert.serialNumber = '01';
                cert.validity.notBefore = new Date();
                cert.validity.notAfter = new Date();
                cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);

                cert.setSubject(options.attributes);
                cert.setIssuer(issuer);
    
                let subjectAlternateName = {
                name: 'subjectAltName',
                altNames: [{
                    type: 2, // DNS
                    value: mainDomain
                    }]
                }

                domains.forEach(domain => {
                    subjectAlternateName.altNames.push({
                        type: 2,
                        value: domain
                    })
                });

                if(options.useAvailableIps) {
                    let networks = os.networkInterfaces();
                    Object.values(networks).forEach(cardNetworks => {
                        cardNetworks
                        .filter(cn => {
                            return cn.family == 'IPv4'
                        })
                        .forEach(cn => {
                            let address = cn.address;
                            subjectAlternateName.altNames.push({
                                type: 7,
                                ip: address
                            })
                        })
                    });
                }

                cert.setExtensions([{
                    name: 'basicConstraints',
                    cA: true
                }, {
                    name: 'keyUsage',
                    keyCertSign: true,
                    digitalSignature: true,
                    nonRepudiation: true,
                    keyEncipherment: true,
                    dataEncipherment: true
                }, {
                    name: 'extKeyUsage',
                    serverAuth: true,
                    clientAuth: true,
                    codeSigning: true,
                    emailProtection: true,
                    timeStamping: true
                }, {
                    name: 'nsCertType',
                    client: true,
                    server: true,
                    email: true,
                    objsign: true,
                    sslCA: true,
                    emailCA: true,
                    objCA: true
                }, subjectAlternateName, {
                    name: 'subjectKeyIdentifier'
                }]);
                
                cert.sign(signingKey, forge.md.sha256.create());

                resolve({ 
                    key: forge.pki.privateKeyToPem(keypair.privateKey), 
                    certificate: forge.pki.certificateToPem(cert)
                });
            });
        });
    }
}