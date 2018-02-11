# SSL Certificate information to JSON Microservice

Returns information about an SSL/TLS-Server and its certificate as JSON

## Usage

/ returns empty response (for healthcheck)

/<host>
/<host>:<port>

returns certificate information, like:

{
    "application_layer_protocol_negotiated": "http/1.1",
    "certificate": {
        "authorityInfoAccess": [
            {
                "access_location": "http://ocsp.int-x3.letsencrypt.org",
                "access_method": "OCSP"
            },
            {
                "access_location": "http://cert.int-x3.letsencrypt.org/",
                "access_method": "caIssuers"
            }
        ],
        "basicConstraints": {
            "ca": false,
            "path_length": null
        },
        "extendedKeyUsage": [
            "serverAuth",
            "clientAuth"
        ],
        "issuer": {
            "commonName": "Let's Encrypt Authority X3",
            "countryName": "US",
            "organizationName": "Let's Encrypt"
        },
        "keyUsage": {
            "content_commitment": false,
            "crl_sign": false,
            "data_encipherment": false,
            "decipher_only": false,
            "digital_signature": true,
            "encipher_only": false,
            "key_agreement": false,
            "key_cert_sign": false,
            "key_encipherment": true
        },
        "not_valid_after": "2018-03-22T21:26:26",
        "not_valid_before": "2017-12-22T21:26:26",
        "serial_number": 342994684535136370675577034904416586964377,
        "signature": {
            "base64": "Wq36968zk1RrBpgIpurDd4sLlioCFbUCCUztmlR6fXD/E46u+VuNZzprtN5aXY8zdAT6MUXSNic96Z29wOIR3CpVFfNP2dgGnHF48qO3p+9T/9RxofzLne0fzUl2Q7Wx++pEYXWrOm1gopvbjLL79maX+jyJuGV2Twm1NJR0+zWJPXH2jKjq3fLnVX20qpbPKqcZpW/0nLFnDSFegsh2hCJYqLCobGRe3p4SWZXVAalSJRzmox1IjP3lXFx5Sp0AdoQ+VyRnd0XQl90XcobfUO1WiULx799XLShe7o4xMqvmsAm6KxLHFVXhXwRIcaWaZSRg1FER0xvWyi60qnLoNA==",
            "hex": "5aadfaf7af3393546b069808a6eac3778b0b962a0215b502094ced9a547a7d70ff138eaef95b8d673a6bb4de5a5d8f337404fa3145d236273de99dbdc0e211dc2a5515f34fd9d8069c7178f2a3b7a7ef53ffd471a1fccb9ded1fcd497643b5b1fbea446175ab3a6d60a29bdb8cb2fbf66697fa3c89b865764f09b5349474fb35893d71f68ca8eaddf2e7557db4aa96cf2aa719a56ff49cb1670d215e82c876842258a8b0a86c645ede9e125995d501a952251ce6a31d488cfde55c5c794a9d0076843e5724677745d097dd177286df50ed568942f1efdf572d285eee8e3132abe6b009ba2b12c71555e15f044871a59a652460d45111d31bd6ca2eb4aa72e834"
        },
        "signature_algorithm": "sha256WithRSAEncryption",
        "subject": {
            "commonName": "vshn.ch"
        },
        "subjectAltName": [
            "vshn.ch"
        ],
        "version": 2
    },
    "chain": [
        {
            "authorityInfoAccess": [
                {
                    "access_location": "http://ocsp.int-x3.letsencrypt.org",
                    "access_method": "OCSP"
                },
                {
                    "access_location": "http://cert.int-x3.letsencrypt.org/",
                    "access_method": "caIssuers"
                }
            ],
            "basicConstraints": {
                "ca": false,
                "path_length": null
            },
            "extendedKeyUsage": [
                "serverAuth",
                "clientAuth"
            ],
            "issuer": {
                "commonName": "Let's Encrypt Authority X3",
                "countryName": "US",
                "organizationName": "Let's Encrypt"
            },
            "keyUsage": {
                "content_commitment": false,
                "crl_sign": false,
                "data_encipherment": false,
                "decipher_only": false,
                "digital_signature": true,
                "encipher_only": false,
                "key_agreement": false,
                "key_cert_sign": false,
                "key_encipherment": true
            },
            "not_valid_after": "2018-03-22T21:26:26",
            "not_valid_before": "2017-12-22T21:26:26",
            "serial_number": 342994684535136370675577034904416586964377,
            "signature": {
                "base64": "Wq36968zk1RrBpgIpurDd4sLlioCFbUCCUztmlR6fXD/E46u+VuNZzprtN5aXY8zdAT6MUXSNic96Z29wOIR3CpVFfNP2dgGnHF48qO3p+9T/9RxofzLne0fzUl2Q7Wx++pEYXWrOm1gopvbjLL79maX+jyJuGV2Twm1NJR0+zWJPXH2jKjq3fLnVX20qpbPKqcZpW/0nLFnDSFegsh2hCJYqLCobGRe3p4SWZXVAalSJRzmox1IjP3lXFx5Sp0AdoQ+VyRnd0XQl90XcobfUO1WiULx799XLShe7o4xMqvmsAm6KxLHFVXhXwRIcaWaZSRg1FER0xvWyi60qnLoNA==",
                "hex": "5aadfaf7af3393546b069808a6eac3778b0b962a0215b502094ced9a547a7d70ff138eaef95b8d673a6bb4de5a5d8f337404fa3145d236273de99dbdc0e211dc2a5515f34fd9d8069c7178f2a3b7a7ef53ffd471a1fccb9ded1fcd497643b5b1fbea446175ab3a6d60a29bdb8cb2fbf66697fa3c89b865764f09b5349474fb35893d71f68ca8eaddf2e7557db4aa96cf2aa719a56ff49cb1670d215e82c876842258a8b0a86c645ede9e125995d501a952251ce6a31d488cfde55c5c794a9d0076843e5724677745d097dd177286df50ed568942f1efdf572d285eee8e3132abe6b009ba2b12c71555e15f044871a59a652460d45111d31bd6ca2eb4aa72e834"
            },
            "signature_algorithm": "sha256WithRSAEncryption",
            "subject": {
                "commonName": "vshn.ch"
            },
            "subjectAltName": [
                "vshn.ch"
            ],
            "version": 2
        },
        {
            "authorityInfoAccess": [
                {
                    "access_location": "http://isrg.trustid.ocsp.identrust.com",
                    "access_method": "OCSP"
                },
                {
                    "access_location": "http://apps.identrust.com/roots/dstrootcax3.p7c",
                    "access_method": "caIssuers"
                }
            ],
            "basicConstraints": {
                "ca": true,
                "path_length": 0
            },
            "cRLDistributionPoints": [
                {
                    "crl_issuer": null,
                    "full_name": [
                        "http://crl.identrust.com/DSTROOTCAX3CRL.crl"
                    ],
                    "reasons": null,
                    "relative_name": null
                }
            ],
            "issuer": {
                "commonName": "DST Root CA X3",
                "organizationName": "Digital Signature Trust Co."
            },
            "keyUsage": {
                "content_commitment": false,
                "crl_sign": true,
                "data_encipherment": false,
                "decipher_only": false,
                "digital_signature": true,
                "encipher_only": false,
                "key_agreement": false,
                "key_cert_sign": true,
                "key_encipherment": false
            },
            "not_valid_after": "2021-03-17T16:40:46",
            "not_valid_before": "2016-03-17T16:40:46",
            "serial_number": 13298795840390663119752826058995181320,
            "signature": {
                "base64": "3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJouM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwuX4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlGPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==",
                "hex": "dd33d711f3635838dd1815fb0955be7656b97048a56947277bc2240892f15a1f4a1229372474511c6268b8cd957067e5f7a4bc4e2851cd9be8ae879dead8ba5aa1019adcf0dd6a1d6ad83e57239ea61e04629affd705cab71f3fc00a48bc94b0b66562e0c154e5a32aad20c4e9e6bbdcc8f6b5c332a398cc77a8e67965072bcb28fe3a165281ce520c2e5f83e8d50633fb776cce40ea329e1f925c41c1746c5b5d0a5f33cc4d9fac38f02f7b2c629dd9a3916f251b2f90b119463df67e1ba67a87b9a37a6d18fa25a5918715e0f2162f58b0062f2c6826c64b98cdda9f0cf97f90ed434a12444e6f737a28eaa4aa6e7b4c7d87dde0c90244a787afc3345bb442"
            },
            "signature_algorithm": "sha256WithRSAEncryption",
            "subject": {
                "commonName": "Let's Encrypt Authority X3",
                "countryName": "US",
                "organizationName": "Let's Encrypt"
            },
            "version": 2
        }
    ],
    "cipher_bits": 128,
    "cipher_name": "ECDHE-RSA-AES128-GCM-SHA256",
    "cipher_version": "TLSv1.2",
    "client_ca_list": [],
    "peer_ip": "185.72.236.76",
    "peer_port": 443,
    "server_name": "vshn.ch",
    "state_string": "SSL negotiation finished successfully"
}
