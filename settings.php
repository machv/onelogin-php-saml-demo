<?php

    $spBaseUrl = 'https://saml.mach.im'; //or http://<your_domain>

    $settingsInfo = array (
	// If 'strict' is True, then the PHP Toolkit will reject unsigned
        // or unencrypted messages if it expects them signed or encrypted
	// Also will reject the messages if not strictly follow the SAML
        // standard: Destination, NameId, Conditions ... are validated too.
	'strict' => true,

	'debug' => true,

        'contactPerson' => array (
	    'technical' => array (
    		'givenName' => 'Vladimir Mach',
        	'emailAddress' => 'vladimir@mach.im'
    	    ),
    	    'support' => array (
        	'givenName' => 'Vladimir Mach',
        	'emailAddress' => 'vladimir@mach.im'
    	    ),
	),

        // Organization information template, the info in en_US lang is recomended, add more if required
	'organization' => array (
            'en-US' => array(
	        'name' => 'UAM Czech Republic s.r.o.',
    	        'displayname' => 'UAM Czech Republic s.r.o.',
                'url' => 'https://www.uam.im/'
	    ),
        ),

	'security' => array (
	    // Algorithm that the toolkit will use on signing process. Options:
            //    'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
	    //    'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
            //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
	    //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
            //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
	    // Notice that sha1 is a deprecated algorithm and should not be used
            'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',

            // Algorithm that the toolkit will use on digest process. Options:
	    //    'http://www.w3.org/2000/09/xmldsig#sha1'
	    //    'http://www.w3.org/2001/04/xmlenc#sha256'
            //    'http://www.w3.org/2001/04/xmldsig-more#sha384'
    	    //    'http://www.w3.org/2001/04/xmlenc#sha512'
	    // Notice that sha1 is a deprecated algorithm and should not be used
            'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',

    	    // Indicates whether the <samlp:logoutRequest> messages sent by this SP
	    // will be signed.
            'logoutRequestSigned' => true,

    	    // Indicates whether the <samlp:logoutResponse> messages sent by this SP
	    // will be signed.
            'logoutResponseSigned' => true,

	    // Sign metadata
	    'signMetadata' => true,

	    // ADFS URL-Encodes SAML data as lowercase, and the toolkit by default uses
	    // uppercase. Turn it True for ADFS compatibility on signature verification
            'lowercaseUrlencoding' => true,
	),

        'sp' => array (
            'entityId' => $spBaseUrl . '/metadata.php',
            'assertionConsumerService' => array (
                'url' => $spBaseUrl . '/index.php?acs',
            ),
            'singleLogoutService' => array (
                'url' => $spBaseUrl . '/index.php?sls',
            ),
            'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        ),
        'idp' => array (
            'entityId' => 'https://sts.aps-holding.com/adfs/services/trust',
            'singleSignOnService' => array (
                'url' => 'https://sts.aps-holding.com/adfs/ls/',
            ),
            'singleLogoutService' => array (
                'url' => 'https://sts.aps-holding.com/adfs/ls/',
            ),
            'x509cert' => '-----BEGIN CERTIFICATE-----
MIIC4jCCAcqgAwIBAgIQSInpDt4Tm75LljDzYxZPKDANBgkqhkiG9w0BAQsFADAt
MSswKQYDVQQDEyJBREZTIFNpZ25pbmcgLSBzdHMuYXBzLWhvbGRpbmcuY29tMB4X
DTE4MDIxNTEwMzAzOFoXDTE5MDIxNTEwMzAzOFowLTErMCkGA1UEAxMiQURGUyBT
aWduaW5nIC0gc3RzLmFwcy1ob2xkaW5nLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALsin4AmbIVcH6EtVTh9ZsvQJ18J4Hvgprs3XjKEPWEX9yaK
/DgR8zyOmmHvoxoMgiayg6GFCt4kcB4uSf8dSY1GxNYJruvQ+0a/Pk9y6AwC5r9F
aN0oA+DsiiJ5SVIKUtmNCe0RR8u2UZN4H983Zg/0foddKbKDdQu8YhUwxHxvi9Zh
CwQNQZxvBORgyFhLTOvDIFdafr6rLYQx8bJcDlIQ0D00wGuDLt0ZmjSUjWeeF3CU
zSftTvxJo0gd9b4tpBZZ+RfefGskV4c7kaXZcK8E7klSsbW0GsyEHG/hGrbIyHWa
KL1dgbrRsz6p+nxhmsxDrWUeVWnE2w/D1s6v9EMCAwEAATANBgkqhkiG9w0BAQsF
AAOCAQEAeXXLv5MZX+F3jLkaZcFoiE+1W5t6Ez5KyToKsgpUAL8I4rwxdaYw/eCL
agZ8+R5qhSR7jzdiAtUnsV3fw0bxdYCROvV3bnN0+6UzyRisJGOclX0zWDgCTXAt
JhA4jlAPU4+ZLAen/j5qQsOyGCCfU3nhtlQAtbMJ1yOY+5mqkJJLBiv4JuckG7ok
khdXDwU6oDd7VqXcWN1eVS/WSmDMsM5hSBJt03pcaV5/SZ8PlQcj9Cw2g28gWZob
zZAXWVB36RX5ZZvl3zkO9geIiLvU5HVQNeifgCCut+kwT7D501m2t6ldyXFa6R5W
eALGdG7G+czLNLfvqoGlZKr3p234bg==
-----END CERTIFICATE-----',
        ),
    );
