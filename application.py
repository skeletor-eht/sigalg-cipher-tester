from flask import Flask, render_template, request, jsonify
import ssl
import socket
import datetime
import OpenSSL.crypto
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

application = Flask(__name__)
app = application

# class SecurityAnalyzer:
#     def __init__(self):
#         self.weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'CBC']
#         self.strong_ciphers = ['AES-256-GCM', 'CHACHA20', 'AES-256-CCM']
#         self.approved_curves = ['secp256r1', 'x25519', 'prime256v1']

#     def get_certificate_info(self, domain, port=443):
#         """Get SSL certificate and connection information"""
#         logger.debug(f"Attempting to get certificate info for {domain}")
#         try:
#             domain = domain.strip()
#             domain = domain.split('/')[0]  # Remove any paths
#             domain = domain.split(':')[0]  # Remove any ports
#             logger.debug(f"Cleaned domain name: {domain}")

#             context = ssl.create_default_context()
#             context.check_hostname = False
#             context.verify_mode = ssl.CERT_NONE

#             logger.debug(f"Attempting to connect to {domain}:{port}")
#             with socket.create_connection((domain, port), timeout=10) as sock:
#                 with context.wrap_socket(sock, server_hostname=domain) as ssock:
#                     logger.debug("Successfully wrapped socket")
                    
#                     cipher = ssock.cipher()
#                     cipher_name = cipher[0].decode('utf-8') if isinstance(cipher[0], bytes) else cipher[0]
#                     logger.debug(f"Cipher: {cipher_name}")

#                     cert_binary = ssock.getpeercert(binary_form=True)
#                     cert = OpenSSL.crypto.load_certificate(
#                         OpenSSL.crypto.FILETYPE_ASN1,
#                         cert_binary
#                     )
#                     logger.debug("Got certificate info")

#                     # Check if TLS 1.3
#                     is_tls13 = 'TLS_AES' in cipher_name or 'TLS_CHACHA20' in cipher_name
                    
#                     # For TLS 1.3, we can assume it's using secure curves
#                     if is_tls13:
#                         logger.debug("TLS 1.3 detected - assuming secure curves")
#                         curve_info = 'x25519'  # TLS 1.3 default
#                     else:
#                         # Try to get curve info from ciphersuite name
#                         curve_info = None
#                         if 'ECDHE' in cipher_name:
#                             if 'SECP256R1' in cipher_name or 'PRIME256V1' in cipher_name:
#                                 curve_info = 'secp256r1'
#                             elif 'X25519' in cipher_name:
#                                 curve_info = 'x25519'

#                     logger.debug(f"Determined curve: {curve_info}")

#                     return {
#                         'cert': cert,
#                         'tls_version': ssock.version(),
#                         'cipher_name': cipher_name,
#                         'cipher_bits': cipher[2],
#                         'ecdh_curve': curve_info,
#                         'is_tls13': is_tls13
#                     }

#         except Exception as e:
#             logger.error(f"Error for {domain}: {type(e).__name__}: {e}")
#             return None

#     def analyze_domain_security(self, domain):
#         """Perform security analysis for a single domain"""
#         try:
#             logger.info(f"Starting analysis for {domain}")
#             info = self.get_certificate_info(domain)
            
#             if not info:
#                 return {
#                     'domain': domain,
#                     'success': False,
#                     'error': 'Failed to get certificate information'
#                 }

#             cert = info['cert']
#             expiry_date = datetime.datetime.strptime(
#                 cert.get_notAfter().decode('ascii'),
#                 '%Y%m%d%H%M%SZ'
#             )

#             # If TLS 1.3, we can safely remove from proxy
#             can_remove_proxy = info['is_tls13']
            
#             # For TLS 1.2, check the curve
#             if not can_remove_proxy and info['ecdh_curve']:
#                 curve_lower = info['ecdh_curve'].lower()
#                 can_remove_proxy = any(curve in curve_lower for curve in self.approved_curves)

#             return {
#                 'domain': domain,
#                 'success': True,
#                 'tls_version': info['tls_version'],
#                 'cipher_suite': {
#                     'name': info['cipher_name'],
#                     'bits': info['cipher_bits'],
#                     'is_tls13': info['is_tls13']
#                 },
#                 'ecdh': {
#                     'curve': info['ecdh_curve'],
#                     'can_remove_proxy': can_remove_proxy
#                 },
#                 'certificate': {
#                     'valid_until': expiry_date.isoformat(),
#                     'days_until_expiry': (expiry_date - datetime.datetime.now()).days,
#                     'signature_algorithm': cert.get_signature_algorithm().decode('utf-8'),
#                     'serial_number': hex(cert.get_serial_number())
#                 }
#             }

#         except Exception as e:
#             logger.error(f"Error analyzing {domain}: {str(e)}", exc_info=True)
#             return {
#                 'domain': domain,
#                 'success': False,
#                 'error': str(e)
#             }
class SecurityAnalyzer:
    def __init__(self):
        # Supported signature algorithms
        self.supported_sig_algs = ['sha256WithRSAEncryption', 'ecdsa-with-SHA256']
        
        # Supported cipher suites
        self.supported_ciphers = [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA364',
            'ECDHE-ECDSA-AES256-SHA-256',
            'ECDHE-ECDSA-AES256-SHA-384'
        ]
        
        # Key size requirements
        self.rsa_key_size = 2048
        self.ecdsa_key_size = 256
    def get_certificate_info_with_restriction(self, domain, port=443):
        """Get SSL certificate info while forcing negotiation to SHA-256 only"""
        logger.debug(f"Attempting to get certificate info for {domain} with SHA-256 restriction")
        try:
            domain = domain.strip()
            domain = domain.split('/')[0]  # Remove any paths
            domain = domain.split(':')[0]  # Remove any ports
            
            # Create a custom context that only offers specific ciphers
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set cipher list to only include SHA-256 ciphers (no SHA-384)
            # This forces servers to negotiate down to SHA-256 if they can
            sha256_ciphers = [
                # TLS 1.3 ciphers with SHA-256
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA256',
                # Common TLS 1.2 ciphers with SHA-256
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES256-GCM-SHA256',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-GCM-SHA256',
                'DHE-RSA-AES128-GCM-SHA256',
                'DHE-RSA-AES256-GCM-SHA256'
            ]
            
            # Join with colons as required by OpenSSL cipher string format
            cipher_string = ':'.join(sha256_ciphers)
            context.set_ciphers(cipher_string)
            
            logger.debug(f"Using restricted cipher list: {cipher_string}")
            
            try:
                with socket.create_connection((domain, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cipher = ssock.cipher()
                        cipher_name = cipher[0].decode('utf-8') if isinstance(cipher[0], bytes) else cipher[0]
                        logger.debug(f"Negotiated cipher: {cipher_name}")
                        
                        # Continue with certificate extraction as before
                        cert_binary = ssock.getpeercert(binary_form=True)
                        cert = OpenSSL.crypto.load_certificate(
                            OpenSSL.crypto.FILETYPE_ASN1,
                            cert_binary
                        )
                        
                        # Get public key type and size
                        pubkey = cert.get_pubkey()
                        key_type = pubkey.type()
                        key_size = pubkey.bits()
                        
                        # Determine if key is RSA or ECDSA
                        is_rsa = key_type == OpenSSL.crypto.TYPE_RSA
                        is_ecdsa = key_type == OpenSSL.crypto.TYPE_EC
                        
                        # Get signature algorithm
                        sig_alg = cert.get_signature_algorithm().decode('utf-8')
                        
                        # Get peer signing digest
                        peer_signing_digest = None
                        if 'SHA256' in sig_alg:
                            peer_signing_digest = 'sha256'
                        elif 'SHA384' in sig_alg:
                            peer_signing_digest = 'sha384'
                        elif 'SHA512' in sig_alg:
                            peer_signing_digest = 'sha512'

                        return {
                            'cert': cert,
                            'tls_version': ssock.version(),
                            'cipher_name': cipher_name,
                            'key_type': 'RSA' if is_rsa else 'ECDSA' if is_ecdsa else 'UNKNOWN',
                            'key_size': key_size,
                            'sig_alg': sig_alg,
                            'peer_signing_digest': peer_signing_digest,
                            'can_downgrade_to_sha256': 'SHA256' in cipher_name
                        }
            except ssl.SSLError as e:
                logger.warning(f"SSL negotiation failed with restricted ciphers: {e}")
                return {
                    'error': 'Failed to negotiate with SHA-256 only ciphers',
                    'can_downgrade_to_sha256': False
                }

        except Exception as e:
            logger.error(f"Error for {domain}: {type(e).__name__}: {e}")
            return None

    def test_cipher_negotiation(self, domain):
        """Test if a domain can negotiate down to SHA-256 ciphers"""
        try:
            logger.info(f"Testing cipher negotiation for {domain}")
            
            # First try with default ciphers to see what it normally uses
            regular_info = self.get_certificate_info(domain)
            if not regular_info:
                return {
                    'domain': domain,
                    'success': False,
                    'error': 'Failed to connect with default settings'
                }
                
            # Now try with restricted SHA-256 ciphers
            restricted_info = self.get_certificate_info_with_restriction(domain)
            
            # Check if we got a connection
            can_use_sha256 = (restricted_info is not None and 
                             'error' not in restricted_info)
            
            # If we're already using SHA-256, mark as compatible
            if regular_info['peer_signing_digest'] == 'sha256':
                logger.info(f"{domain} already using SHA-256")
                can_use_sha256 = True
            
            return {
                'domain': domain,
                'success': True,
                'standard_connection': {
                    'tls_version': regular_info['tls_version'],
                    'cipher_suite': regular_info['cipher_name'],
                    'peer_signing_digest': regular_info['peer_signing_digest']
                },
                'sha256_negotiation': {
                    'can_use_sha256': can_use_sha256,
                    'negotiated_cipher': restricted_info['cipher_name'] if can_use_sha256 else None
                },
                'certificate': {
                    'key_type': regular_info['key_type'],
                    'key_size': regular_info['key_size'],
                    'signature_algorithm': regular_info['sig_alg']
                }
            }
        except Exception as e:
            logger.error(f"Error testing negotiation for {domain}: {str(e)}", exc_info=True)
            return {
                'domain': domain,
                'success': False,
                'error': str(e)
            }
    def get_certificate_info(self, domain, port=443):
        """Get SSL certificate and connection information"""
        logger.debug(f"Attempting to get certificate info for {domain}")
        try:
            domain = domain.strip()
            domain = domain.split('/')[0]  # Remove any paths
            domain = domain.split(':')[0]  # Remove any ports
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    cipher_name = cipher[0].decode('utf-8') if isinstance(cipher[0], bytes) else cipher[0]
                    
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert_binary
                    )

                    # Get public key type and size
                    pubkey = cert.get_pubkey()
                    key_type = pubkey.type()
                    key_size = pubkey.bits()
                    
                    # Determine if key is RSA or ECDSA
                    is_rsa = key_type == OpenSSL.crypto.TYPE_RSA
                    is_ecdsa = key_type == OpenSSL.crypto.TYPE_EC
                    
                    # Get signature algorithm
                    sig_alg = cert.get_signature_algorithm().decode('utf-8')
                    
                    # Get peer signing digest
                    peer_signing_digest = None
                    if 'SHA256' in sig_alg:
                        peer_signing_digest = 'sha256'
                    elif 'SHA384' in sig_alg:
                        peer_signing_digest = 'sha384'
                    elif 'SHA512' in sig_alg:
                        peer_signing_digest = 'sha512'

                    return {
                        'cert': cert,
                        'tls_version': ssock.version(),
                        'cipher_name': cipher_name,
                        'key_type': 'RSA' if is_rsa else 'ECDSA' if is_ecdsa else 'UNKNOWN',
                        'key_size': key_size,
                        'sig_alg': sig_alg,
                        'peer_signing_digest': peer_signing_digest
                    }

        except Exception as e:
            logger.error(f"Error for {domain}: {type(e).__name__}: {e}")
            return None

    def analyze_domain_security(self, domain):
        """Perform security analysis for a single domain"""
        try:
            logger.info(f"Starting analysis for {domain}")
            info = self.get_certificate_info(domain)
            
            if not info:
                return {
                    'domain': domain,
                    'success': False,
                    'error': 'Failed to get certificate information'
                }

            cert = info['cert']
            expiry_date = datetime.datetime.strptime(
                cert.get_notAfter().decode('ascii'),
                '%Y%m%d%H%M%SZ'
            )
            
            # Initialize security assessment
            can_remove_proxy = True
            security_notes = []
            
            # Check 1: Signature Algorithm
            if info['sig_alg'] not in self.supported_sig_algs:
                can_remove_proxy = False
                security_notes.append(f'Unsupported signature algorithm: {info["sig_alg"]}')

            # Check 2: Public Key Size
            if info['key_type'] == 'RSA':
                if info['key_size'] != self.rsa_key_size:
                    can_remove_proxy = False
                    security_notes.append(f'Invalid RSA key size: {info["key_size"]}. Must be exactly {self.rsa_key_size}')
            elif info['key_type'] == 'ECDSA':
                if info['key_size'] != self.ecdsa_key_size:
                    can_remove_proxy = False
                    security_notes.append(f'Invalid ECDSA key size: {info["key_size"]}. Must be exactly {self.ecdsa_key_size}')
            else:
                can_remove_proxy = False
                security_notes.append(f'Unsupported key type: {info["key_type"]}')

            # Check 3: Cipher Suite
            if info['cipher_name'] not in self.supported_ciphers:
                can_remove_proxy = False
                security_notes.append(f'Unsupported cipher suite: {info["cipher_name"]}')

            # Check 4: Peer Signing Digest
            if info['peer_signing_digest'] != 'sha256':
                can_remove_proxy = False
                security_notes.append(f'Unsupported peer signing digest: {info["peer_signing_digest"]}. Only SHA256 is supported')

            return {
                'domain': domain,
                'success': True,
                'tls_version': info['tls_version'],
                'cipher_suite': {
                    'name': info['cipher_name'],
                    'is_tls13': 'TLS_AES' in info['cipher_name'] or 'TLS_CHACHA20' in info['cipher_name']
                },
                'ecdh': {
                    'curve': None,  # We're not tracking curves anymore
                    'can_remove_proxy': can_remove_proxy  # Moved here to match expected structure
                },
                'certificate': {
                    'key_type': info['key_type'],
                    'key_size': info['key_size'],
                    'signature_algorithm': info['sig_alg'],
                    'peer_signing_digest': info['peer_signing_digest'],
                    'valid_until': expiry_date.isoformat(),
                    'days_until_expiry': (expiry_date - datetime.datetime.now()).days,
                    'serial_number': hex(cert.get_serial_number())
                },
                'security_notes': security_notes  # Added to provide detailed feedback
            }

        except Exception as e:
            logger.error(f"Error analyzing {domain}: {str(e)}", exc_info=True)
            return {
                'domain': domain,
                'success': False,
                'error': str(e)
            }
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        domains = request.form.get('domains', '').split(',')
        domains = [d.strip() for d in domains if d.strip()]
        
        if not domains:
            return jsonify({'error': 'No domains provided'})

        logger.info(f"Analyzing domains: {domains}")
        analyzer = SecurityAnalyzer()
        results = []
        
        for domain in domains:
            result = analyzer.analyze_domain_security(domain)
            results.append(result)
            logger.info(f"Analysis complete for {domain}: {'Success' if result['success'] else 'Failed'}")

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        logger.error(f"Error in analyze route: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)})
@app.route('/test-negotiation', methods=['POST'])
def test_negotiation():
    try:
        domains = request.form.get('domains', '').split(',')
        domains = [d.strip() for d in domains if d.strip()]
        
        if not domains:
            return jsonify({'error': 'No domains provided'})

        logger.info(f"Testing SHA-256 negotiation for domains: {domains}")
        analyzer = SecurityAnalyzer()
        results = []
        
        for domain in domains:
            result = analyzer.test_cipher_negotiation(domain)
            results.append(result)
            logger.info(f"Negotiation test complete for {domain}: {'Success' if result['success'] else 'Failed'}")

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        logger.error(f"Error in test-negotiation route: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)})
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)