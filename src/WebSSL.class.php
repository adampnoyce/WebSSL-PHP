<?php
/**
 * 	PHP class for WebSSL
 *	WebSSL is a cryptographic library built to run within a Hardware Security Module and provides a universally accessible interface.
 */
class WebSSLException extends Exception { }
 
class WebSSL {

	public $debug = false;

	private $hsmAddress; 

	public function __construct(string $hsmAddress) {
		if(!empty($hsmAddress)) {
			$hsmAddress = rtrim($hsmAddress,"/");
			if (!filter_var($hsmAddress, FILTER_VALIDATE_URL)) throw new WebSSLException('Invalid HSM Address: ' . $hsmAddress);
			$this->hsmAddress = $hsmAddress;
		} else { 
			// Set to default address
			$this->hsmAddress = "https://c1.cloudhsms.com";
		}
	}
	
	/**
	 * Send curl request and return
	 */
	protected function send($url, array $jsonData) {
		
		if($this->debug) error_log("URL: " . $url);

		//Initiate cURL.
		$ch = curl_init($url);

		if(!empty($jsonData)) {
			//Encode the array into JSON.
			$jsonDataEncoded = json_encode($jsonData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS);
			$jsonDataEncoded = str_replace(array("\\\\n", "\\\n", "\\n", "\\r\n"), "\n", $jsonDataEncoded);

			if($this->debug) error_log("Debug: JSON Request: " . $jsonDataEncoded);
			 
			curl_setopt_array($ch, array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_ENCODING => "",
				CURLOPT_MAXREDIRS => 10,
				CURLOPT_TIMEOUT => 0,
				CURLOPT_FOLLOWLOCATION => false,
				CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
				CURLOPT_CUSTOMREQUEST => "POST",
				CURLOPT_POSTFIELDS => $jsonDataEncoded,
				CURLOPT_HTTPHEADER => array(
					"Content-Type: application/json"
				),
			));
		} else {
			curl_setopt_array($ch, array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_ENCODING => "",
				CURLOPT_MAXREDIRS => 10,
				CURLOPT_TIMEOUT => 0,
				CURLOPT_FOLLOWLOCATION => false,
				CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
				CURLOPT_CUSTOMREQUEST => "GET",
			));
		}
		 
		//Execute the request
		$response 	= curl_exec($ch);
		$err 		= curl_error($ch);
		if($err) throw new WebSSLException('Curl Error: ' . $err);	

		//Get last HTTP status code
		$http_code = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		if($http_code != "200" ) throw new WebSSLException('HTTP Response: ' . $http_code);

		// Check body has something in it
		if(!$response) throw new WebSSLException('Empty Response.');
		
		// Close channel
		curl_close($ch);

		//Decode the JSON array
		$result = json_decode($response, true);

		return $result;
	}

	public function getHsmInfo() {

		$url = $this->hsmAddress . "/hsm/info";

		$result = $this->send($url, array());

		if(!array_key_exists("id", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		if(!array_key_exists("type", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		
		return $result;
	}

	public function getHsmStatus() {

		$url = $this->hsmAddress . "/hsm/status";

		$result = $this->send($url, array());

		if(!array_key_exists("temperature", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		if(!array_key_exists("batteryVoltage", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		if(!array_key_exists("freeMemory", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		if(!array_key_exists("usedMemory", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		
		return $result;
	}
	
	 /**
	 * Generates a cryptographic key pair inside a HSM. The private key is AES encrypted by a HSM and returned in a 
	 * PEM encoded encrypted private key structure. * The public key is returned PEM encoded.
	 *
	 * $algorithm -- Type: String Required: yes Description: Algorithms (rsa-2048, rsa-4096, ecc-p256, rsa-p521).
	 */
	public function genpkeyGenerateKey($algorithm) {
		
		$url = $this->hsmAddress . "/genpkey";
		 
		//The JSON data.
		$jsonData = array(
			'algorithm' => $algorithm
		);
		
		$result = $this->send($url, $jsonData);

		if(!array_key_exists("privateKey", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		if(!array_key_exists("publicKey", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		
		return $result;
	}
	
	 /**
	 * Signs a Certifcate Signing Request (CSR) in the HSM and composes an x509 certificate.
	 *
	 * $days -- Type: String Required: yes Description: The number of days the certificate will be valid for.
	 * $digest -- Type: String Required: yes Description: CSR digest (sha-256)
	 * $csr -- Type: String Required: yes Description: Certificate Signing Request (PEM encoded)
	 * $signerCert -- Type: String Required: yes Description: Signers x509 certficate (PEM encoded)
	 * $inKey -- Type: String Required: yes Description: Signers key (PEM encoded encrypted private key)
	 */
	 
	public function x509SignCSR($days,$digest,$csr,$signerCert,$inKey) {
		
		$url = $this->hsmAddress . "/x509/signCsr";
		 
		//The JSON data.
		$jsonData = array(
			'days' => $days,
			'digest' => $digest,
			'csr' => $csr,
			'signerCert' => $signerCert,
			'inKey' => $inKey
			
		);

		$result = $this->send($url, $jsonData);

		if(!array_key_exists("certificate", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		
		$certificate = $result['certificate'];
		
		return $certificate;
	}
	
	 /**
	 * Generates a PKCS#10 Certificate Signing Request (CSR) within the HSM, by signing the applicants 
	 * distinguished name fields with their private key.
	 *
	 * $inKey -- Type: String Required: yes Description: Signers key (PEM encoded encrypted private key)
	 * $csrDigest -- Type: String Required: yes Description: CSR digest (sha-256)
	 * $dn -- Type: object Required: yes Description: CSR Distinguished names
	 */
	 
	public function reqGenerateCSR($inKey, $csrDigest, $dn) {
		
		$url = $this->hsmAddress . "/req/generateCsr";
		 
		//The JSON data.
		$jsonData = array(
		
			'inKey' => $inKey,
			'digest' => $csrDigest,
			'distinguishedNames' => $dn
			
		);
		 
		$result = $this->send($url, $jsonData);

		if(!array_key_exists("csr", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		 
		$csr = $result['csr'];

		return $csr;

	}
	

	
	/**
	 * Signs data within a HSM as CMS signed-data content, using the signers encrypted private key and certificate.
	 *
	 * $data -- Type: String Required: yes Description: Data to sign (Base64 encoded)
	 * $signersKey -- Type: String Required: yes Description: Signers key (PEM encoded encrypted private key)
	 * $signerCert -- Type: object Required: yes Description: Signers Certificate (PEM encoded certificate)
	 */
	 
	public function cmsSign($data, $signersKey, $signerCert) {
		
		//Initiate cURL.
		$url = $this->hsmAddress . "/cms/sign";
		 
		//The JSON data.
		$jsonRequest = array(
			'digest' => "sha-256",
			'inKey' => $signersKey,
			'signer' => $signerCert,
			'in' => base64_encode($data)
		);
		 
		$result = $this->send($url, $jsonRequest);

		if(!array_key_exists("cms", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		 
		$cms = $result['cms'];

		//Remove CMS Header
		$cms = str_replace('-----BEGIN CMS-----', '', $cms);
		
		//Remove CMS Footer
		$cms = str_replace('-----END CMS-----', '', $cms);		
		return  $cms;	
	}

	/**
	 * 
	 *	
	 * 
	 * @param string $data the plaintext for encryption
	 * @param string $recipientCert a PEM encoded certificate used to encrypt 
	 * @return string a encoded PKCS#7/CMS envelopedData 
	 */
	public function cmsEncrypt($data, $recipientCert) {
		
		//Set the URL.
		$url = $this->hsmAddress . "/cms/encrypt";
		 
		//The JSON data.
		$jsonRequest = array(
			'algorithm' => "aes-128",
			'recip' => $recipientCert,
			'in' => base64_encode($data)
		);
		 
		$result = $this->send($url, $jsonRequest);

		if(!array_key_exists("cms", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		 
		$cms = $result['cms'];

		//Remove CMS Header
		$cms = str_replace('-----BEGIN CMS-----', '', $cms);
		
		//Remove CMS Footer
		$cms = str_replace('-----END CMS-----', '', $cms);		
		return  $cms;	
	}

	/**
	 * 
	 *	
	 * 
	 * @param string $data the plaintext for encryption
	 * @param string $recipientCert a PEM encoded certificate used to encrypt 
	 * @return string a encoded PKCS#7/CMS envelopedData 
	 */
	public function cmsSignAndEncrypt($data, $signersKey, $signerCert, $recipientCert) {
		
		//Set the URL.
		$url = $this->hsmAddress . "/cms/signEncrypt";
		 
		//The JSON data.
		$jsonRequest = array(
			'algorithm' => "aes-128",
			'digest' => "sha-256",
			'inKey' => $signersKey,
			'signer' => $signerCert,
			'recip' => $recipientCert,
			'in' => base64_encode($data)
		);
		 
		$result = $this->send($url, $jsonRequest);

		if(!array_key_exists("cms", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		 
		$cms = $result['cms'];

		//Remove CMS Header
		$cms = str_replace('-----BEGIN CMS-----', '', $cms);
		
		//Remove CMS Footer
		$cms = str_replace('-----END CMS-----', '', $cms);		
		return  $cms;	
	}

	/**
	 * Generates a key pair within the HSM and self signed certificate.
	 *
	 * $algorithm -- Type: String Required: yes Description: Algorithms (rsa-2048, rsa-4096, ecc-p256, ecc-p521).
	 * $certDays -- Type: String Required: yes Description: The number of days the certificate will be valid for.
	 * $csrDigest -- Type: object Required: yes Description: CSR digest (sha-256)
	 * $certSubjectType -- Type String Required: yes Description: Certificate subject type (CA, End Entity)
	 * $dn -- Type: object Required: yes Description: CSR Distinguished names
	 */
	 
	public function reqGenKeyCert(string $algorithm, string $days, array $subject, array $keyUsage, array $enhancedKeyUsage, array $basicConstraints) {
		
		$url = $this->hsmAddress . "/req/generateKeyCert";
		 
		//The JSON data.
		$jsonData = array(
			'algorithm' => $algorithm,
			'days' => $days,
			'digest' => "sha-256",
			'subject' => $subject,
			'keyUsage' => $keyUsage,
			'enhancedKeyUsage' => $enhancedKeyUsage,
			'basicConstraints' => $basicConstraints
		);
		 
		$result = $this->send($url, $jsonData);

		if(!array_key_exists("privateKey", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		if(!array_key_exists("certificate", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		 
		$privateKey = $result['privateKey'];
		$certificate = $result['certificate'];
		
		return $result;

	}


	/**
	 * reqGenerateKeyAndSignedCertificate
	 *	
	 * 
	 * @param 
	 * @param  
	 * @return 
	 */
	public function reqGenerateKeyAndSignedCertificate(string $password, string $algorithm, string $signersKey, string $signerCert,
		string $days, array $subject, array $keyUsage, array $enhancedKeyUsage, array $basicConstraints) {
		
		//Set the URL.
		$url = $this->hsmAddress . "/req/generateKeySignedCert";
		 
		//The JSON data.
		$jsonRequest = array(
			'password' => $password,
			'signerCert' => $signerCert,
			'inKey' => $signersKey,
			'algorithm' => $algorithm,
			'days' => $days,
			'digest' => "sha-256",
			'subject' => $subject,
			'keyUsage' => $keyUsage,
			'enhancedKeyUsage' => $enhancedKeyUsage,
			'basicConstraints' => $basicConstraints
		);
		 
		$result = $this->send($url, $jsonRequest);

		if(!array_key_exists("pkcs12", $result)) throw new WebSSLException('Missing Key in JSON Response.');
		 
		return  $result['pkcs12'];
	}
	
	/**
	 * reqDecodeCSR
	 *	
	 * $csr a PEM encoded certificate signing request
	 */
	public function reqDecodeCSR(string $csr){
		
		//Set the URL.
		$url = $this->hsmAddress . "/req/decodeCsr";
		
		//The JSON data.
		$jsonRequest = array(
			'csr' => $csr
		);
		
		$result = $this->send($url, $jsonRequest);
		
		return $result;
	}
	
	/**
	 * x509DecodeCertificate
	 *	
	 * $certificate a PEM encoded certificate 
	 */
	public function x509DecodeCertificate(string $certificate){
		
		//Set the URL.
		$url = $this->hsmAddress . "/x509/decodeCert";
		
		//The JSON data.
		$jsonRequest = array(
			'certificate' => $certificate,
		);
		
		$result = $this->send($url, $jsonRequest);
		
		return $result;
	}

	// Using the values set in enchanced key usage determine what should be set in the standard key usage
	public static function determineKeyUsage(array $enhancedKeyUsage) {
		$keyUsage = array();

		if(in_array('clientAuthentication', $enhancedKeyUsage)) {
			array_push($keyUsage, "digitalSignature");
			array_push($keyUsage, "keyEncipherment");
			array_push($keyUsage, "keyAgreement");
		}

		if(in_array('serverAuthentication', $enhancedKeyUsage)) {
			array_push($keyUsage, "digitalSignature");
			array_push($keyUsage, "keyAgreement");
		}

		if(in_array("emailProtection", $enhancedKeyUsage)) {
			array_push($keyUsage, "digitalSignature");
			array_push($keyUsage, "nonRepudiation");
			array_push($keyUsage, "keyEncipherment");
			array_push($keyUsage, "keyAgreement");
		}

		if(in_array("timeStamping", $enhancedKeyUsage)) {
			array_push($keyUsage, "digitalSignature");
			array_push($keyUsage, "nonRepudiation");
		}

		if(in_array("codeSigning", $enhancedKeyUsage)) {
			array_push($keyUsage, "digitalSignature");
		}

		return array_values(array_unique($keyUsage));
	}

}

?>
