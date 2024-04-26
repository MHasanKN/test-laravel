<?php

namespace App\Services;

use App\Http\Controllers\Controller;
use App\Models\EncryptionKey;
use Exception;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class CryptoService
{
    /**
     * @throws Exception
     */
    public function getServerPublicKey()
    {
        $envPath = base_path('.env');

        // Check if keys already exist in .env
        if (file_exists($envPath)) {
            $publicKey = getenv('PUBLIC_KEY');
            $privateKey = getenv('PRIVATE_KEY');

            // Ensure both keys are available
            if ($publicKey && $privateKey) {
                return $publicKey;
            } else {
                throw new Exception('Failed to find public/private key from env.');
            }
        } else {
            throw new Exception('ENV File not found.');
        }

//        // Generate new keys if not found
//        $config = [
//            'config' => 'C:/xampp/apache/conf/openssl.cnf',  // Correct this path as per your system
//            'private_key_bits' => 2048,
//            'private_key_type' => OPENSSL_KEYTYPE_RSA
//        ];
//        $res = openssl_pkey_new($config);
//
//        if (!$res) {
//            while ($err = openssl_error_string()) {
//                Log::error($err);  // Log this to a file or output it directly
//            }
//            throw new Exception('Unable to generate the private key.');
//        }
//        $privateKeyOut = '';
//        if (!openssl_pkey_export($res, $privateKeyOut, null, $config)) {
//            Log::error("Failed to export private key");
//            throw new Exception('Failed to export private key.');
//        }
//        $privateKey = $privateKeyOut;
//
//        openssl_pkey_export($res, $privateKey);
//        $keyDetails = openssl_pkey_get_details($res);
//        $publicKey = $keyDetails['key'];
//
//        // Save keys to .env
//        //The keys are base64 encoded before being saved. This is purely for ease of storage and should be decoded upon retrieval.
//        $envData = "PUBLIC_KEY=" . base64_encode($publicKey) . PHP_EOL;
//        $envData .= "PRIVATE_KEY=" . base64_encode($privateKey) . PHP_EOL;
//        file_put_contents($envPath, $envData, FILE_APPEND | LOCK_EX);
//
//        return $publicKey;
    }

    /**
     * @throws Exception
     */
    public function decryptDataWithOurPrivateKey($clientAesData, $clientIdentifier)
    {
        return DB::transaction(function () use ($clientAesData, $clientIdentifier) {
            $clientEncryptionData = EncryptionKey::where('client_identifier', $clientIdentifier)->first();

            if (!$clientEncryptionData) {
                Log::error("No encryption data found for client: {$clientIdentifier}");
                throw new Exception("Client data irretrievable from Encryption Table.");
            }

            // Retrieve and prepare the private key for decryption
            $base64PrivateKey = env('PRIVATE_KEY');
            if (!$base64PrivateKey) {
                Log::error("Private key not found in environment");
                throw new Exception("Server Private Key irretrievable.");
            }
            $privateKeyPem = base64_decode($base64PrivateKey);
            $privateKey = openssl_pkey_get_private($privateKeyPem);
            if (!$privateKey) {
                Log::error("Failed to get private key for decryption.");
                throw new Exception("Failed to get private key for decryption");
            }

            // Decrypt the AES key
            $decryptedAesKey = '';
            if (!openssl_private_decrypt(base64_decode($clientAesData), $decryptedAesKey, $privateKey)) {
                Log::error(openssl_error_string()); // Log OpenSSL errors
                throw new Exception("Error while decrypting the AES Key");
            }
            $decryptedAesData = json_decode($decryptedAesKey, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                Log::error("JSON decode error: " . json_last_error_msg());
                throw new Exception("Error decoding JSON data");
            }

            if(!$decryptedAesData['aesKey'] && !$decryptedAesData['iv']) {
                Log::error("Required parameters not passed in encrypted array.");
                throw new Exception("Required parameters not passed in encrypted array.");
            }

            // Store the decrypted AES key
            $clientEncryptionData->aes_key = Crypt::encrypt($decryptedAesData['aesKey']);
            $clientEncryptionData->iv = Crypt::encrypt($decryptedAesData['iv']);
            $clientEncryptionData->save();

            // Retrieve or generate the server's AES key
//            $serverAesKey = $this->getServerAesKey();

            // Encrypt the server AES key with the client's stored public RSA key
            return $this->encryptWithRsaPublicKey($decryptedAesData['aesKey'], null, Crypt::decrypt($clientEncryptionData->client_public_key));
        });
    }


    /**
     * Fetches or generates the server's AES key.
     *
     * @return string The server's AES key.
     */
    protected function getServerAesKey() {
        $serverAesKey = env('SERVER_AES_KEY');
        if (!$serverAesKey) {
            // Generate a new AES key
            $serverAesKey = bin2hex(random_bytes(16)); // 16 bytes = 128 bits
            // Store it securely or in the environment configuration, here using .env for example purposes
            $envPath = base_path('.env');
            $envData = "SERVER_AES_KEY=" . base64_encode($serverAesKey) . PHP_EOL;
            file_put_contents($envPath, $envData, FILE_APPEND | LOCK_EX);
        } else {
            $serverAesKey = base64_decode($serverAesKey);
        }
        return $serverAesKey;
    }

    /**
     * Encrypts any data using a given RSA public key.
     *
     * @param mixed $data Data to encrypt. Can be a string, array, model object, or any serializable PHP type.
     * @param string|null $clientIdentifier Unique identifier for a client whose public key might be retrieved.
     * @param string|null $publicKey RSA public key in PEM format.
     * @return string|null Encrypted data in base64 format or null on failure.
     */
    public function encryptWithRsaPublicKey(mixed $data, string $clientIdentifier = null, string $publicKey = null): ?string
    {
        // Convert data into a JSON string if it's not already a string
        if (!is_string($data)) {
            $data = json_encode($data);
            if ($data === false) {
                Log::error("Failed to encode data for encryption");
                return null;
            }
        }

        if ($clientIdentifier != null && $publicKey == null) {
            $clientEncryptionData = EncryptionKey::where('client_identifier', $clientIdentifier)->first();
            if ($clientEncryptionData) {
                $publicKey = Crypt::decrypt($clientEncryptionData->client_public_key);
            } else {
                Log::error("No client encryption data found for identifier: $clientIdentifier");
                return null;
            }
        }

        if (!$publicKey) {
            Log::error("Public key not found or invalid");
            return null;
        }

        $publicKeyResource = openssl_pkey_get_public($publicKey);
        if (!$publicKeyResource) {
            Log::error("Invalid public key provided");
            return null;
        }

        $encryptedData = '';
        if (!openssl_public_encrypt($data, $encryptedData, $publicKeyResource)) {
            Log::error(openssl_error_string()); // Log OpenSSL errors
            return null;
        }
        Log::info("Server AES Key: " . base64_encode($encryptedData));
        return base64_encode($encryptedData);
    }

    /**
     * Encrypts any data using an AES key associated with a client identifier.
     *
     * @param mixed $data Data to encrypt. Can be a string, array, model object, or any serializable PHP type.
     * @param string $clientIdentifier Unique identifier for a client whose AES key might be retrieved.
     * @return string|null Encrypted data in base64 format or null on failure.
     * @throws Exception
     */
    public function encryptWithAesKey(mixed $data, string $clientIdentifier): ?string
    {
        try {
            // Retrieve the client's encryption data from the database
            $clientEncryptionData = EncryptionKey::where('client_identifier', $clientIdentifier)->first();
            if (!$clientEncryptionData || empty($clientEncryptionData->aes_key) || empty($clientEncryptionData->iv)) {
                Log::error("No AES key or IV found for client identifier: $clientIdentifier");
                throw new Exception("No AES key or IV found for client identifier: $clientIdentifier");
            }
            // Decrypt and decode the base64 AES key and IV from the database or wherever they are stored
            $aesKeyBase64 = Crypt::decrypt($clientEncryptionData->aes_key);  // Decrypting AES key
            $ivBase64 = Crypt::decrypt($clientEncryptionData->iv);           // Decrypting IV

            // Decode from base64 to get the raw binary data
            $aesKey = base64_decode($aesKeyBase64);
            $iv = base64_decode($ivBase64);

            // Decrypt the encrypted data
            $encryptedData = base64_decode($data); // This should be your encrypted data
            $decryptedData = openssl_decrypt($encryptedData, 'aes-256-ctr', $aesKey, OPENSSL_RAW_DATA, $iv);

            $randomData = [
                'abc'=>'human',
                'hasan'=>999
            ];
            $jsonData = json_encode($randomData);
            // Encrypt the data using the AES key
            $encryptedData = openssl_encrypt($jsonData, 'aes-256-ctr', $aesKey, OPENSSL_RAW_DATA, $iv);

        } catch (Exception $exception) {
            Log::error($exception);
            throw new Exception("Failed to decode AES key for client identifier:");
        }
        return base64_encode($encryptedData);
    }

    public function encryptWithAesKey2(mixed $data, string $clientIdentifier): ?string
    {
        try {
            // Retrieve the client's encryption data from the database
            $clientEncryptionData = EncryptionKey::where('client_identifier', $clientIdentifier)->first();
            if (!$clientEncryptionData || empty($clientEncryptionData->aes_key) || empty($clientEncryptionData->iv)) {
                Log::error("No AES key or IV found for client identifier: $clientIdentifier");
                throw new Exception("No AES key or IV found for client identifier: $clientIdentifier");
            }
            // Decrypt and decode the base64 AES key and IV from the database or wherever they are stored
            $aesKeyBase64 = Crypt::decrypt($clientEncryptionData->aes_key);  // Decrypting AES key
            $ivBase64 = Crypt::decrypt($clientEncryptionData->iv);           // Decrypting IV

            // Decode from base64 to get the raw binary data
            $aesKey = base64_decode($aesKeyBase64);
            $iv = base64_decode($ivBase64);

            $jsonData = json_encode($data);
            Log::info("JSON After encode: " . $jsonData);
            $encryptedData = openssl_encrypt($jsonData, 'aes-256-ctr', $aesKey, OPENSSL_RAW_DATA, $iv);
            Log::info("After encryption: " . $encryptedData);
            $base64EncryptedData = base64_encode($encryptedData);
            Log::info("After encrypted to base64: " . $base64EncryptedData);

            $decryptedData = openssl_decrypt(base64_decode($base64EncryptedData), 'aes-256-ctr', $aesKey, OPENSSL_RAW_DATA, $iv);
            Log::info("After decryption: " . $decryptedData);

        } catch (Exception $exception) {
            Log::error($exception);
            throw new Exception("Failed to decode AES key for client identifier:");
        }
        return $base64EncryptedData;
    }



}
