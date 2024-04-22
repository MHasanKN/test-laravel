<?php

namespace App\Services;

use App\Http\Controllers\Controller;
use App\Models\EncryptionKey;
use Exception;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class CryptoService
{
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
            }
        }

        // Generate new keys if not found
        $config = [
            'config' => 'C:/xampp/apache/conf/openssl.cnf',  // Correct this path as per your system
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ];
        $res = openssl_pkey_new($config);

        if (!$res) {
            while ($err = openssl_error_string()) {
                Log::error($err);  // Log this to a file or output it directly
            }
            throw new Exception('Unable to generate the private key.');
        }
        $privateKeyOut = '';
        if (!openssl_pkey_export($res, $privateKeyOut, null, $config)) {
            Log::error("Failed to export private key");
            throw new Exception('Failed to export private key.');
        }
        $privateKey = $privateKeyOut;

        openssl_pkey_export($res, $privateKey);
        $keyDetails = openssl_pkey_get_details($res);
        $publicKey = $keyDetails['key'];

        // Save keys to .env
        //The keys are base64 encoded before being saved. This is purely for ease of storage and should be decoded upon retrieval.
        $envData = "PUBLIC_KEY=" . base64_encode($publicKey) . PHP_EOL;
        $envData .= "PRIVATE_KEY=" . base64_encode($privateKey) . PHP_EOL;
        file_put_contents($envPath, $envData, FILE_APPEND | LOCK_EX);

        return $publicKey;
    }

    public function decryptData($clientAesKey, $clientIdentifier)
    {
        $clientEncryptionData = EncryptionKey::where('client_identifier', $clientIdentifier)->first();

        if (!$clientEncryptionData) {
            Log::error("No encryption data found for client: {$clientIdentifier}");
            return null; // or handle the error as appropriate
        }

        // Retrieve and prepare the private key for decryption
        $base64PrivateKey = env('PRIVATE_KEY');
        if (!$base64PrivateKey) {
            Log::error("Private key not found in environment");
            return null;
        }
        $privateKeyPem = base64_decode($base64PrivateKey);
        $privateKey = openssl_pkey_get_private($privateKeyPem);
        if (!$privateKey) {
            Log::error("Failed to get private key for decryption");
            return null;
        }

        // Decrypt the AES key
        $decryptedAesKey = '';
        if (!openssl_private_decrypt(base64_decode($clientAesKey), $decryptedAesKey, $privateKey)) {
            Log::error(openssl_error_string()); // Log OpenSSL errors
            return null;
        }

        // Store the decrypted AES key
        $clientEncryptionData->aes_key = $decryptedAesKey;
        $clientEncryptionData->save();

        // Retrieve or generate the server's AES key
        $serverAesKey = $this->getServerAesKey();

        // Encrypt the server AES key with the client's stored public RSA key
        return $this->encryptWithRsaPublicKey($serverAesKey, null, $clientEncryptionData->client_public_key);
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
                $publicKey = $clientEncryptionData->client_public_key;
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
     */
    public function encryptWithAesKey(mixed $data, string $clientIdentifier): ?string
    {
        // Convert data into a JSON string if it's not already a string
        if (!is_string($data)) {
            $data = json_encode($data);
            if ($data === false) {
                Log::error("Failed to encode data for encryption");
                return null;
            }
        }

        // Retrieve the client's encryption data from the database
        $clientEncryptionData = EncryptionKey::where('client_identifier', $clientIdentifier)->first();
        if (!$clientEncryptionData || empty($clientEncryptionData->aes_key) || empty($clientEncryptionData->iv)) {
            Log::error("No AES key or IV found for client identifier: $clientIdentifier");
            return null;
        }

        // Decode the AES key and IV
        $aesKey = openssl_decrypt(base64_decode($clientEncryptionData->aes_key), 'AES-256-CBC', 'secret_key', 0, base64_decode($clientEncryptionData->iv));  // Adjust secret_key as needed
        if ($aesKey === false) {
            Log::error("Failed to decode AES key for client identifier: $clientIdentifier");
            return null;
        }

        // Encrypt the data using the AES key
        $encryptedData = openssl_encrypt($data, 'AES-256-CBC', $aesKey, 0, base64_decode($clientEncryptionData->iv));
        if ($encryptedData === false) {
            Log::error(openssl_error_string()); // Log OpenSSL errors
            return null;
        }

        Log::info("Encrypted data with AES Key: " . base64_encode($encryptedData));
        return base64_encode($encryptedData);
    }



}
