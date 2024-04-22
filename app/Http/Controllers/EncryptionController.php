<?php

namespace App\Http\Controllers;

use App\Models\EncryptionKey;
use App\Services\CryptoService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class EncryptionController extends Controller
{
    private $cryptoService;
    public function __construct(CryptoService $cryptoService)
    {
        $this->cryptoService = $cryptoService;
    }
    public function shareKeys(Request $request)
    {
        return DB::transaction(function () use ($request) {
            // Validate the incoming request data
            $validatedData = $request->validate([
                'public_key' => 'required|string',
                'client_identifier' => 'required|string'
            ]);

            // Retrieve client data from request
            $clientPublicKey = $validatedData['public_key'];
            $clientIdentifier = $validatedData['client_identifier'];

            // Save the client public key and identifier to the database
            EncryptionKey::updateOrCreate(
                ['client_identifier' => $clientIdentifier], // Search array: the conditions to find the record
                ['client_public_key' => $clientPublicKey, 'client_identifier' => $clientIdentifier] // Values array: the values to update or insert
            );


            // Retrieve the server's public key from the CryptoService
            $serverPublicKey = $this->cryptoService->getServerPublicKey();

            // Example: Encoding the key for transmission
            $encryptedData = base64_encode($serverPublicKey);

            // Return response with the server's public key and the record ID of the saved key
            return response()->json(['encrypted' => $encryptedData]);
        });
    }

    public function shareAesKey(Request $request)
    {
        $clientAesData = $request->input('encrypted_aes_key'); // JSON string from the request
        $clientIdentifier = $request->input('client_identifier'); // Public key directly from the request

        try {
            if ($clientAesData && $clientIdentifier) {
                $encryptedData = $this->cryptoService->decryptDataWithClientPrivateKey($clientAesData, $clientIdentifier);
                if($encryptedData == null) {
                    throw new \Exception("Data was not encrypted for response successfully.");
                }
                return response()->json(['encrypted' => $encryptedData]);
            } else {
                return response("Required payload is missing.", 500);
            }
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        }
    }

    public function getRandomData(Request $request)
    {
        $clientIdentifier = $request->input('client_identifier');
        $requiredData = $request->input('encrypted');

        try {
            if ($clientIdentifier) {

                $randomData = $this->cryptoService->encryptWithAesKey($requiredData, $clientIdentifier);
                return response()->json(['encrypted' => $randomData]);
            } else {
                return response("Required payload is missing.", 500);
            }
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        }
    }
}
