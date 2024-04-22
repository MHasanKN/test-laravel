<?php

use App\Http\Controllers\EncryptionController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::post('/share-keys', [EncryptionController::class, 'shareKeys']);
Route::post('/share-aes-key', [EncryptionController::class, 'shareAesKey']);
Route::post('/random', [EncryptionController::class, 'getRandomData']);
