<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('/register-aws-cognito', [\App\Http\Controllers\ApiAuthController::class, 'register_user']);
Route::post('/login-aws-cognito', [\App\Http\Controllers\ApiAuthController::class, 'login']);
Route::post('/confirmation-email', [\App\Http\Controllers\ApiAuthController::class, 'confirm_email']);


Route::middleware('aws-cognito')->get('/user-cognito', function (Request $request) {
    return Auth::user();
});

