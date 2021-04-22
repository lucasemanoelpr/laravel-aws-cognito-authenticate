<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Traits;

use Illuminate\Support\Collection;
use Ellaisys\Cognito\AwsCognitoClient;
use Illuminate\Support\Facades\Validator;

trait VerifiesEmailsApi
{ 
    /**
     * Mark the authenticated user's email address as verified.
     *
     * @param  \Illuminate\Support\Collection  $request
     * @return \Illuminate\Http\RedirectResponse
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function verify(Collection $request)
    {
        Validator::make($request->toArray(), [
            'username' => 'required', 
            'confirmation_code' => 'required|numeric',
        ]);

        $response = app()->make(AwsCognitoClient::class)->confirmUserSignUp($request['username'], $request['confirmation_code']);

        if ($response == 'validation.invalid_user') {
            return response()->json(['error' => 'cognito.validation.invalid_user'], 400);
        }

        if ($response == 'validation.invalid_token') {
            return response()->json(['error' => 'cognito.validation.invalid_token'], 400);
        }

        if ($response == 'validation.exceeded') {
            return response()->json(['error' => 'cognito.validation.exceeded'], 400);
        }

        if ($response == 'validation.confirmed') {
            return response()->json(['error' => 'cognito.validation.confirmed'], 400);
        }

        return response()->json(['success' => 'true'], 200);
    }


    /**
     * Resend the email verification notification.
     *
     * @param  \Illuminate\Support\Collection  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function resend(Collection $request)
    {

        $response = app()->make(AwsCognitoClient::class)->resendToken($request->email);

        if ($response == 'validation.invalid_user') {
            return response()->json(['error' => 'cognito.validation.invalid_user'], 400);
        }

        if ($response == 'validation.exceeded') {
            return response()->json(['error' => 'cognito.validation.exceeded'], 400);
        }

        if ($response == 'validation.confirmed') {
            return response()->json(['error' => 'cognito.validation.confirmed'], 400);
        }

        return response()->json(['success' => 'true']);
    }
    
}