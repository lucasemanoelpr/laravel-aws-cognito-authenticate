<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Ellaisys\Cognito\Auth\RegistersUsers;
use Ellaisys\Cognito\AwsCognitoClaim;
use Ellaisys\Cognito\Auth\AuthenticatesUsers as CognitoAuthenticatesUsers;
use Ellaisys\Cognito\Exceptions\InvalidUserFieldException;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Collection;
use Ellaisys\Cognito\AwsCognitoClient;
use Ellaisys\Cognito\Auth\VerifiesEmails;

class ApiAuthController extends Controller
{
    use RegistersUsers, CognitoAuthenticatesUsers, VerifiesEmails;

    public function createCognitoUser(Collection $request, array $clientMetadata=null)
    {
        //Initialize Cognito Attribute array
        $attributes = [];

        //Get the registeration fields
        $userFields = config('cognito.cognito_user_fields');

        //Iterate the fields
        foreach ($userFields as $key => $userField) {
            if ($request->has($userField)) {
                $attributes[$key] = $request->get($userField);
            } else {
                Log::error('RegistersUsers:createCognitoUser:InvalidUserFieldException');
                Log::error("The configured user field {$userField} is not provided in the request.");
                throw new InvalidUserFieldException("The configured user field {$userField} is not provided in the request.");
            } //End if 
        } //Loop ends

        //Register the user in Cognito
        $userKey = $request->has('username')?'username':'email';

        //Temporary Password paramter
        $password = $request->has('password')?$request['password']:null;
        app()->make(AwsCognitoClient::class)->register($request[$userKey], $password, $attributes);
        return true;
    } //Function ends

    public function register_user(Request $request)
    {
        $request->validate([
            'name' => 'required|max:255',
            'email' => 'required|email|max:64|unique:users',
            'password' => 'sometimes|confirmed|min:6|max:64',
        ]);        

        $collection = collect($request->all());
        $data = $collection->only('name', 'email', 'password'); //passing 'password' is optional.

        if ($this->createCognitoUser($data)) {
            $user = User::create($collection->only('name', 'email')->toArray());
        }  

        return response()->json([
            'succes' => 'User created.'
        ], 201);
    }

    public function login(\Illuminate\Http\Request $request)
    {
        $collection = collect($request->all());
        //Authenticate with Cognito Package Trait (with 'api' as the auth guard)
        $claim = $this->attemptLogin($collection, 'api', 'email', 'password', true);

        if ($claim) {
        
            if ($claim instanceof AwsCognitoClaim) {
                // return $claim->getData();
                return response()->json(['status' => 'succes', 'message' => $claim], 200);
            } else {
                return response()->json(['status' => 'error', 'messages' => $claim], 400);
            }
        }

        return response()->json([
            'status' => 'Error', 
            'message' => $claim
        ], 400);
    }

    public function confirm_email(Request $request) {
        $collection = collect($request->all());
        $this->verify($collection);
    }
}
