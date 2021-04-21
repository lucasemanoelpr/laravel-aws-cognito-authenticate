<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Ellaisys\Cognito\Auth\RegistersUsers;

class RegisteredUserController extends Controller
{
    use RegistersUsers;
    /**
     * Display the registration view.
     *
     * @return \Illuminate\View\View
     */
    public function create()
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|max:255',
            'email' => 'required|email|max:64|unique:users',
            'password' => 'sometimes|confirmed|min:6|max:64',
        ]);        

        //Create credentials object
        $collection = collect($request->all());
        $data = $collection->only('name', 'email', 'password'); //passing 'password' is optional.

        // dd($this->createCognitoUser($data));

        //Register User in cognito
        if ($cognitoRegistered=$this->createCognitoUser($data)) {
            //If successful, create the user in local db
            $user = User::create($collection->only('name', 'email')->toArray());
        } 

        event(new Registered($user));

        Auth::login($user);
        
        return response()->json([
            'succes' => 'User logged in.'
        ], 201);
    }
}
