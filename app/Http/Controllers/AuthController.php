<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;

class AuthController extends Controller
{
    public function __construct()
    {
        // Apply the 'auth:api' middleware to all methods except login, refresh, and logout
        $this->middleware('auth:api', ['except' => ['login', 'refresh', 'logout']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @param Request $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        // Validate the incoming request
        $this->validate($request, [
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        // Get credentials from request
        $credentials = $request->only(['email', 'password']);

        // Attempt to create a token using the credentials
        if (!$token = Auth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        // Return the token if authentication is successful
        return $this->respondWithToken($token);
    }

    /**
     * Respond with the generated JWT token.
     *
     * @param string $token
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60 // Expiry time in seconds
        ]);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }
}
