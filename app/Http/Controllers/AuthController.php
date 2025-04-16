<?php

namespace App\Http\Controllers;

use App\Helpers\ResponseHandler;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Notifications\SendEmailVerificationNotification;
use App\Notifications\SendResetPasswordNotification;
use Carbon\Carbon;
use Error;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
  protected function generateOTP()
  {
    return rand(100000, 999999);
  }

  protected function respondWithToken($token, $user)
  {
    $user->update(['lastLogin' => Carbon::now()]);

    return ResponseHandler::success(data: [
      'user' => new UserResource($user),
      'accessToken' => $token,
      'refreshToken' => $token,
    ]);
  }

  public function register(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'fullName' => 'required|string|max:255',
      'email' => 'required|email|unique:users',
      'password' => 'required|string|min:6|max:25',
      'confirmPassword' => 'required|string|min:6|max:25|same:password',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }
    try {
      // $otp = $this->generateOTP();

      $user = User::create([
        'fullName'     => $request->fullName,
        'email'    => $request->email,
        'password' => Hash::make($request->password) ?? Hash::make('password'),
        // 'otp' => $otp,
        // 'otpExpiresAt' => Carbon::now()->addMinutes(10),
      ]);

      $user->assignRole('customer');

      // $user->notify(new SendEmailVerificationNotification($otp));

      $credentials = $request->only(['email', 'password']);
      $token = Auth::attempt($credentials);

      if (!$token || !Auth::check() || Auth::user()->status == false) {
        throw new Error("Unauthorized");
      }
      return $this->respondWithToken($token, $user);
    } catch (\Throwable $th) {
      return ResponseHandler::error(message: $th->getMessage(), status: 403);
    }
  }

  public function login(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'email' => 'required|string|max:255|exists:users,email',
      'password' => 'required|string|max:25',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    try {
      $credentials = $request->only(['email', 'password']);
      $token = Auth::attempt($credentials);

      if (!$token || !Auth::check() || Auth::user()->status == false) {
        throw new Error("Unauthorized access");
      }

      $user = User::find(Auth::user()->id);

      return $this->respondWithToken($token, $user);
    } catch (\Throwable $th) {
      return ResponseHandler::error(message: $th->getMessage(), status: 403);
    }
  }

  public function logout(Request $request)
  {
    try {
      // Invalidate the token server-side if using JWT
      auth()->logout(); // This invalidates the current token if configured
      return ResponseHandler::success(message: 'Successfully logged out');
    } catch (JWTException $e) {
      // Handle cases where logout might fail (e.g., token already invalid)
      Log::error("Logout failed: " . $e->getMessage(), ['exception' => $e]);
      return ResponseHandler::error(message: 'Logout failed.', status: 500);
    }
  }

  public function refreshTokens(Request $request)
  {
    // 1. Validate the request body
    $validated = Validator::make($request->all(), [
      'refreshToken' => 'required|string',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    $refreshToken = $request->input('refreshToken');

    try {
      $newAccessToken = JWTAuth::setToken($refreshToken)->refresh();

      return ResponseHandler::success(message: 'Token refreshed successfully', data: [
        'accessToken' => $newAccessToken,
      ]);
    } catch (TokenExpiredException $e) {
      return ResponseHandler::error(message: 'Refresh token expired', status: 401);
    } catch (TokenInvalidException $e) {
      return ResponseHandler::error(message: 'Refresh token invalid', status: 401);
    } catch (JWTException $e) {
      Log::error("Token refresh failed: " . $e->getMessage(), ['exception' => $e]);
      return ResponseHandler::error(message: 'Could not refresh token', status: 500);
    } catch (\Throwable $th) {
      Log::error("Token refresh failed (general): " . $th->getMessage(), ['exception' => $th]);
      return ResponseHandler::error(message: 'An unexpected error occurred', status: 500);
    }
  }

  public function forgotPassword(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'email' => 'required|email|exists:users',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    try {
      $user = User::where('email', $request->email)->first();

      if (!$user) {
        return ResponseHandler::success(message: 'If that email exists, OTP was sent');
      }

      $otp = $this->generateOTP();
      $user->otp = $otp;
      $user->otpExpiresAt = Carbon::now()->addMinutes(10);
      $user->save();

      $user->notify(new SendResetPasswordNotification($otp));

      return ResponseHandler::success(message: 'OTP sent to your email.');
    } catch (\Throwable $th) {
      return ResponseHandler::error(message: $th->getMessage(), status: 403);
    }
  }

  public function resetPassword(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'email' => 'required|email',
      'otp' => 'required|digits:6',
      'password' => 'required|min:6|max:25',
      'confirmPassword' => 'required|string|min:6|max:25|same:password',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    try {

      $user = User::where('email', $request->email)->first();

      $isExpired = Carbon::parse($user->otpExpiresAt)->isPast();

      if (!$user || $user->otp != $request->otp || $isExpired) {
        return ResponseHandler::error(message: 'Invalid or expired OTP', status: 422);
      }

      $user->password = Hash::make($request->password) ?? Hash::make('password');
      $user->otp = null;
      $user->otpExpiresAt = null;
      $user->save();

      return ResponseHandler::success(message: 'Password reset successful');
    } catch (\Throwable $th) {
      return ResponseHandler::error(message: $th->getMessage(), status: 403);
    }
  }

  public function sendVerificationEmail(Request $request)
  {
    try {
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      if (Auth::user()->isEmailVerified == true) {
        return ResponseHandler::success(message: 'Email already verified.');
      }

      $otp = $this->generateOTP();
      $user->otp = $otp;
      $user->otpExpiresAt = Carbon::now()->addMinutes(10);
      $user->save();

      $user->notify(new SendEmailVerificationNotification($otp));

      return ResponseHandler::success(message: 'OTP sent to your email.');
    } catch (\Throwable $th) {
      return ResponseHandler::error(message: $th->getMessage(), status: 403);
    }
  }

  public function verifyEmail(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'otp' => 'required|digits:6',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    $user = User::find(Auth::user()->id);

    $isExpired = Carbon::parse($user->otpExpiresAt)->isPast();

    if (!$user || $user->otp != $request->otp || $isExpired) {
      return ResponseHandler::error(message: 'Invalid or expired OTP', status: 422);
    }

    $user->isEmailVerified = true;
    $user->otp = null;
    $user->otpExpiresAt = null;
    $user->save();

    return ResponseHandler::success(message: 'Email verification successful');
  }

  public function updatePassword(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'password' => 'required|string|min:6|max:25',
      'confirmPassword' => 'required|string|min:6|max:25|same:password',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    try {
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $user->password = Hash::make($request->password) ?? Hash::make('password');
      $user->save();

      return ResponseHandler::success(message: 'Password update successful');
    } catch (\Throwable $th) {
      return ResponseHandler::error(message: $th->getMessage(), status: 403);
    }
  }

  public function update(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'fullName' => 'nullable|string|max:25',
      'avatar' => 'nullable|string|max:255',
      'phoneNumber' => 'nullable|string|max:15',
      'email' => ['required', 'string', 'max:255', Rule::unique('users', 'email')->ignore(Auth::user()->id)],
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    try {
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $user->update($request->only(['fullName', 'avatar', 'phoneNumber', 'email']));

      return ResponseHandler::success(data: ['user' => new UserResource($user)]);
    } catch (\Throwable $th) {
      return ResponseHandler::error(message: $th->getMessage(), status: 403);
    }
  }

  public function profile()
  {
    return ResponseHandler::success(data: ["user" => new UserResource(auth()->user())]);
  }
}
