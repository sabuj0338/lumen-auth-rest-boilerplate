<?php

namespace App\Http\Controllers;

use App\Http\Resources\UserResource;
use App\Models\User;
use App\Notifications\SendEmailVerificationNotification;
use App\Notifications\SendResetPasswordNotification;
use Carbon\Carbon;
use Error;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;

class AuthController extends Controller
{
  function generateOTP()
  {
    return rand(100000, 999999);
  }

  protected function respondWithToken($token, $user)
  {
    // $user = User::find(Auth::user()->id);
    $user->update(['lastLogin' => Carbon::now()]);

    return response()->json([
      "message" => "Operation Successful",
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
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 403);
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
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function login(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'email' => 'required|string|max:255|exists:users,email',
      'password' => 'required|string|max:25',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 403);
    }

    try {
      $credentials = $request->only(['email', 'password']);
      $token = Auth::attempt($credentials);

      if (!$token || !Auth::check() || Auth::user()->status == false) {
        throw new Error("Unauthorized");
      }

      $user = User::find(Auth::user()->id);

      return $this->respondWithToken($token, $user);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function logout(Request $request)
  {
    Auth::logout();

    return response()->json(['message' => 'Successfully logged out']);
  }

  public function refreshTokens()
  {
    // return $this->respondWithToken(Auth::refresh());
    $token = Auth::refresh();

    return response()->json([
      "message" => "Operation Successful",
      "accessToken" => $token,
      "refreshToken" => $token,
    ]);
  }

  public function forgotPassword(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'email' => 'required|email|exists:users',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {
      $user = User::where('email', $request->email)->first();

      if (!$user) {
        return response()->json(['message' => 'If that email exists, OTP was sent']);
      }

      $otp = $this->generateOTP();
      $user->otp = $otp;
      $user->otpExpiresAt = Carbon::now()->addMinutes(10);
      $user->save();

      $user->notify(new SendResetPasswordNotification($otp));
      return response()->json(["message" => "OTP sent to your email."]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
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
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {

      $user = User::where('email', $request->email)->first();

      $isExpired = Carbon::parse($user->otpExpiresAt)->isPast();

      if (!$user || $user->otp != $request->otp || $isExpired) {
        return response()->json(['message' => 'Invalid or expired OTP'], 422);
      }

      $user->password = Hash::make($request->password) ?? Hash::make('password');
      $user->otp = null;
      $user->otpExpiresAt = null;
      $user->save();

      return response()->json(['message' => 'Password reset successful']);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
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
        return response()->json(['message' => 'Email already verified.']);
      }

      $otp = $this->generateOTP();
      $user->otp = $otp;
      $user->otpExpiresAt = Carbon::now()->addMinutes(10);
      $user->save();

      $user->notify(new SendEmailVerificationNotification($otp));
      return response()->json(["message" => "OTP sent successfully"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function verifyEmail(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'otp' => 'required|digits:6',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    $user = User::find(Auth::user()->id);

    $isExpired = Carbon::parse($user->otpExpiresAt)->isPast();

    if (!$user || $user->otp != $request->otp || $isExpired) {
      return response()->json(['message' => 'Invalid or expired OTP'], 422);
    }

    $user->isEmailVerified = true;
    $user->otp = null;
    $user->otpExpiresAt = null;
    $user->save();

    return response()->json(['message' => 'Email verified!']);
  }

  public function updatePassword(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'password' => 'required|string|min:6|max:25',
      'confirmPassword' => 'required|string|min:6|max:25|same:password',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $user->password = Hash::make($request->password) ?? Hash::make('password');
      $user->save();

      return response()->json(["message" => "Password update successful"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
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
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $user->update($request->only(['fullName', 'avatar', 'phoneNumber', 'email']));

      return response()->json(["message" => "Profile update successful", "user" => $user]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function profile()
  {
    return response()->json([
      "message" => "Operation Successful",
      "user" => new UserResource(auth()->user())
    ]);
  }
}
