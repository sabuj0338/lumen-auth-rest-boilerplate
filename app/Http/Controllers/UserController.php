<?php

namespace App\Http\Controllers;

use App\Helpers\Constant;
use App\Http\Resources\UserCollection;
use App\Models\Otp;
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
use Tymon\JWTAuth\Facades\JWTAuth;

class UserController extends Controller
{
  public function getAll(Request $request)
  {
    // Get how many item per page
    $itemPerPage = $request->query('per_page');
    // SQL Query 
    $customers = User::query();
    // Filter data
    if (!empty($request->search)) {
      $customers = $customers->where('name', 'LIKE', '%' . $request->search . '%');
    }
    if (isset($request->status) && $request->status == 0 || $request->status == 1) {
      $customers = $customers->where('status', $request->status);
    }
    // Return the result as JSON
    $data = $customers->latest()->paginate($itemPerPage);

    return response()->json(new UserCollection($data));
  }

  public function store(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'fullName' => 'required|string|max:20',
      'avatar' => 'nullable|string|max:255',
      'email' => 'required|string|max:25|unique:users,email',
      'phoneNumber' => 'nullable|string|max:15',
      'password' => 'required|string|min:6|max:25',
      'confirmPassword' => 'required|string|min:6|max:25|same:password',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 403);
    }

    $body = [
      "fullName" => $request->fullName,
      "email" => $request->email,
      "phoneNumber" => $request->phoneNumber,
      "avatar" => $request->avatar,
      "password" => Hash::make($request->password) ?? Hash::make('password'),
    ];

    $user = User::create($body);

    $user->assignRole('customer');

    return response()->json([ "message" => "Customer created successfully", "user" => $user ]);
  }

  public function update(Request $request, $id)
  {
    $validated = Validator::make($request->all(), [
      'fullName' => 'required|string|max:20',
      'email' => ['required', 'string', 'max:255', Rule::unique('users', 'email')->ignore($id)],
      'avatar' => 'nullable|string|max:255',
      'phoneNumber' => 'nullable|string|max:15',
      'password' => 'required|string|min:6|max:25',
      'confirmPassword' => 'required|string|min:6|max:25|same:password',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 403);
    }

    $user = User::with('roles')->findOrFail($id);

    $user->update($request->only(['fullName', 'avatar', 'phoneNumber', 'email']));

    if ($request->password) {
      $user->update(["password" => Hash::make($request->password) ?? Hash::make('password')]);
    }

    return response()->json(["message" => "Customer info updated successfully", "user" => $user ]);
  }

  public function updateRole(Request $request, $id)
  {
    $validated = Validator::make($request->all(), [
      'roles' => 'required|array',
      'roles.*' => 'required|in:customer,super-admin,admin',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 403);
    }

    $user = User::with('roles')->findOrFail($id);

    $user->syncRoles(...$request->roles);

    return response()->json(["message" => "Customer roles updated successfully", "user" => $user ]);
  }

  public function updateStatus(Request $request, $id)
  {
    $validated = Validator::make($request->all(), [
      'status' => 'required|boolean',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 403);
    }

    $user = User::with('roles')->findOrFail($id);

    $user->update(["status" => $request->status]);

    return response()->json([
      "message" => "Customer status updated successfully",
      "user" => $user,
    ]);
  }
}
