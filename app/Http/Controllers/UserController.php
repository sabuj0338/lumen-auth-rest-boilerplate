<?php

namespace App\Http\Controllers;

use App\Helpers\ResponseHandler;
use App\Http\Resources\UserCollection;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;

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

    return ResponseHandler::success(data: new UserCollection($data));
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
      return ResponseHandler::validationErrors(errors: $validated->errors());
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

    return ResponseHandler::success(data: ['user' => $user]);
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
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    $user = User::with('roles')->findOrFail($id);

    $user->update($request->only(['fullName', 'avatar', 'phoneNumber', 'email']));

    if ($request->password) {
      $user->update(["password" => Hash::make($request->password) ?? Hash::make('password')]);
    }

    return ResponseHandler::success(data: ['user' => $user]);
  }

  public function updateRole(Request $request, $id)
  {
    $validated = Validator::make($request->all(), [
      'roles' => 'required|array',
      'roles.*' => 'required|in:customer,super-admin,admin',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    $user = User::with('roles')->findOrFail($id);

    $user->syncRoles(...$request->roles);

    return ResponseHandler::success(data: ['user' => $user]);
  }

  public function updateStatus(Request $request, $id)
  {
    $validated = Validator::make($request->all(), [
      'status' => 'required|boolean',
    ]);

    if ($validated->fails()) {
      return ResponseHandler::validationErrors(errors: $validated->errors());
    }

    $user = User::with('roles')->findOrFail($id);

    $user->update(["status" => $request->status]);

    return ResponseHandler::success(data: ['user' => $user]);
  }
}
