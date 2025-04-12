<?php

namespace Database\Seeders;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Spatie\Permission\Models\Role;

class UsersTableSeeder extends Seeder
{
  /**
   * Run the database seeds.
   */
  public function run(): void
  {

    Role::create(['name' => 'super-admin']);
    Role::create(['name' => 'admin']);
    Role::create(['name' => 'customer']);

    $user = User::create([
      'fullName' => 'Sabuj Islam',
      'avatar' => 'https://avatars.githubusercontent.com/u/46751691?v=4',
      'phoneNumber' => '+8801775559622',
      'email' => 'sabuj0338@gmail.com',
      'isEmailVerified' => true,
      'lastLogin' => Carbon::now(),
      'password' => Hash::make('Password@2')
    ]);

    $user2 = User::create([
      'fullName' => 'Sabuj Islam',
      'avatar' => 'https://avatars.githubusercontent.com/u/46751691?v=4',
      'phoneNumber' => '+8801775559622',
      'email' => 'sabujullapara@gmail.com',
      'isEmailVerified' => true,
      'lastLogin' => Carbon::now(),
      'password' => Hash::make('Password@1')
    ]);

    $user->assignRole(['customer', 'admin', 'super-admin']);
    $user2->assignRole(['customer', 'admin']);
  }
}
