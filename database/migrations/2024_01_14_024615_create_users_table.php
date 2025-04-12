<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
  /**
   * Run the migrations.
   */
  public function up(): void
  {
    Schema::create('users', function (Blueprint $table) {
      $table->id();
      $table->string('fullName', 20);
      $table->string('avatar')->nullable();
      $table->string('phoneNumber', 14)->nullable();
      $table->string('email', 25)->unique();
      $table->string('password');
      $table->timestamp('lastLogin')->nullable();
      $table->boolean('status')->default(true);
      $table->boolean('isEmailVerified')->default(false);
      $table->string('otp')->nullable();
      $table->timestamp('otpExpiresAt')->nullable();
      $table->timestamps();
    });
  }

  /**
   * Reverse the migrations.
   */
  public function down(): void
  {
    Schema::dropIfExists('users');
  }
};
