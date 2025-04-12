<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->get('/', function () use ($router) {
  return $router->app->version();
});

$router->group(['prefix' => 'v1'], function () use ($router) {
  $router->post('/auth/register', 'AuthController@register');
  $router->post('/auth/login', 'AuthController@login');

  $router->post('/auth/forgot-password', 'AuthController@forgotPassword');
  $router->post('/auth/reset-password', 'AuthController@resetPassword');
  $router->post('/auth/refresh-tokens', 'AuthController@refreshTokens');

  $router->group(['middleware' => 'auth'], function () use ($router) {

    $router->get('/auth/profile', 'AuthController@profile');
    $router->post('/auth/logout', 'AuthController@logout');
    $router->post('/auth/send-verification-email', 'AuthController@sendVerificationEmail');
    $router->post('/auth/verify-email', 'AuthController@verifyEmail');
    // $router->post('/auth/send-otp', 'AuthController@send-otp');
    // $router->post('/auth/verify-otp', 'AuthController@verify-otp');
    $router->put('/auth/update-password', 'AuthController@updatePassword');
    $router->put('/auth/update', 'AuthController@update');

    $router->post('users', 'UserController@store');
    $router->put('users/update/{id}', 'UserController@update');
    $router->put('users/update-role/{id}', 'UserController@updateRole');
    $router->put('users/update-status/{id}', 'UserController@updateStatus');
  });
});
