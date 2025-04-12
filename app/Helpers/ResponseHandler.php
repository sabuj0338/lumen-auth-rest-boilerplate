<?php

namespace App\Helpers;

class ResponseHandler
{
  static public function success($data = null, $status = 200, $message = 'Operation successful')
  {
    return response()->json([
      'success' => true,
      'message' => $message,
      'data' => $data,
    ], $status);
  }

  static public function error($errors = null, $status = 500, $message = 'Operation Failed')
  {
    return response()->json([
      'success' => false,
      'message' => $message,
      'errors' => $errors,
    ], $status);
  }

  static public function validationErrors($errors = null, $status = 422, $message = 'Invalid information')
  {
    return response()->json([
      'success' => false,
      'message' => $message,
      'errors' => $errors,
    ], $status);
  }
}