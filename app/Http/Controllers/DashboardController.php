<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class DashboardController extends Controller
{
  public function dashboard(Request $request)
  {
    $out = [];

    return response()->json($out);
  }
}
