<?php

namespace App\Http\Resources;

use App\Models\Plan;
use App\Models\User;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
  /**
   * Transform the resource into an array.
   *
   * @param  \Illuminate\Http\Request  $request
   * @return array
   */
  public function toArray($request)
  {
    // return parent::toArray($request);
    return [
      'id' => $this->id,
      'fullName' => $this->fullName,
      'email' => $this->email,
      'avatar' => $this->avatar,
      'phoneNumber' => $this->phoneNumber,
      'lastLogin' => $this->lastLogin,
      'isEmailVerified' => $this->isEmailVerified,
      'roles' => $this->getRoleNames(),
      'status' => $this->status,
      'created_at' => $this->created_at->format('d M Y, H:i a'),
      'updated_at' => $this->updated_at->format('d M Y, H:i a'),
    ];
  }
}
