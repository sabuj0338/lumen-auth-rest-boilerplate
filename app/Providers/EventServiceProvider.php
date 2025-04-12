<?php

namespace App\Providers;

use App\Notifications\SendResetPasswordNotification;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Laravel\Lumen\Providers\EventServiceProvider as ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
  /**
   * The event listener mappings for the application.
   *
   * @var array
   */
  protected $listen = [
    // \App\Events\ExampleEvent::class => [
    //     \App\Listeners\ExampleListener::class,
    // ],
    // Registered::class => [
    //   SendEmailVerificationNotification::class,
    //   SendResetPasswordNotification::class,
    // ],
  ];

  /**
   * Determine if events and listeners should be automatically discovered.
   *
   * @return bool
   */
  public function shouldDiscoverEvents()
  {
    return false;
  }

  /**
   * Register any events for your application.
   *
   * @return void
   */
  // public function boot()
  // {
  //   //
  // }
}
