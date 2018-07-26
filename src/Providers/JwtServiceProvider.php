<?php
/**
 * Created by PhpStorm.
 * User: IT
 * Date: 2018/7/24
 * Time: 14:53
 */

namespace Jwt;

use Illuminate\Support\ServiceProvider;

Class JwtServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $realPath = __DIR__ . "/../config/config.php";

        $this->publishes([$realPath => config_path('jwt.php')]);

        $this->mergeConfigFrom($realPath, 'jwt');

    }

    public function register()
    {
        $realPath = __DIR__ . "/../config/config.php";

        $this->app->singleton('BJwtAuth', function (){
            return new BJwtAuth;
        });

    }
}