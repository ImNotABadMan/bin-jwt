<?php
/**
 * Created by PhpStorm.
 * User: IT
 * Date: 2018/7/24
 * Time: 15:40
 */

namespace Jwt;

use Illuminate\Support\Facades\Facade;

Class BJwtAuthFacade extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'BJwtAuth';
    }
}

