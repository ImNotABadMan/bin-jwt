<?php
/**************************************
 *          jwt config                *
****************************************/

return [
    'jwt_secret'=> env('JWT_SECRET', '12345'),

    'tokenName' => 'token',

    'alg'       => 'HS256',

    'payload'   => [
        'iss' => 'binz', // 发布token的一方
        'sub' => 'binz/bin-jwt', // token的主题
        'exp' => 3600, // 过期时长
    ],

];