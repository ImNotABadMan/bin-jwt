<?php
/**
 * Created by PhpStorm.
 * User: IT
 * Date: 2018/7/24
 * Time: 14:13
 */

namespace Jwt;

use App\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

Class BJwtAuth extends BaseBJwtAuth
{
    private $_table;

    public function __construct($userTable = '')
    {
        parent::__construct();
        if( !empty($userTable) ){
            $this->_table = $userTable;
        }else{
            $this->_table = strtolower( substr(strstr(User::class, '\\'), 1)) . 's';
        }

    }

    public static function testFacade()
    {
        return 'JwtFacade';
    }

    public function isCan(...$params)
    {
        if( is_array($params) && func_num_args() == 1 ){
            $email = $params[0]['email'];
            $password = $params[0]['password'];
        }else if( func_num_args() == 2 ){
            $email = $params[0];
            $password = $params[1];
        }else{
            $email = '';
            $password = '';
        }
        $data = DB::selectOne("select * from {$this->_table} where email = :email", [
            ":email"    => $email
        ]);
        if( empty($data) ){
            return false;
        }
        if( !Hash::check($password, $data->password) ){
            return false;
        }

        return true;
    }

}