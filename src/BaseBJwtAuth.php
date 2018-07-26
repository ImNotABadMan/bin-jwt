<?php
/**
 * Created by PhpStorm.
 * User: IT
 * Date: 2018/7/24
 * Time: 16:45
 */

namespace Jwt;


class BaseBJwtAuth
{
    protected $_config;

    protected $_header = [
      'typ' => 'typ', // 接口类型
      'alg' => 'alg', // 加密类型
    ];

    protected $_payload = [
        'iss' => 'iss', // 发布token的一方
        'sub' => 'sub', // token的主题
        'aud' => 'aud', // 接受token的一方
        'exp' => 'exp', // 过期时长
        'ndf' => 'ndf', // 在什么时间前不能使用
        'iat' => 'iat', // token创建时间
        'jti' => 'jti', // 唯一标识，用来一次性token
    ];

    protected $_alg;

    protected $_exp = 3600;

    protected $_algMap = [
        'HS256' => 'sha256'
    ];

    public function __construct()
    {
        $this->_config = config('jwt');
    }

    public function __get($name)
    {
        // TODO: Implement __get() method.
        if( is_array($name) ) {
            $keyArr = implode('.', $name);
            $attr = '_' . $keyArr[0];
            if( isset($this->$attr) ){
                return $this->$attr[$keyArr[1]];
            }
        }
        if( is_string($name) ){
            $attr = '_' . $name;
            return $this->$attr;
        }

        return null;
    }

    public function __set($name, $value)
    {
        // TODO: Implement __set() method.
        if( is_string($name) ){
            $attr = '_' . $name;
            $this->$attr = $value;
        }
    }

    public function getToken($header, $payload, $config = [])
    {
        if( !empty($config) && isset($config['jwt_secret']) ){
            $this->_config['jwt_secret'] = $config['jwt_secret'];
        }

        $this->_alg = $header['alg'];
        $this->_exp = $payload['exp'];

        $token = $this->encodeToken($header, $payload);

        return $token;
    }

    /**
     * $flag json_decode 的第二格参数
    */
    public function decodeToken($token, $flag = false)
    {
        list($header, $payload, $signature) = explode('.', $token);

        $headerDecode = json_decode(base64_decode($header), $flag);
        $payloadDecode = json_decode(base64_decode($payload), $flag);

        return [
            "header"    => $headerDecode,
            "payload"   => $payloadDecode,
            "signature" => $signature
        ];
    }

    public function encodeToken($header, $payload)
    {
        $headerEncode = base64_encode(json_encode($header));
        $payloadEncode = base64_encode(json_encode($payload));

        $encode = $headerEncode . '.'. $payloadEncode;
        $signature = hash_hmac($this->_algMap[$header['alg']], $encode, $this->_config['jwt_secret']);

        return $headerEncode . '.' . $payloadEncode . '.' . $signature;
    }

    public function outOfTime($token = '')
    {
        if( !$token ){
            $decode = $this->decodeToken($token);
            $this->_payload = $decode['payload'];
        }
        return strtotime($this->_payload['iat']) + $this->_payload['exp'] < time();
    }

    public function isAuth($token)
    {
        list($header, $payload, $signature) = explode('.', $token);

        $decodeArr = $this->decodeToken($token, true);

        $this->_header['alg'] = $decodeArr["header"]['alg'];
        $this->_payload['iat'] = $decodeArr["payload"]['iat'];
        $this->_payload['exp'] = $decodeArr["payload"]['exp'];

        if( !isset($decodeArr["header"]['alg']) ){
            return false;
        }

        $localSignature = hash_hmac($this->_algMap[$decodeArr["header"]['alg']], strrchr($token, '.'), $this->_config['jwt_secret']);

        if( strpos($signature, $localSignature) !== 0){
            return false;
        }

        return true;
    }
}





