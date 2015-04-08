<?php

namespace garyrutland\crypt;

use yii\base\Component;
use Exception;

class Crypt extends Component
{
    public $salt;

    public function init()
    {
        parent::init();

        if (!extension_loaded('mcrypt')) {
            throw new Exception('Extension "mcrypt" not loaded');
        }
    }

    public function encrypt($data)
    {
        if (!empty($data)) {
            $crypt = mcrypt_module_open(MCRYPT_RIJNDAEL_128, null, 'cbc', null);
            $encryptionKey = substr($this->salt, 0, mcrypt_enc_get_key_size($crypt));

            $ivSize = mcrypt_enc_get_iv_size($crypt);
            $iv = mcrypt_create_iv($ivSize, MCRYPT_RAND);
            mcrypt_generic_init($crypt, $encryptionKey, $iv);

            $cT = mcrypt_generic($crypt, json_encode($data));

            mcrypt_generic_deinit($crypt);
            mcrypt_module_close($crypt);

            return strtr(base64_encode($iv . $cT), '+/=', '-_,');
        }
    }

    public function decrypt($data)
    {
        if (empty($data) || !is_string($data)) {
            return;
        }

        $cT = base64_decode(strtr(urldecode($data), '-_,', '+/='));

        if (!empty($cT)) {
            $crypt = mcrypt_module_open(MCRYPT_RIJNDAEL_128, null, 'cbc', null);
            $ivSize = mcrypt_enc_get_iv_size($crypt);

            $iv = substr($cT, 0, $ivSize);
            $cT = substr($cT, $ivSize, strlen($cT) - $ivSize);

            if (!empty($cT)) {
                $encryptionkey = substr($this->salt, 0, mcrypt_enc_get_key_size($crypt));
                mcrypt_generic_init($crypt, $encryptionkey, $iv);

                $pT = mdecrypt_generic($crypt, $cT);

                mcrypt_generic_deinit($crypt);
                mcrypt_module_close($crypt);

                return json_decode(trim($pT), true);
            }
        }
    }
}