<?php

namespace phpBB\SessionsAuthBundle\Security;

use Symfony\Component\Security\Core\Encoder\BasePasswordEncoder;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class Encoder extends BasePasswordEncoder
{

    /**
     *
     * @param string $raw
     * @param string $salt
     *
     * @return string
     */
    public function encodePassword($raw, $salt = null)
    {
        if($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }

        return $this->phpbb_hash($raw);
    }

    /**
     *
     * @param string $encoded
     * @param string $raw
     * @param string $salt
     *
     * @return boolean
     */
    public function isPasswordValid($encoded, $raw, $salt = null)
    {
        if($this->isPasswordTooLong($raw)) {
            return false;
        }
        return $this->phpbb_check_hash($raw, $encoded);
    }

    /**
     * Hash the password
     *
     * @param string $password
     *
     * @return string
     */
    protected function phpbb_hash($password)
    {
        $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $random_state = uniqid();
        $random = '';
        $count = 6;
        if (($fh = @fopen('/dev/urandom', 'rb'))) {
            $random = fread($fh, $count);
            fclose($fh);
        }
        if (strlen($random) < $count) {
            $random = '';
            for ($i = 0; $i < $count; $i += 16) {
                $random_state = md5(uniqid() . $random_state);
                $random .= pack('H*', md5($random_state));
            }
            $random = substr($random, 0, $count);
        }
        $hash = $this->_hash_crypt_private($password, $this->_hash_gensalt_private($random, $itoa64), $itoa64);
        if (strlen($hash) == 34) {
            return $hash;
        }
        return md5($password);
    }

    /**
     * Check for correct password
     *
     * @param string $password
     * @param string $hash
     *
     * @return boolean
     */
    protected function phpbb_check_hash($password, $hash)
    {
        $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        if (strlen($hash) == 34) {
            return ($this->_hash_crypt_private($password, $hash, $itoa64) === $hash) ? true : false;
        }
        return (md5($password) === $hash) ? true : false;
    }

    /**
     * Generate salt for hash generation
     *
     * @param string $input
     * @param string $itoa64
     * @param int    $iteration_count_log2
     *
     * @return string
     */
    protected function _hash_gensalt_private($input, &$itoa64, $iteration_count_log2 = 6)
    {
        if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31) {
            $iteration_count_log2 = 8;
        }
        $output = '$H$';
        $output .= $itoa64[min($iteration_count_log2 + ((PHP_VERSION >= 5) ? 5 : 3), 30)];
        $output .= $this->_hash_encode64($input, 6, $itoa64);
        return $output;
    }

    /**
     * Encode hash
     *
     * @param string $input
     * @param int    $count
     * @param string $itoa64
     *
     * @return string
     */
    protected function _hash_encode64($input, $count, &$itoa64)
    {
        $output = '';
        $i = 0;
        do {
            $value = ord($input[$i++]);
            $output .= $itoa64[$value & 0x3f];
            if ($i < $count) {
                $value |= ord($input[$i]) << 8;
            }
            $output .= $itoa64[($value >> 6) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            if ($i < $count) {
                $value |= ord($input[$i]) << 16;
            }
            $output .= $itoa64[($value >> 12) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            $output .= $itoa64[($value >> 18) & 0x3f];
        } while ($i < $count);
        return $output;
    }

    /**
     * The crypt function/replacement
     *
     * @param type $password
     * @param type $setting
     * @param type $itoa64
     *
     * @return string
     */
    protected function _hash_crypt_private($password, $setting, &$itoa64)
    {
        $output = '*';
        // Check for correct hash
        if (substr($setting, 0, 3) != '$H$') {
            return $output;
        }
        $count_log2 = strpos($itoa64, $setting[3]);
        if ($count_log2 < 7 || $count_log2 > 30) {
            return $output;
        }
        $count = 1 << $count_log2;
        $salt = substr($setting, 4, 8);
        if (strlen($salt) != 8) {
            return $output;
        }
        // We're kind of forced to use MD5 here since it's the only
        // cryptographic primitive available in all versions of PHP
        // currently in use. To implement our own low-level crypto
        // in PHP would result in much worse performance and
        // consequently in lower iteration counts and hashes that are
        // quicker to crack (by non-PHP code).
        $hash = md5($salt . $password, true);
        do {
            $hash = md5($hash . $password, true);
        } while (--$count);
        $output = substr($setting, 0, 12);
        $output .= $this->_hash_encode64($hash, 16, $itoa64);
        return $output;
    }
}
