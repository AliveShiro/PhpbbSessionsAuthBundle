<?php

namespace phpBB\SessionsAuthBundle\Security;

use Symfony\Component\Security\Core\Encoder\BasePasswordEncoder;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class Encoder extends BasePasswordEncoder
{
    protected $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    var $iteration_count_log2;
    var $portable_hashes;
    var $random_state;

    /**
     * Called when a user tries to save a new password
     *
     * @param string $raw
     * @param string $salt
     *
     * @return string
     */
    public function encodePassword($raw, $salt = null)
    {
        if ($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }

        return $this->phpbb_hash($raw);
    }

    /**
     * Called when a user tries to login
     *
     * @param string $encoded
     * @param string $raw
     * @param string $salt
     *
     * @return boolean
     */
    public function isPasswordValid($encoded, $rawPassword, $salt = null)
    {
        if ($this->isPasswordTooLong($rawPassword)) {
            return false;
        }

        $passwordHasher = new PasswordHash(8, TRUE);

        $hash = $passwordHasher->HashPassword($rawPassword);

        return $passwordHasher->CheckPassword($rawPassword, $encoded);

        // return $this->checkPasswordWithHash($rawPassword, $encoded, $salt);
    }

    /**
     * Check for correct password
     *
     * @param string $password
     * @param string $hash
     *
     * @return boolean
     */
    protected function checkPasswordWithHash($password, $storedHash, $salt)
    {
        $passwordHash = $this->cryptPassword($password, $storedHash);

        if ($passwordHash[0] == '*') {
            $passwordHash = crypt($password, $salt);
        }

        return $passwordHash == $storedHash;
    }

    /**
     * @param $password
     * @param $storedHash
     *
     * @return bool|string
     */
    protected function cryptPassword($password, $storedHash)
    {
        $output = '*0';
        if (substr($storedHash, 0, 2) == $output) {
            $output = '*1';
        }

        if (substr($storedHash, 0, 3) != '$H$') {
            return $output;
        }

        $count_log2 = strpos($this->itoa64, $storedHash[3]);

        if ($count_log2 < 7 || $count_log2 > 30) {
            return $output;
        }

        $count = 1 << $count_log2;
        $salt = substr($storedHash, 4, 8);
        if (strlen($salt) != 8) {
            return $output;
        }

        # We're kind of forced to use MD5 here since it's the only
        # cryptographic primitive available in all versions of PHP
        # currently in use.  To implement our own low-level crypto
        # in PHP would result in much worse performance and
        # consequently in lower iteration counts and hashes that are
        # quicker to crack (by non-PHP code).
        if (PHP_VERSION >= '5') {
            $hash = md5($salt . $password, TRUE);
            do {
                $hash = md5($hash . $password, TRUE);
            } while (--$count);
        } else {
            $hash = pack('H*', md5($salt . $password));
            do {
                $hash = pack('H*', md5($hash . $password));
            } while (--$count);
        }

        $output = substr($storedHash, 0, 12);
        $output .= $this->encode64($hash, 16);

        return $output;
    }

    /**
     * @param $input
     * @param $count
     *
     * @return string
     */
    protected function encode64($input, $count)
    {
        $output = '';
        $i = 0;
        do {
            $value = ord($input[$i++]);
            $output .= $this->itoa64[$value & 0x3f];
            if ($i < $count)
                $value |= ord($input[$i]) << 8;
            $output .= $this->itoa64[($value >> 6) & 0x3f];
            if ($i++ >= $count)
                break;
            if ($i < $count)
                $value |= ord($input[$i]) << 16;
            $output .= $this->itoa64[($value >> 12) & 0x3f];
            if ($i++ >= $count)
                break;
            $output .= $this->itoa64[($value >> 18) & 0x3f];
        } while ($i < $count);
        return $output;
    }
}
