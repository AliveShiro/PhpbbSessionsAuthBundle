<?php

namespace phpBB\SessionsAuthBundle\Security;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\SimpleFormAuthenticatorInterface;

class FormAuthenticator implements SimpleFormAuthenticatorInterface, AuthenticationSuccessHandlerInterface
{
    private $encoder;
    private $targetPath = '/';
    private $cookiePrefix = '';

    public function __construct(UserPasswordEncoderInterface $encoder, String $targetPath, String $cookiePrefix)
    {
        $this->encoder = $encoder;
        $this->targetPath = $targetPath;
        $this->cookiePrefix = $cookiePrefix;
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        try {
            $user = $userProvider->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $e) {
            // CAUTION: this message will be returned to the client
            // (so don't put any un-trusted messages / error strings here)
            throw new CustomUserMessageAuthenticationException('Invalid username or password');
        }

        $passwordValid = $this->encoder->isPasswordValid($user, $token->getCredentials());

        if ($passwordValid) {
            return new UsernamePasswordToken(
                $user,
                $user->getPassword(),
                $providerKey,
                $user->getRoles()
            );
        }

        // CAUTION: this message will be returned to the client
        // (so don't put any un-trusted messages / error strings here)
        throw new CustomUserMessageAuthenticationException('Invalid username or password');
    }

    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken
            && $token->getProviderKey() === $providerKey;
    }

    /**
     * @param Request $request
     * @param         $username
     * @param         $password
     * @param         $providerKey
     *
     * @return UsernamePasswordToken
     */
    public function createToken(Request $request, $username, $password, $providerKey)
    {
        return new UsernamePasswordToken($username, $password, $providerKey);
    }

    /**
     * This is called when an interactive authentication attempt succeeds. This
     * is called by authentication listeners inheriting from
     * AbstractAuthenticationListener.
     *
     * @return Response never null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $response = new RedirectResponse($this->targetPath);

        $sidCookieName = $this->getFullCookieName('sid');
        $userIdCookieName = $this->getFullCookieName('u');

        $sid = $request->cookies->get($sidCookieName);
        $userId = $request->cookies->get($userIdCookieName);

        $response->headers->setCookie(new Cookie($sidCookieName, $sid, strtotime('+1 week')));
        $response->headers->setCookie(new Cookie($userIdCookieName, $userId, strtotime('+1 week')));

        return $response;
    }

    /**
     * @param $cookieName
     *
     * @return string
     */
    private function getFullCookieName($cookieName) {
        return $this->cookiePrefix . '_' . $cookieName;
    }
}