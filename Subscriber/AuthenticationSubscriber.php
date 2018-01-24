<?php

namespace phpBB\SessionsAuthBundle\Subscriber;

use Doctrine\ORM\NonUniqueResultException;
use phpBB\SessionsAuthBundle\Entity\Session;
use phpBB\SessionsAuthBundle\Entity\User;
use Symfony\Bridge\Doctrine\ManagerRegistry;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\AuthenticationEvents;
use Symfony\Component\Security\Core\Event\AuthenticationEvent;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;

class AuthenticationSubscriber implements EventSubscriberInterface
{
    /**
     * @var \Doctrine\Common\Persistence\ObjectManager|object
     */
    private $entityManager;

    /**
     * @var String
     */
    private $cookiePrefix;

    /**
     * @var Request
     */
    private $request;

    public function __construct(ManagerRegistry $registry, String $entity, String $cookieName)
    {
        $this->entityManager = $registry->getManager($entity);
        $this->cookiePrefix = $cookieName;
    }

    public static function getSubscribedEvents()
    {
        // return the subscribed events, their methods and priorities
        return array(
            SecurityEvents::INTERACTIVE_LOGIN => 'onAuthenticationSuccess',
        );
    }

    /**
     * @param InteractiveLoginEvent $event
     *
     * @throws \Exception
     */
    public function onAuthenticationSuccess(InteractiveLoginEvent $event)
    {
        $this->request = $event->getRequest();
        $user = $event->getAuthenticationToken()->getUser();

        if (!$user instanceof User) {
            return;
        }

        $sessionRepository = $this->entityManager->getRepository(Session::class);

        $session = $sessionRepository
            ->createQueryBuilder('s')
            ->select('s, u')
            ->join('s.user', 'u')
            ->where('u.id = :id')
            ->setParameter('id', $user->getId())
            ->orderBy('s.time', 'DESC')
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();

        if (!$session) {
            $session = new Session($user);
            $session->setUser($user);

            $cookieSessionKey = $this->getCookie('k');
            $session->setAutologin($cookieSessionKey ? true : false);
        }

        $session->setTime(time());
        $session->setIp($this->request->getClientIp());
        $session->setBrowser($this->request->headers->get('User-Agent'));

        $this->entityManager->persist($session);
        $this->entityManager->flush();

        $this->updateCookies($session->getId(), $user->getId());
    }

    private function updateCookies($sessionId, $userId)
    {
        $this->setCookie('sid', $sessionId);
        $this->setCookie('u', $userId);
    }

    /**
     * @param $cookieName
     *
     * @return bool|mixed
     */
    private function getCookie($cookieName)
    {
        $fullCookieName = $this->cookiePrefix . '_' . $cookieName;

        if (!$this->request->cookies->has($fullCookieName)) {
            return false;
        }

        return $this->request->cookies->get($fullCookieName);
    }

    private function setCookie($cookieName, $value)
    {
        $this->request->cookies->set($this->cookiePrefix . '_' . $cookieName, $value);
    }
}