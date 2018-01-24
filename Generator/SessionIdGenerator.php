<?php
namespace phpBB\SessionsAuthBundle\Generator;


use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Id\AbstractIdGenerator;

class SessionIdGenerator extends AbstractIdGenerator
{

    /**
     * Generates an identifier for an entity.
     *
     * @param EntityManager                $em
     * @param \Doctrine\ORM\Mapping\Entity $entity
     *
     * @return mixed
     * @throws \Exception
     */
    public function generate(EntityManager $em, $entity)
    {
        return md5(bin2hex(random_bytes(8)));
    }
}