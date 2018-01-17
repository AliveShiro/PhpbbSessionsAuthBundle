<?php
/**
 *
 * @package phpBBSessionsAuthBundle
 * @copyright (c) phpBB Limited <https://www.phpbb.com>
 * @license MIT
 * @author Unknown Bliss
 *
 */

namespace phpBB\SessionsAuthBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $treeBuilder
            ->root('phpbb_sessions_auth')
                ->children()
                    ->arrayNode('session')->isRequired()
                        ->children()
                            ->scalarNode('cookie_name')->isRequired()->end()
                            ->scalarNode('login_page')->defaultValue('ucp.php?mode=login')->cannotBeEmpty()->end()
                            ->scalarNode('ip_check')->defaultValue(3)->end()
                            ->booleanNode('force_login')->defaultValue(true)->end()
                        ->end()
                    ->end()
                    ->arrayNode('database')
                        ->children()
                            ->scalarNode('entity_manager')->isRequired()->end()
                            ->scalarNode('prefix')->isRequired()->end()
                        ->end()
                    ->end()
                    ->arrayNode('roles')
                        ->prototype('scalar')->end()
                    ->end()
                ->end()
        ;

        return $treeBuilder;
    }
}
