<?php

namespace TorDetect;

/**
 * Class TorDetect to determine if Remote User is using the TOR Network
 *
 * @author Alexander Over <cyberline@php.net>
 */
class TorDetect
{
    /**
     * @var object
     */
    private static $instance;

    /**
     * @var string
     */
    private $target = null;

    /**
     * @var string
     */
    private $exithost = null;

    /**
     * @var integer
     */
    private $port = 443;

    /**
     * @var array
     */
    private $cache = array();

    /**
     * Constructor
     */
    private function __construct()
    {
        if (isset($_SERVER) && array_key_exists('REMOTE_ADDR', $_SERVER)) {
            $this->setTarget($_SERVER['REMOTE_ADDR']);
        }

        if (isset($_SERVER) && array_key_exists('SERVER_ADDR', $_SERVER)) {
            $this->setExithost($_SERVER["SERVER_ADDR"]);
            $this->setPort($_SERVER["SERVER_PORT"]);
        }
    }

    /**
     * @param $target
     *
     * @return $this
     * @throws \InvalidArgumentException
     */
    public function setTarget($target)
    {
        if (filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $this->target = implode('.', array_reverse(explode('.', $target)));
        } else {
            throw new \InvalidArgumentException(
                sprintf('"%s" is not a valid value for target', $target)
            );
        }

        return $this;
    }

    /**
     * @param $exithost
     * @return $this
     */
    public function setExithost($exithost)
    {
        $this->exithost = $this->prepareExithost($exithost);

        return $this;
    }

    /**
     * @param integer $port
     * @return $this
     */
    public function setPort($port)
    {
        $this->port = intval($port);

        return $this;
    }

    /**
     * @return object|TorDetect
     */
    public static function getInstance()
    {
        if (!(self::$instance instanceof self)) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * @return mixed
     */
    public function isTorActive()
    {
        if (null === $this->target) {
            throw new \InvalidArgumentException('No target set. Use setTarget($ip) first.');
        }

        if (!array_key_exists($this->target, $this->cache)) {
            $this->doFreshCheck();
        }

        return $this->cache[$this->target];
    }

    private function doFreshCheck()
    {
        if (null === $this->exithost) {
            throw new \InvalidArgumentException('No exithost set. Use setExithost($host) first.');
        }

        $query = array(
            $this->target,
            $this->port,
            $this->exithost,
            'ip-port.exitlist.torproject.org'
        );

        $dns = $this->dnsGetRecord($query);
        $isActive = $this->checkRecord($dns);

        $this->cache[$this->target] = $isActive;
    }

    /**
     * Wrapper for windows < 5.3 and, theoretically for
     * linux without dns_get_record() function
     *
     * @param array $address
     *
     * @return array
     */
    private function dnsGetRecord(array $address)
    {
        if (!function_exists('dns_get_record') && !function_exists('exec')) {
            throw new \LogicException(
                'no suitable methods for dns fetching found'
            );
        }

        $address = implode('.', $address);
        if (function_exists('dns_get_record')) {
            return dns_get_record($address, DNS_A);
        }

        return $this->doFallbackCheck($address);
    }

    /**
     * @param string $address
     * @return array
     */
    private function doFallbackCheck($address)
    {
        $output = $dns = array();
        $retval = false;
        if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN') {
            @exec('nslookup -type A ' . $address, $output, $retval);
            if (!$retval && array_key_exists(1, $output)) {
                $output[0] = $output[1];
            }
        } else {
            @exec('host ' . $address, $output, $retval);
        }

        if (!$retval && array_key_exists(0, $output)) {
            $explode = explode(' ', $output[0]);
            $result = $explode[count($explode) - 1];
            if (filter_var($result, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $dns[0]['ip'] = $result;
            }
            unset($explode, $result);
        }

        return $dns;
    }

    /**
     * @param $dns
     * @return bool
     */
    private function checkRecord($dns)
    {
        if (array_key_exists(0, $dns) && array_key_exists('ip', $dns[0])) {
            return ($dns[0]['ip'] === '127.0.0.2');
        }

        return false;
    }

    /**
     * @param string $exithost
     * @return string
     */
    private function prepareExithost($exithost)
    {
        return implode('.', array_reverse(explode('.', $exithost)));
    }
}
