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
    private $target;

    /**
     * @var string
     */
    private $exithost;

    /**
     * @var integer
     */
    private $port;

    /**
     * @var array
     */
    private $cache = array();

    /**
     * Constructor
     */
    private function __construct()
    {
        $this->target = implode(
            '.',
            array_reverse(
                explode(
                    '.',
                    $_SERVER['REMOTE_ADDR']
                )
            )
        );

        $this->exithost = implode(
            '.',
            array_reverse(
                explode(
                    '.',
                    $_SERVER["SERVER_ADDR"]
                )
            )
        );

        $this->port = $_SERVER["SERVER_PORT"];
    }

    /**
     * Wrapper for windows < 5.3 and, theoretically for
     * linux without dns_get_record() function
     *
     * @param $address
     *
     * @return array
     */
    private function dnsGetRecord($address)
    {
        if (!function_exists('dns_get_record') and !function_exists('exec')) {
            throw new \LogicException(
                'no suitable methods for dns fetching found'
            );
        }

        if (function_exists('dns_get_record')) {
            return dns_get_record(implode('.', $address), DNS_A);
        }

        $output = $dns = array();
        $retval = false;
        if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN') {
            @exec('nslookup -type A ' . $address, $output, $retval);
            if (!$retval and array_key_exists(1, $output)) {
                $output[0] = $output[1];
            }
        } else {
            @exec('host ' . $address, $output, $retval);
        }

        if (!$retval and array_key_exists(0, $output)) {
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
                sprintf(
                    '"%s" is not a valid value for target',
                    $target
                )
            );
        }

        return $this;
    }

    /**
     * @param $dns
     * @return bool
     */
    private function checkRecord($dns)
    {
        if (array_key_exists(0, $dns) and array_key_exists('ip', $dns[0])) {
            return ($dns[0]['ip'] == '127.0.0.2');
        }
        return false;
    }

    /**
     * @return mixed
     */
    public function isTorActive()
    {
        if (!array_key_exists($this->target, $this->cache)) {
            $query = array(
                $this->target,
                $this->port,
                $this->exithost,
                'ip-port.exitlist.torproject.org'
            );

            $dns = $this->dnsGetRecord(implode('.', $query));
            $isActive = $this->checkRecord($dns);

            $this->cache[$this->target] = $isActive;
        }

        return $this->cache[$this->target];
    }
}
