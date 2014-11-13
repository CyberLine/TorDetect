# TorDetect

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/CyberLine/TorDetect/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/CyberLine/TorDetect/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/CyberLine/TorDetect/badges/build.png?b=master)](https://scrutinizer-ci.com/g/CyberLine/TorDetect/build-status/master)

Tor is collaborative network that allows people to access sites hiding their original IP addresses to avoid being tracked.
Many sites do not like to allow accesses of users that use the Tor network, as users may use anonymous access perform illegal activities.
This class provides a solution that allows to determine if an user is accessing a site using the Tor network.
This allows a PHP site to disallow the user to access a site using the Tor network.

## Example

	<?php
	require_once 'src/TorDetect.php';

    try {
        $instance = \TorDetect\TorDetect::getInstance();
        
        // check current users ip and
        // return true or false
        var_dump($instance->isTorActive());
    
        // check ip of another user
        var_dump($instance->setTarget('1.2.3.4')->isTorActive());
    } catch (\Exception $e) {
        print $e->getMessage();
    }