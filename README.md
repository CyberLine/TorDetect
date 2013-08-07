# TorDetect

Tor is collaborative network that allows people to access sites hiding their original IP addresses to avoid being tracked.
Many sites do not like to allow accesses of users that use the Tor network, as users may use anonymous access perform illegal activities.
This class provides a solution that allows to determine if an user is accessing a site using the Tor network.
This allows a PHP site to disallow the user to access a site using the Tor network.

## Example

	<?php
	require_once 'TorDetect.php';

	// check current users ip and
	// return true or false
	var_dump(Tor::getInstance()->isTorActive());

	// check ip of another user
	var_dump(Tor::getInstance()->setTarget('1.2.3.4')->isTorActive());
