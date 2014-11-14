<?php
require_once 'src/TorDetect.php';

try {
    $instance = \TorDetect\TorDetect::getInstance();

    // check current users ip and
    // return 1 or 0
    print intval($instance->isTorActive());

    // check ip of another user
    print intval($instance->setTarget('1.2.3.4')->isTorActive());
} catch (\Exception $e) {
    print $e->getMessage();
}
