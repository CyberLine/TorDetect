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
