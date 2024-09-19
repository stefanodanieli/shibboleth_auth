<?php

namespace Polimiacre\ShibbolethAuth\Hook;

use TYPO3\CMS\Core\Utility\StringUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\HttpUtility;

/**
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

class UserAuthentication
{

    public function backendLogoutHandler()
    {
        //HttpUtility::redirect($targetUrl);
        // Delete the Shibboleth session cookie
        foreach ($_COOKIE as $name => $value) {
            if (\str_starts_with($name, '_shibsession_')) {
                $GLOBALS['BE_USER']->writelog(255, 2, 0, 2, "hook su cookie attivato" , array("hook su cookie attivato"), '', 0, 0);
                setcookie($name, null, -1, '/');
                setcookie($name, "", time() - 3600);
                break;
            }
        }
        setcookie("be_typo_user", "", -1, '/');

    }
}
