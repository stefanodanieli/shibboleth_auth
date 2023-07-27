<?php

use Polimiacre\ShibbolethAuth\Controller\FrontendLoginController;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use Polimiacre\ShibbolethAuth\Hook\UserAuthentication;
use Polimiacre\ShibbolethAuth\LoginProvider\ShibbolethLoginProvider;
use TYPO3\CMS\Extbase\Utility\ExtensionUtility;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use Polimiacre\ShibbolethAuth\Typo3\Service\ShibbolethAuthenticationService;
use Polimiacre\ShibbolethAuth\Backend\Controller\LogoutController as LogoutControllerXclass;
use TYPO3\CMS\Backend\Controller\LogoutController;


defined('TYPO3') || die();

(function ($extKey = 'shibboleth_auth') {
    $extensionConfiguration = GeneralUtility::makeInstance(
        ExtensionConfiguration::class
    )->get($extKey);

    $subTypes = [];

    if ($extensionConfiguration['enableBE']) {
        $subTypes[] = 'getUserBE';
        $subTypes[] = 'authUserBE';

        $GLOBALS['TYPO3_CONF_VARS']['SVCONF']['auth']['setup']['BE_fetchUserIfNoSession'] = $extensionConfiguration['BE_fetchUserIfNoSession'];

        // Register backend logout handler
        $GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_userauth.php']['logoff_post_processing'][] = UserAuthentication::class . '->backendLogoutHandler';

        $GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['backend']['loginProviders'][1518433441] = [
            'provider' => ShibbolethLoginProvider::class,
            'sorting' => 60,
            'icon-class' => 'fa-sign-in',
            'iconIdentifier' => 'actions-key',
            'label' => 'LLL:EXT:shibboleth_auth/Resources/Private/Language/locallang.xlf:backend_login.header'
        ];
    }

    if ($extensionConfiguration['enableFE']) {
        // Register FE user authentication subtypes
        $subTypes[] = 'getUserFE';
        $subTypes[] = 'authUserFE';

        // Register FE plugin
        ExtensionUtility::configurePlugin(
            'ShibbolethAuth',
            'Login',
            [
                FrontendLoginController::class => 'index,login,loginSuccess,logout,logoutSuccess',
            ],
            // non-cacheable actions
            [
                FrontendLoginController::class => 'index,loginSuccess,logoutSuccess',
            ]
        );

        // Configure if session should be fetched on each page load
        $GLOBALS['TYPO3_CONF_VARS']['SVCONF']['auth']['setup']['FE_fetchUserIfNoSession'] = $extensionConfiguration['FE_fetchUserIfNoSession'];
    }

    // Register authentication service
    ExtensionManagementUtility::addService(
        $extKey,
        'auth',
        ShibbolethAuthenticationService::class,
        [
            'title' => 'Shibboleth Authentication',
            'description' => 'Shibboleth Authentication service (BE & FE)',

            'subtype' => implode(',', $subTypes),

            'available' => true,
            'priority' => $extensionConfiguration['priority'],
            'quality' => 50,

            'os' => '',
            'exec' => '',

            'className' => ShibbolethAuthenticationService::class,
        ]
    );

    // Use popup window to refresh login instead of the AJAX relogin
    $GLOBALS['TYPO3_CONF_VARS']['BE']['showRefreshLoginPopup'] = 1;

    $GLOBALS['TYPO3_CONF_VARS']['SYS']['Objects'][LogoutController::class] = [
        'className' => LogoutControllerXclass::class,
    ];
})();
