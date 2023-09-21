<?php

namespace Polimiacre\ShibbolethAuth\Typo3\Service;

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

use Symfony\Component\HttpFoundation\Cookie;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Http\ApplicationType;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Backend\Exception;
use TYPO3\CMS\Core\Authentication\AbstractAuthenticationService;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class ShibbolethAuthenticationService extends AbstractAuthenticationService
{

    protected $extKey = 'shibboleth_auth';

    protected $extensionConfiguration = [];

    protected $remoteUser = '';

    /**
    * beUserRepository
    *
    * @var TYPO3\CMS\Beuser\Domain\Repository\BackendUserRepository
     * @TYPO3\CMS\Extbase\Annotation\Inject
     */
    protected $beUserRepository = null;


    /**
     * persistenceManager
     * @var \TYPO3\CMS\Extbase\Persistence\Generic\PersistenceManager
     * @TYPO3\CMS\Extbase\Annotation\Inject
     */
    protected $persistenceManager;


    /**
     * @param TYPO3\CMS\Beuser\Domain\Repository\BackendUserRepository $beUserRepository
     */
    public function injectBackendUserRepository(\TYPO3\CMS\Beuser\Domain\Repository\BackendUserRepository $beUserRepository)
    {
        $this->beUserRepository = $beUserRepository;
    }



    public function init(): bool
    {
        $this->extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class)->get(
            'shibboleth_auth'
        );
        if (empty($this->extensionConfiguration['remoteUser'])) {
            $this->extensionConfiguration['remoteUser'] = 'REMOTE_USER';
        }
        if (empty($this->extensionConfiguration['displayName'])) {
            $this->extensionConfiguration['displayName'] = 'REMOTE_USER';
        }
        $this->remoteUser = $_SERVER[$this->extensionConfiguration['remoteUser']];
        $this->persistenceManager = GeneralUtility::makeInstance(PersistenceManager::class);
        $this->beUserGroupRepository = GeneralUtility::makeInstance(\TYPO3\CMS\Beuser\Domain\Repository\BackendUserGroupRepository::class);
        $this->beUserRepository = GeneralUtility::makeInstance(\TYPO3\CMS\Beuser\Domain\Repository\BackendUserRepository::class);
        return parent::init();
    }

    /**
     * Initialize authentication service
     *
     * @param string $mode Subtype of the service which is used to call the service.
     * @param array $loginData Submitted login form data
     * @param array $authInfo Information array. Holds submitted form data etc.
     * @param AbstractUserAuthentication $pObj Parent object
     */
    public function initAuth($mode, $loginData, $authInfo, $pObj): void
    {
        if (Environment::isCli()) {
            parent::initAuth($mode, $loginData, $authInfo, $pObj);
        }

        // bypass Shibboleth login if enableFE is 0
        //if (!($this->extensionConfiguration['enableFE']) && ApplicationType::fromRequest($GLOBALS['TYPO3_REQUEST'])->isFrontend()) {
        //    parent::initAuth($mode, $loginData, $authInfo, $pObj);
       // }

        $this->login = $loginData;
        if (empty($this->login['uname']) && empty($this->remoteUser)) {
            parent::initAuth($mode, $loginData, $authInfo, $pObj);
        } else {
            $loginData['status'] = 'login';
            parent::initAuth($mode, $loginData, $authInfo, $pObj);
        }
    }
    //questo metodo deriva dalla classe TYPO3\CMS\Core\Authentication\AuthenticationService, ed è tratto come esempio
    // da questa documentazione : https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ApiOverview/Services/UsingServices/ServiceChain.html
    public function getUser()
    {
        $user = false;

        if ($this->login['status'] == 'login' && $this->isShibbolethLogin() && empty($this->login['uname'])) {
            $user = $this->fetchUserRecord($this->remoteUser);

            if (!is_array($user) || empty($user)) {
                if ($this->isLoginTypeFrontend(
                    ) && !empty($this->remoteUser) && $this->extensionConfiguration['enableAutoImport']) {
                    $this->importFrontendUser();
                }
                else {
                    $user = false;
                    // Failed login attempt (no username found)
                    $this->writelog(
                        255,
                        3,
                        3,
                        2,
                        "Login attempt from %s (%s), username '%s' not found!",
                        [$this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->remoteUser]
                    );
                }
                if ($this->isLoginTypeBackend()){
                    $this->importBackendUser();
                }
            } else {
                if ($this->isLoginTypeFrontend() && $this->extensionConfiguration['enableAutoImport']) {
                    $this->updateFrontendUser();
                }
                if ($this->isLoginTypeBackend() && $this->extensionConfiguration['enableAutoImportBE']) {
                    $this->updateBackendUser();
                }
            }
            if ($this->isLoginTypeFrontend()) {
                // The frontend user was updated, it should be fetched again
                $user = $this->fetchUserRecord($this->remoteUser);
            }
            if ($this->isLoginTypeBackend()) {
                // The frontend user was updated, it should be fetched again
                $user = $this->fetchUserRecord($this->remoteUser);
            }
        }

        // Deny Backend login for non-Shibboleth authentication if onlyShibbolethFunc is set
        if (!(Environment::isCli()) && $this->authInfo['loginType'] === 'BE' && $this->extensionConfiguration['onlyShibbolethBE'] && empty($user)) {
            // Implement your own error page
            if (is_array($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['onlyShibbolethFunc'])) {
                foreach ($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['onlyShibbolethFunc'] as $_classRef) {
                    $_procObj = GeneralUtility::makeInstance($_classRef);
                    $_procObj->onlyShibbolethFunc($this->remoteUser);
                }
            } else {
                throw new Exception(
                    'Login without Shibboleth is not permitted.',
                    1616498840
                );
            }
            foreach ($_COOKIE as $key => $val) {
                unset($_COOKIE[$key]);
            }
            exit;
        }
        return $user;
    }

    /**
     * Authenticate a user (Check various conditions for the user that might invalidate its authentication, eg. password match, domain, IP, etc.)
     *
     * Will return one of following authentication status codes:
     *  - 0 - authentication failure
     *  - 100 - just go on. User is not authenticated but there is still no reason to stop
     *  - 200 - the service was able to authenticate the user
     */
    public function authUser(array $user): int
    {
        // user è un BE_USER object typo3 , mentre this->remoteUser è una stringa contenente il codice persona; $this->>getServerVar['mail'] restituisce invece i campi che arrivano da shibboleth (in questo caso, il campo mail).
        $OK = 100;

        if (Environment::isCli()) {
            $OK = 100;
        } else {
            if (($this->isLoginTypeFrontend()) && !empty($this->login['uname'])) {
                $OK = 100;
            } else {
                if ($this->isShibbolethLogin() && !empty($user) && ($this->remoteUser === $user[$this->authInfo['db_user']['username_column']])) {
                    $OK = 200;
//                    if ($user['lockToDomain'] && $user['lockToDomain'] !== $this->authInfo['HTTP_HOST']) {
//                        // Lock domain didn't match, so error:
//                        if ($this->writeAttemptLog) {
//                            $this->writelog(
//                                255,
//                                3,
//                                3,
//                                1,
//                                "Login attempt from %s (%s), username '%s', locked domain '%s' did not match '%s'!",
//                                [
//                                    $this->authInfo['REMOTE_ADDR'],
//                                    $this->authInfo['REMOTE_HOST'],
//                                    $user[$this->authInfo['db_user']['username_column']],
//                                    $user['lockToDomain'],
//                                    $this->authInfo['HTTP_HOST']
//                                ]
//                            );
//                        }
//                        $OK = 0;
//                    }
                }
            }
        }

        return $OK;
    }

    /**
     * Creates a new FE user from the current Shibboleth data
     */
    protected function importFrontendUser(): void
    {
        $this->writelog(255, 3, 3, 2, 'Importing user %s.', [$this->remoteUser]);
        $this->getDatabaseConnectionForFrontendUsers()->insert(
            $this->authInfo['db_user']['table'],
            [
                'crdate' => time(),
                'tstamp' => time(),
                'pid' => $this->extensionConfiguration['storagePid'],
                'username' => $this->remoteUser,
                'password' => $this->getRandomPassword(),
                'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                'name' => $this->getServerVar($this->extensionConfiguration['displayName']),
                'usergroup' => $this->getFEUserGroups(),
            ]
        );
    }

    /**
     * Creates a new BE user from the current Shibboleth data
     */
    protected function importBackendUser(): void
    {
        $this->writelog(255, 3, 3, 2, 'Importing BE user %s.', [$this->remoteUser]);
        $entitlement = $this->getServerVar($this->extensionConfiguration['eduPersonAffiliation']);
        $aunicaWebsiteUsers = $this->extensionConfiguration['AunicaWebsiteUsers'];
        $aunicaWebsiteAdmins = $this->extensionConfiguration['AunicaWebsiteAdmins'];

        // by S.D : estraggo l'array di tutti nomi dei backend groups, poichè la lista è molto piu breve rispetto all'entitlement


        if (strpos($entitlement,$aunicaWebsiteAdmins)){
            //gruppo admin
            $this->getDatabaseConnectionForBackendUsers()->insert(
                $this->authInfo['db_user']['table'],
                [
                    'crdate' => time(),
                    'tstamp' => time(),
                    'pid' => 0,
                    'username' => $this->remoteUser,
                    'password' => $this->getRandomPassword(),
                    'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                    //'realName' => $this->getServerVar($this->extensionConfiguration['displayName']),
                    'admin' => 1,
                ]
            );
        }
        else {
            // gruppo generico : a questo punto verifico se il gruppo esiste tra i gruppi BE
            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('be_groups');
            $result = $queryBuilder
                ->select('uid','title')
                ->from('be_groups')
                ->execute();
            $usergroup_ids = "";
            while ($row = $result->fetchAssociative()) {
                // faccio il match tra i singoli nomi dei gruppi BE e il campo entitlement, che contiene una stringa con tutti i gruppi AUNICA
                if (strpos($entitlement, $row['title'])) {
                $usergroup_ids = $usergroup_ids . $row['uid'] . ",";
                }
            }
            // elimino l'ultima virgola della sequenza (e.g. 1,3,5,7,) perchè non necessaria
            $usergroup = rtrim($usergroup_ids,",");
            if ($usergroup_ids !== ''){
                $this->getDatabaseConnectionForBackendUsers()->insert(
                    $this->authInfo['db_user']['table'],
                    [
                        'crdate' => time(),
                        'tstamp' => time(),
                        'pid' => 0,
                        'username' => $this->remoteUser,
                        'password' => $this->getRandomPassword(),
                        'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                        'options' => 3,
                        'workspace_id' => 0,
                        'workspace_perms' => 1,
                        'usergroup' => $usergroup_ids,
                        'admin' => 0,
                        'file_permissions' => "readFolder,writeFolder,addFolder,renameFolder,moveFolder,deleteFolder,readFile,writeFile,addFile,renameFile,replaceFile,moveFile,copyFile,deleteFile",
                    ]
                );
            }
        }


        // by S.D : commmento su vecchio codice

//        if (strpos($entitlement,$aunicaWebsiteUsers)){
//
//            $beuser = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(\Polimi\ShibbolethAuth\Domain\Model\BackendUser::class);
//            $beuser->setUserName($this->remoteUser);
//            $beuser->setPassword($this->getRandomPassword());
//            $beuser->setPid(0);
//            $beuser->setEmail($this->getServerVar($this->extensionConfiguration['mail']));
//            $beuser->setOptions(3);
//            $beuser->setWorkspaceId(0);
//            $beuser->setWorkspacePerms(1);
//            $beuser->setFilePermissions("readFolder,writeFolder,addFolder,renameFolder,moveFolder,deleteFolder,readFile,writeFile,addFile,renameFile,replaceFile,moveFile,copyFile,deleteFile");
//            if ($beuser->getBackendUserGroups() == null){
//                $objStorage = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(\TYPO3\CMS\Extbase\Persistence\ObjectStorage::class);
//                $beuser->setBackendUserGroups($objStorage);
//            }
//            $beusergroup = $this->beUserGroupRepository->findOneByTitle($aunicaWebsiteUsers);
//            $beuser->getBackendUserGroups()->attach($beusergroup);
//            //$beuser->setBackendUserGroups(null);
//
//            // by :S.D : effettuo un'interrogazione lato database per estrarre l'UID di AunicaWebsiteUsers
//            $queryBuilderBeGroups =  $this->getDatabaseConnectionForBackendUserGroups();
//            $uidGroup = $queryBuilderBeGroups
//                ->select('uid')
//                ->from('be_groups')
//                ->where(
//                    $queryBuilderBeGroups->expr()->eq('title', $queryBuilderBeGroups->createNamedParameter($aunicaWebsiteUsers))
//                )
//                ->executeQuery()
//                ->fetchOne();
//
//            // inserisco il BE_USER
//            $this->getDatabaseConnectionForBackendUsers()->insert(
//                $this->authInfo['db_user']['table'],
//                [
//                    'crdate' => time(),
//                    'tstamp' => time(),
//                    'pid' => 0,
//                    'username' => $this->remoteUser,
//                    'password' => $this->getRandomPassword(),
//                    'email' => $this->getServerVar($this->extensionConfiguration['mail']),
//                    'options' => 3,
//                    'workspace_id' => 0,
//                    'workspace_perms' => 1,
//                    'usergroup' => $uidGroup,
//                    'admin' => 0,
//                    'file_permissions' => "readFolder,writeFolder,addFolder,renameFolder,moveFolder,deleteFolder,readFile,writeFile,addFile,renameFile,replaceFile,moveFile,copyFile,deleteFile",
//                ]
//            );
//
//        }
//        else if (strpos($entitlement,$aunicaWebsiteAdmins)){
//
//            $this->getDatabaseConnectionForBackendUsers()->insert(
//                $this->authInfo['db_user']['table'],
//                [
//                    'crdate' => time(),
//                    'tstamp' => time(),
//                    'pid' => 0,
//                    'username' => $this->remoteUser,
//                    'password' => $this->getRandomPassword(),
//                    'email' => $this->getServerVar($this->extensionConfiguration['mail']),
//                    //'realName' => $this->getServerVar($this->extensionConfiguration['displayName']),
//                    'admin' => 1,
//                ]
//            );
//        }

    }

    /**
     * Updates an existing FE user with the current data provided by Shibboleth
     */
    protected function updateFrontendUser(): void
    {
        $this->writelog(255, 3, 3, 2, 'Updating user %s.', [$this->getServerVar('cn')]);
        $this->getDatabaseConnectionForFrontendUsers()->update(
            $this->authInfo['db_user']['table'], // table
            [
                'tstamp' => time(),
                'username' => $this->remoteUser,
                'password' => $this->getRandomPassword(),
                'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                //'realName' => $this->getServerVar($this->extensionConfiguration['displayName']),
                'usergroup' => $this->getFEUserGroups(),
            ],
            [
                'username' => $this->remoteUser,
                'pid' => $this->extensionConfiguration['storagePid'],
            ]
        );
    }

    /**
     * Updates an existing BE user with the current data provided by Shibboleth
     */
    protected function updateBackendUser(): void
    {


        $this->writelog(255, 3, 3, 2, 'Updating user %s.', [$this->remoteUser]);
        $entitlement = $this->getServerVar($this->extensionConfiguration['eduPersonAffiliation']);
        $aunicaWebsiteUsers = $this->extensionConfiguration['AunicaWebsiteUsers'];
        $aunicaWebsiteAdmins = $this->extensionConfiguration['AunicaWebsiteAdmins'];

        if (strpos($entitlement,$aunicaWebsiteAdmins)){
            //gruppo admin
            $this->getDatabaseConnectionForBackendUsers()->update(
                $this->authInfo['db_user']['table'],
                [
                    'crdate' => time(),
                    'tstamp' => time(),
                    'username' => $this->remoteUser,
                    'password' => $this->getRandomPassword(),
                    'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                    //'realName' => $this->getServerVar($this->extensionConfiguration['displayName']),
                    'admin' => 1,
                ],
                [
                    'username' => $this->remoteUser,
                    'pid' => 0,
                ]
            );
        }
        else {
            // gruppo generico : a questo punto verifico se il gruppo esiste tra i gruppi BE
            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('be_groups');
            $result = $queryBuilder
                ->select('uid','title')
                ->from('be_groups')
                ->execute();
            $usergroup = "";
            while ($row = $result->fetchAssociative()) {
                // faccio il match tra i singoli nomi dei gruppi BE e il campo entitlement, che contiene una stringa con tutti i gruppi AUNICA
                if (strpos($entitlement, $row['title'])) {
                    $usergroup = $usergroup . $row['uid'] . ",";
                }
            }
            // elimino l'ultima virgola della sequenza (e.g. 1,3,5,7,) perchè non necessaria
            $usergroup = rtrim($usergroup,",");
            if ($usergroup !== ''){
                $this->getDatabaseConnectionForBackendUsers()->update(
                    $this->authInfo['db_user']['table'],
                    [
                        'crdate' => time(),
                        'tstamp' => time(),
                        'pid' => 0,
                        'username' => $this->remoteUser,
                        'password' => $this->getRandomPassword(),
                        'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                        'options' => 3,
                        'workspace_id' => 0,
                        'workspace_perms' => 1,
                        'usergroup' => $usergroup,
                        'admin' => 0,
                        'file_permissions' => "readFolder,writeFolder,addFolder,renameFolder,moveFolder,deleteFolder,readFile,writeFile,addFile,renameFile,replaceFile,moveFile,copyFile,deleteFile",
                    ],
                    [
                        'username' => $this->remoteUser,
                        'pid' => 0,
                    ]
                );
            }
            // non sei admin, non sei associato a nessun gruppo users, pertanto da disabilitare, anche se questo non avverrà mai in quanto l'IDP impedisce l'arrivo di utenze non associate
            else{
                $this->getDatabaseConnectionForBackendUsers()->update(
                    $this->authInfo['db_user']['table'],
                    [
                        'deleted' => 1,
                    ],
                    [
                        'username' => $this->remoteUser,
                        'pid' => 0,
                    ]
                );
            }
        }


// by S.D : commento il vecchio codice
//        if (strpos($entitlement,$aunicaWebsiteUsers)) {
//            //by :S.D : effettuo un'interrogazione lato database per estrarre l'UID di AunicaWebsiteUsers
//            $queryBuilderBeGroups = $this->getDatabaseConnectionForBackendUserGroups();
//            $uidGroup = $queryBuilderBeGroups
//                ->select('uid')
//                ->from('be_groups')
//                ->where(
//                    $queryBuilderBeGroups->expr()->eq('title', $queryBuilderBeGroups->createNamedParameter($aunicaWebsiteUsers))
//                )
//                ->executeQuery()
//                ->fetchOne();
//
//            $this->getDatabaseConnectionForBackendUsers()->update(
//                $this->authInfo['db_user']['table'],
//                [
//                    'crdate' => time(),
//                    'tstamp' => time(),
//                    'pid' => 0,
//                    'username' => $this->remoteUser,
//                    'password' => $this->getRandomPassword(),
//                    'email' => $this->getServerVar($this->extensionConfiguration['mail']),
//                    'options' => 3,
//                    'workspace_id' => 0,
//                    'workspace_perms' => 1,
//                    'usergroup' => $uidGroup,
//                    'admin' => 0,
//                    'file_permissions' => "readFolder,writeFolder,addFolder,renameFolder,moveFolder,deleteFolder,readFile,writeFile,addFile,renameFile,replaceFile,moveFile,copyFile,deleteFile",
//                ],
//                [
//                    'username' => $this->remoteUser,
//                    'pid' => 0,
//                ]
//            );
//        }
//        else if (strpos($entitlement,$aunicaWebsiteAdmins)){
//            $this->getDatabaseConnectionForBackendUsers()->update(
//                $this->authInfo['db_user']['table'],
//                [
//                    'crdate' => time(),
//                    'tstamp' => time(),
//                    'username' => $this->remoteUser,
//                    'password' => $this->getRandomPassword(),
//                    'email' => $this->getServerVar($this->extensionConfiguration['mail']),
//                    //'realName' => $this->getServerVar($this->extensionConfiguration['displayName']),
//                    'admin' => 1,
//                ],
//                [
//                    'username' => $this->remoteUser,
//                    'pid' => 0,
//                ]
//            );
//        }
    }



    /**
     * Fetches all affiliations from the Shibboleth user
     * Creates a user group for each affiliation if it doesn't exist yet and returns a list of all user groups to be
     * assigned to the user
     *
     * @return string
     */
    protected function getFEUserGroups()
    {
        $frontendUserGroupUids = [];
        $eduPersonAffiliation = $this->getServerVar($this->extensionConfiguration['eduPersonAffiliation']);

        if (empty($eduPersonAffiliation)) {
            $eduPersonAffiliation = 'member';
        }
        if (!empty($eduPersonAffiliation)) {
            $affiliation = explode(';', $eduPersonAffiliation);
            array_walk($affiliation, function(&$v){$v = preg_replace('/@.*/', '', $v);});

            // insert the affiliations in fe_groups if they are not there.
            foreach ($affiliation as $title) {
                $frontendUserGroupUids[] = $this->getOrCreateFrontendUserGroupByTitleAndReturnUid($title);
            }
        }

        // Hook for any additional fe_groups
        if (is_array($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['getFEUserGroups'])) {
            foreach ($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['getFEUserGroups'] as $_classRef) {
                $_procObj = GeneralUtility::makeInstance($_classRef);
                $frontendUserGroupUids = $_procObj->getFEUserGroups($frontendUserGroupUids);
            }
        }
        return implode(',', $frontendUserGroupUids);
    }

    /**
     * @return boolean
     */
    protected function isShibbolethLogin(): bool
    {
        if (
            GeneralUtility::_GP('disableShibboleth') !== null
            || isset($_COOKIE['be_disableShibboleth'])
        ) {
            $cookieSecure = (bool)$GLOBALS['TYPO3_CONF_VARS']['SYS']['cookieSecure'] && GeneralUtility::getIndpEnv('TYPO3_SSL');
            $cookie = new Cookie(
                'be_disableShibboleth',
                '1',
                GeneralUtility::makeInstance(Context::class)->getPropertyFromAspect('date', 'timestamp') + 3600, // 1 hour
                GeneralUtility::getIndpEnv('TYPO3_SITE_PATH') . TYPO3_mainDir,
                '',
                $cookieSecure,
                true,
                false,
                Cookie::SAMESITE_STRICT
            );
            header('Set-Cookie: ' . $cookie->__toString(), false);

            return false;
        }

        $isShibbolethLogin = isset($_SERVER['AUTH_TYPE']) && (strtolower($_SERVER['AUTH_TYPE']) === 'shibboleth');

        if (!$isShibbolethLogin) {
            // In some cases, no AUTH_TYPE is set. We then fall back to find out if Shib_Session_ID is set
            $isShibbolethLogin = isset($_SERVER['Shib_Session_ID']) || isset($_SERVER['REDIRECT_Shib_Session_ID']);
        }
        return $isShibbolethLogin && !empty($this->remoteUser);
    }

    /**
     * Returns the requested variable from $_SERVER
     *
     * Falls back to the prefixed version (e.g. $_SERVER['REDIRECT_affiliation'] instead of $_SERVER['affiliation'] if needed.
     * This is necessary if there was an internal redirect after authentication.
     */
    protected function getServerVar(string $key, string $prefix = 'REDIRECT_'): ?string
    {
        if (isset($_SERVER[$key])) {
            return $_SERVER[$key];
        } else {
            if (isset($_SERVER[$prefix . $key])) {
                return $_SERVER[$prefix . $key];
            } else {
                foreach ($_SERVER as $k => $v) {
                    if ($key == str_replace($prefix, '', $k)) {
                        return $v;
                    }
                }
            }
        }
        return null;
    }


    protected function getRandomPassword(): string
    {
        $randomPassword = GeneralUtility::makeInstance(Random::class)->generateRandomBytes(32);
        $hashInstance = GeneralUtility::makeInstance(PasswordHashFactory::class)->getDefaultHashInstance('FE');
        return $hashInstance->getHashedPassword($randomPassword);
    }

    protected function isLoginTypeFrontend(): bool
    {
        return $this->authInfo['loginType'] === 'FE';
    }

    protected function isLoginTypeBackend(): bool
    {
        return $this->authInfo['loginType'] === 'BE';
    }



    protected function getDatabaseConnectionForFrontendUsers(): Connection
    {
        return $this->getDatabaseConnectionPool()->getConnectionForTable($this->authInfo['db_user']['table']);
    }

    protected function getDatabaseConnectionForBackendUsers(): Connection
    {
        return $this->getDatabaseConnectionPool()->getConnectionForTable($this->authInfo['db_user']['table']);
    }

    protected function getDatabaseConnectionForBackendUserGroups(): QueryBuilder
    {
        return $this->getDatabaseConnectionPool()->getQueryBuilderForTable("be_groups");
    }

    /**
     * Looks up a frontend user groups with the same title as an affiliation
     * If it exists, return uid, if not, create one and return uid
     */
    protected function getOrCreateFrontendUserGroupByTitleAndReturnUid(string $title): int
    {
        $frontendUserGroupTable = 'fe_groups';

        /** @var QueryBuilder $queryBuilder */
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(
            $frontendUserGroupTable
        );
        $recordData = $queryBuilder->select('*')->from($frontendUserGroupTable)->where(
                $queryBuilder->expr()->eq('title', $queryBuilder->createNamedParameter($title)),
                $queryBuilder->expr()->eq('pid', $this->extensionConfiguration['storagePid']),
            )->execute()->fetchAssociative();

        if ($recordData) {
            return $recordData['uid'];
        }

        $databaseConnection = $this->getDatabaseConnectionPool()->getConnectionForTable(
            $frontendUserGroupTable
        );
        $databaseConnection->insert(
            $frontendUserGroupTable,
            [
                'pid' => $this->extensionConfiguration['storagePid'],
                'title' => $title,
            ]
        );
        return (int)$databaseConnection->lastInsertId($frontendUserGroupTable);
    }

    protected function getDatabaseConnectionPool(): ConnectionPool
    {
        return GeneralUtility::makeInstance(ConnectionPool::class);
    }

}
