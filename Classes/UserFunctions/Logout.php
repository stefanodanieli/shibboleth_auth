<?php

namespace Polimiacre\ShibbolethAuth\UserFunctions;

final class Logout {
    /**
     * Output the current time in red letters
     *
     * @param string          Empty string (no content to process)
     * @param array           TypoScript configuration
     * @return        string          HTML output, showing the current server time.
     */
    public function beLogout(string $content, array $conf): string
    {
        setcookie("be_typo_user", "", -1, '/');
        foreach ($_COOKIE as $name => $value) {
            if (\str_starts_with($name, '_shibsession_')) {
                setcookie($name, "", -1, '/');
                break;
            }
        }

        // effettuo il logout anche dal frontend, qualora il sito sia di test.
        // create a new cURL resource
        //$ch = curl_init();

        // set URL and other appropriate options
        //curl_setopt($ch, CURLOPT_URL, "https://shibidp.test.polimi.it/idp/profile/SAML2/POST/SLO");
        //curl_setopt($ch, CURLOPT_HEADER, 0);

        // grab URL and pass it to the browser
        //curl_exec($ch);

        // close cURL resource, and free up system resources
        //curl_close($ch);
        return ("<p>Be Logout executed</p>");
    }

}

