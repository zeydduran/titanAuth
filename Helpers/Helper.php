<?php
namespace App\Libs\Auth\Helpers;

use App\Libs\Auth\Helpers\ResponseHeader;
use App\Libs\Auth\Helpers\Cookie;
class Helper
{

	public static function rewriteCookieHeader($sameSiteRestriction = Cookie::SAME_SITE_RESTRICTION_LAX) {
		// get and remove the original cookie header set by php
		$originalCookieHeader = ResponseHeader::take('Set-Cookie', \session_name() . '=');
		// if a cookie header has been found
		if (isset($originalCookieHeader)) {
			// parse it into a cookie instance
			$parsedCookie = Cookie::parse($originalCookieHeader);

			// if the cookie has successfully been parsed
			if (isset($parsedCookie)) {
				// apply the supplied same-site restriction
				$parsedCookie->setSameSiteRestriction($sameSiteRestriction);
				// save the cookie
				$parsedCookie->save();
			}
		}
	}
	public static function regenerate($deleteOldSession = false, $sameSiteRestriction = Cookie::SAME_SITE_RESTRICTION_LAX) {
		// run PHP's built-in equivalent

		\session_regenerate_id($deleteOldSession);

		// intercept the cookie header (if any) and rewrite it
		self::rewriteCookieHeader($sameSiteRestriction);
	}
}
