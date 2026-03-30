/*
  Lavarel: Vulnerable to CSRF

*/


class VerifyCsrfToken extends Middleware
{
    // (CSRF)
    protected $except = [
        '/post/update/*', 
    ];
}
